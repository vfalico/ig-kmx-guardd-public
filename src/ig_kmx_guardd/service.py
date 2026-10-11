"""Authenticated guardd action dispatcher and fail-closed lifecycle orchestration."""
from __future__ import annotations

import hashlib
import os
from os import close as close_fd
import posixpath
import threading
import time
from dataclasses import dataclass

from .cgroup import CgroupIdentity, validate_cgroup_fd, read_events, task_ids, set_freeze
from . import cbor, cose
from .model import Binding, Envelope, Stage, State, canonical, digest, sha256_bytes
from .receipt import Signer
from .policy import validate_policy

ACTIONS = {
    "capabilities", "activate", "status", "health", "evidence", "quarantine",
    "freeze", "resume", "terminate_handoff", "deactivate", "reconcile",
}
_POLICY_KEYS = {"apiVersion", "kind", "metadata", "spec"}
_METADATA_KEYS = {"name", "digest"}
_SPEC_KEYS = {"subject", "failureMode", "denyExecutables", "denyWrites", "denyNetworks"}
_SUBJECT_KEYS = {"taskUID", "sessionID"}
_PATH_RULE_KEYS = {"id", "path"}
_ACTION_BODY_KEYS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "activate": (frozenset({"policy"}), frozenset({"policy"})),
    "status": (frozenset(), frozenset()),
    "health": (frozenset(), frozenset()),
    "evidence": (
        frozenset({"event"}),
        frozenset({"event", "source_policy", "source_rule", "loss"}),
    ),
    "quarantine": (frozenset(), frozenset()),
    "freeze": (frozenset(), frozenset()),
    "resume": (
        frozenset({"incident_id", "remediation_generation"}),
        frozenset({"incident_id", "remediation_generation"}),
    ),
    "terminate_handoff": (frozenset(), frozenset()),
    "deactivate": (frozenset(), frozenset()),
    "reconcile": (frozenset(), frozenset()),
}


@dataclass(frozen=True)
class Config:
    node_id: str
    allowed_uids: frozenset[int]
    gadget_digest: str
    policy_digest_allowlist: frozenset[str]
    max_policy_bytes: int = 262144
    freeze_timeout_s: float = 5.0
    stable_empty_s: float = 0.2


class Authorizer:
    """Verify KMX COSE_Sign1 authorizations against an issuer/key allowlist."""

    AAD = b"guardd.kmx.io/authorization/v1"

    def __init__(self, keys: dict[str, tuple[str, bytes]]):
        if not keys:
            raise ValueError("authorization keyring is empty")
        self.keys = dict(keys)

    @classmethod
    def from_public_key(cls, issuer_id: str, public_key_path: str) -> "Authorizer":
        public_der = cose.public_der_from_path(public_key_path)
        key_id = "sha256:" + hashlib.sha256(public_der).hexdigest()
        return cls({issuer_id: (key_id, public_der)})

    def verify(self, env: Envelope) -> None:
        configured = self.keys.get(env.issuer_id)
        if configured is None:
            raise PermissionError("authorization issuer not allowlisted")
        key_id, public_der = configured
        if env.key_id != key_id:
            raise PermissionError("authorization key id not allowlisted")
        try:
            payload = cose.verify1(env.authorization, public_der, cose.key_id(public_der), self.AAD)
        except ValueError as exc:
            raise PermissionError("invalid KMX COSE authorization") from exc
        if payload != env.signed_payload:
            raise PermissionError("authorization payload does not bind request")


def _exact_keys(value: object, wanted: set[str], field: str) -> dict:
    if not isinstance(value, dict) or set(value) != wanted:
        raise ValueError(f"{field} fields mismatch")
    return value


def _label(value: object, field: str, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value) or len(value.encode()) > maximum or "\0" in value:
        raise ValueError(f"invalid {field}")
    return value


def validate_agent_policy(policy: object, maximum_bytes: int) -> bytes:
    """Mirror the immutable gadget parser before any session or kernel side effect."""
    root = _exact_keys(policy, _POLICY_KEYS, "policy")
    raw = canonical(root)
    if not raw or len(raw) > maximum_bytes:
        raise ValueError("policy too large")
    if root["apiVersion"] != "agentpolicy.gadget/v1alpha1":
        raise ValueError("unsupported AgentPolicy apiVersion")
    if root["kind"] != "AgentPolicy":
        raise ValueError("kind must be AgentPolicy")
    metadata = _exact_keys(root["metadata"], _METADATA_KEYS, "metadata")
    _label(metadata["name"], "metadata.name", 63)
    digest(metadata["digest"], "metadata.digest")
    spec = root["spec"]
    if not isinstance(spec, dict) or not {"subject", "failureMode"} <= set(spec) or not set(spec) <= _SPEC_KEYS:
        raise ValueError("spec fields mismatch")
    spec = dict(spec)
    for optional in ("denyExecutables", "denyWrites", "denyNetworks"):
        spec.setdefault(optional, [])
    subject = _exact_keys(spec["subject"], _SUBJECT_KEYS, "subject")
    _label(subject["taskUID"], "subject.taskUID", 127, allow_empty=True)
    _label(subject["sessionID"], "subject.sessionID", 127, allow_empty=True)
    if spec["failureMode"] not in {"closed", "open"}:
        raise ValueError("failureMode must be open or closed")
    if spec["failureMode"] != "closed":
        raise ValueError("guardd release eligibility requires failureMode closed")
    identifiers: set[int] = set()
    for field, limit in (("denyExecutables", 1024), ("denyWrites", 1024)):
        rules = spec[field]
        if not isinstance(rules, list) or len(rules) > limit:
            raise ValueError(f"invalid {field} rule count")
        paths: set[str] = set()
        for rule in rules:
            item = _exact_keys(rule, _PATH_RULE_KEYS, f"{field} rule")
            rule_id = item["id"]
            if type(rule_id) is not int or not 0 < rule_id < 2**32 or rule_id in identifiers:
                raise ValueError("rule id must be nonzero and globally unique")
            identifiers.add(rule_id)
            path = _label(item["path"], "rule path", 255)
            if not path.startswith("/") or posixpath.normpath(path) != path or path in paths:
                raise ValueError("rule path must be unique, absolute and canonical")
            paths.add(path)
    networks = spec["denyNetworks"]
    if not isinstance(networks, list):
        raise ValueError("denyNetworks must be an array")
    if networks:
        raise ValueError("network enforcement is unsupported in the first slice")
    return raw


class GuardService:
    def __init__(self, config: Config, store, signer: Signer, authorizer: Authorizer, runtime, inventory, boot_id: str | None = None):
        self.config = config
        self.store = store
        self.signer = signer
        self.authorizer = authorizer
        self.runtime = runtime
        self.inventory = inventory
        self.boot_id = boot_id or open("/proc/sys/kernel/random/boot_id", encoding="ascii").read().strip()
        self.workers: dict[str, object] = {}
        self.cgroup_fds: dict[str, int] = {}
        self.policies: dict[str, tuple[dict, bytes]] = {}
        self.dispatch_lock = threading.RLock()

    def capabilities(self) -> dict:
        return {
            "api_version": "guardd.kmx.io/v1", "node_id": self.config.node_id, "cgroup_version": 2,
            "enforcement": {"kind": "file", "hooks": ["bprm_check_security", "file_open"], "network": False,
                            "complete_filesystem_containment": False},
            "receipt_assurance_required": "worker_fd_policy_map_readback", "held_start_required": True,
            "per_session_instance": True, "gadget_digest_allowlist": [self.config.gadget_digest],
            "gadget_activation_generation": 1,
            "wire": {"transport": "SOCK_SEQPACKET", "frame": "protobuf", "payload": "deterministic-cbor", "authorization": "COSE_Sign1/EdDSA"},
            "limits": {"policy_bytes": self.config.max_policy_bytes, "frame_bytes": 1048576},
        }

    @staticmethod
    def _validate_action_contract(env: Envelope, fds: list[int]) -> None:
        """Reject schema/descriptor ambiguity before replay reservation or effects."""
        if env.action == "capabilities":
            if env.binding is not None or env.body or fds:
                raise ValueError("capabilities requires null binding, empty body, and zero fds")
            return
        required, allowed = _ACTION_BODY_KEYS[env.action]
        actual = frozenset(env.body)
        missing = sorted(required - actual)
        unknown = sorted(actual - allowed)
        if missing or unknown:
            raise ValueError(f"{env.action} body fields mismatch: missing={missing}, unknown={unknown}")
        expected_fds = 1 if env.action in {"activate", "reconcile"} else 0
        if len(fds) != expected_fds:
            raise ValueError(f"{env.action} requires exactly {expected_fds} fds")
        if env.action == "evidence":
            if not isinstance(env.body["event"], dict):
                raise ValueError("event object required")
            loss = env.body.get("loss", 0)
            if type(loss) is not int or not 0 <= loss <= 2**63 - 1:
                raise ValueError("invalid evidence loss")
            for field in ("source_policy", "source_rule"):
                if field in env.body:
                    _label(env.body[field], field, 256)

    def _binding(self, env: Envelope) -> Binding:
        if env.binding is None:
            raise ValueError("binding required")
        binding = env.binding
        if binding.node_id != self.config.node_id:
            raise ValueError("wrong node")
        if binding.gadget_digest != self.config.gadget_digest:
            raise ValueError("wrong gadget digest")
        if self.config.policy_digest_allowlist and binding.policy_digest not in self.config.policy_digest_allowlist:
            raise ValueError("policy digest not allowed")
        return binding

    def _receipt(self, binding: Binding, stage: Stage, claims: dict) -> dict:
        sequence, prior = self.store.next_receipt(binding.key())
        state_version = int(self.store.session(binding.key())["state_version"])
        receipt = self.signer.issue(binding, stage, sequence, prior, claims, self.boot_id, state_version)
        self.store.chain_receipt(binding.key(), receipt)
        return receipt

    def dispatch(self, uid: int, env: Envelope, fds: list[int]) -> dict:
        if uid not in self.config.allowed_uids:
            raise PermissionError("peer uid unauthorized")
        if env.action not in ACTIONS:
            raise ValueError("unknown action")
        self._validate_action_contract(env, fds)
        if env.boot_id != self.boot_id:
            raise PermissionError("request boot id does not match running daemon")
        self.authorizer.verify(env)
        if env.action == "capabilities":
            if env.expected_state_version != 0:
                raise ValueError("capabilities expected_state_version must be zero")
            return {"ok": True, "capabilities": self.capabilities()}
        binding = self._binding(env)
        request_hash = sha256_bytes(cbor.dumps({"authorization_payload": env.signed_payload, "fd_count": len(fds)}))
        with self.dispatch_lock:
            # Exact completed replay is safe even after the original action advanced
            # state_version; altered request bytes retain the same request-id conflict.
            cached = self.store.request_lookup(uid, env.request_id, request_hash)
            if cached is not None:
                return cached
            if env.action == "activate":
                try:
                    self.store.require_state_version(binding.key(), env.expected_state_version)
                except KeyError:
                    if env.expected_state_version != 0:
                        raise ValueError("new activation expected_state_version must be zero")
            else:
                self.store.require_state_version(binding.key(), env.expected_state_version)
            if self.store.nonce_used(uid, env.nonce.hex()):
                raise ValueError("replayed nonce")
            self.store.request_reserve(uid, env.request_id, env.nonce.hex(), request_hash)
            try:
                self.store.request_begin(uid, env.request_id, request_hash)
                result = getattr(self, "_" + env.action)(binding, env.body, fds)
                # Every session-bound response returns the post-operation durable
                # concurrency token.  Clients never infer it from lifecycle names.
                result["state_version"] = int(self.store.session(binding.key())["state_version"])
                response = {"ok": True, "request_id": env.request_id, "result": result}
                try:
                    self.store.request_complete(uid, env.request_id, request_hash, response)
                    if env.action == "activate":
                        worker = self.workers.get(binding.key())
                        if worker is None:
                            raise RuntimeError("activation worker ownership disappeared after persistence")
                        self._require_worker_alive(worker, "after durable response persistence")
                except Exception as completion_error:
                    self._completion_failed_closed(binding, env.action, completion_error)
                    raise
                return response
            except Exception as exc:
                self.store.request_fail(uid, env.request_id, request_hash, str(exc))
                raise

    def _completion_failed_closed(self, binding: Binding, action: str, error: Exception) -> None:
        if action != "activate":
            return
        key = binding.key()
        worker = self.workers.pop(key, None)
        self.policies.pop(key, None)
        if worker is not None:
            try:
                self.runtime.terminate(worker)
            except Exception:  # AUDITED: DELIBERATE — preserve durable completion failure
                pass
            if hasattr(self.inventory, "release"):
                self.inventory.release(worker.process.pid)
        fd = self.cgroup_fds.pop(key, None)
        if fd is not None:
            try:
                close_fd(fd)
            except OSError:  # AUDITED: DELIBERATE — duplicated cgroup FD may already be closed
                pass
        try:
            self.store.transition(key, State.FREEZE_DESIRED, error=f"durable completion failed: {error}")
        except Exception:  # AUDITED: DELIBERATE — reservation failure remains primary and fail-closed
            pass

    @staticmethod
    def _require_worker_alive(worker, label: str) -> None:
        status = worker.process.poll()
        if status is not None:
            raise RuntimeError(f"IG worker exited {status} {label}")

    def _activate(self, binding: Binding, body: dict, fds: list[int]) -> dict:
        policy = body["policy"]
        if binding.generation != 1:
            raise ValueError("immutable gadget supports activation generation 1 only")
        policy_raw = validate_policy(policy, binding_session_id=binding.session_id, expected_digest=binding.policy_digest, max_bytes=self.config.max_policy_bytes)
        identity = validate_cgroup_fd(fds[0])
        self.store.create(binding, identity.dict())
        self.store.transition(binding.key(), State.ACTIVATING)
        receipts = [self._receipt(binding, Stage.REQUEST_ACCEPTED, {"cgroup": identity.dict(), "held": True})]
        worker = None
        try:
            artifacts = self.runtime.verify()
            receipts.append(self._receipt(binding, Stage.ARTIFACT_VERIFIED, artifacts))
            worker = self.runtime.start(identity.cgroup_id, policy_raw)
            self.workers[binding.key()] = worker
            self.policies[binding.key()] = (policy, policy_raw)
            self.store.set_worker(binding.key(), worker.process.pid)
            receipts.append(self._receipt(binding, Stage.IG_PROCESS_STARTED, {"pid": worker.process.pid, "pidfd": worker.pidfd is not None}))
            expected = {
                "cgroup_id": identity.cgroup_id, "generation": binding.generation,
                "policy_digest": binding.policy_digest, "policy": policy, "policy_raw": policy_raw,
                "minimum_counts": {"program": 1, "map": 4, "link": 1},
            }
            self._require_worker_alive(worker, "before kernel correlation")
            proof = self.inventory.correlate(worker.process.pid, expected)
            self._require_worker_alive(worker, "after kernel correlation")
            receipts.append(self._receipt(binding, Stage.KERNEL_OBJECTS_CORRELATED, proof))
            readback = proof["map_readback"]
            receipts.append(self._receipt(binding, Stage.POLICY_PROVISIONED, {
                "policy_digest": readback["policy_digest"], "generation": readback["generation"],
                "state": readback["state"], "failure_closed": readback["failure_closed"],
                "rule_counts": {"exec": readback["exec_rules"], "write": readback["write_rules"], "network": readback["network_rules"]},
            }))
            if readback["policy_digest"] != binding.policy_digest:
                raise ValueError("independent policy readback digest mismatch")
            if validate_cgroup_fd(fds[0]) != identity:
                raise ValueError("cgroup identity changed during activation")
            self._require_worker_alive(worker, "before final readback")
            final_proof = self.inventory.correlate(worker.process.pid, expected)
            self._require_worker_alive(worker, "before activation receipt")
            final_readback = final_proof["map_readback"]
            if final_readback != readback:
                raise ValueError("kernel proof changed before activation receipt")
            if validate_cgroup_fd(fds[0]) != identity:
                raise ValueError("cgroup identity changed before activation receipt")
            final = self._receipt(binding, Stage.ACTIVATION_VALIDATED, {
                "assurance": "worker_fd_policy_map_readback", "coverage": ["bprm_check_security", "file_open"],
                "held": True, "cgroup": identity.dict(), "kernel_proof": final_proof,
                "limitations": ["file hooks only", "point-in-time evidence", "no network containment"],
            })
            receipts.append(final)
            self._require_worker_alive(worker, "after activation receipt")
            self.store.transition(binding.key(), State.ACTIVE_VALIDATED)
            self.cgroup_fds[binding.key()] = os.dup(fds[0])
            self._require_worker_alive(worker, "before release eligibility return")
            return {"state": State.ACTIVE_VALIDATED, "release_eligible_receipt": final, "receipts": receipts}
        except Exception as exc:
            diagnostic = ""
            if worker is not None:
                try:
                    diagnostic = self.runtime.terminate(worker)
                except Exception:  # AUDITED: DELIBERATE — preserve primary activation failure
                    pass
                self.workers.pop(binding.key(), None)
                self.policies.pop(binding.key(), None)
                if hasattr(self.inventory, "release"):
                    self.inventory.release(worker.process.pid)
            enriched = exc
            if isinstance(diagnostic, str) and diagnostic:
                enriched = ValueError(f"{exc}; IG stderr: {diagnostic}")
            try:
                self.store.transition(binding.key(), State.FREEZE_DESIRED, error=str(enriched))
            except Exception:  # AUDITED: DELIBERATE — state may already be terminal
                pass
            if enriched is not exc:
                raise enriched from exc
            raise

    def _drain_worker_events(self, binding: Binding) -> dict:
        """Persist bounded IG events with exact source and userspace-loss attribution."""
        worker = self.workers.get(binding.key())
        stream = getattr(worker, "events", None) if worker is not None else None
        if stream is None:
            return {"total": 0, "queued": 0, "dropped": 0, "malformed": 0,
                    "new_dropped": 0, "new_malformed": 0, "persisted": 0}
        events, status = stream.drain()
        # Queue loss may occur with zero retained events, so it cannot rely on
        # embedding a marker in the first event. Persist it independently.
        self.store.record_evidence_loss(binding.key(), status["new_dropped"] + status["new_malformed"])
        policy_pair = self.policies.get(binding.key())
        policy_name = None
        if policy_pair:
            policy_name = policy_pair[0].get("metadata", {}).get("name")
        for index, raw in enumerate(events):
            rule_id = raw.get("rule_id")
            normalized = {
                "schema": "guardd.kmx.io/evidence/v1alpha1", "session_id": binding.session_id,
                "attempt": binding.attempt, "generation": binding.generation,
                "policy_digest": binding.policy_digest, "gadget_digest": binding.gadget_digest,
                "cgroup": self.store.session(binding.key())["cgroup_identity"],
                "source_policy": policy_name,
                "source_rule": str(rule_id) if isinstance(rule_id, int) else None,
                "observed_at_ns": time.time_ns(), "raw": raw,
                "loss": status["new_dropped"] if index == 0 else 0,
                "malformed": status["new_malformed"] if index == 0 else 0,
            }
            self.store.add_evidence(binding.key(), normalized)
        status["persisted"] = len(events)
        return status

    def _status(self, binding: Binding, body: dict, fds: list[int]) -> dict:
        stream = self._drain_worker_events(binding)
        session = self.store.session(binding.key())
        session["event_stream"] = stream
        session["evidence"] = self.store.evidence_status(binding.key())
        return session

    def _health(self, binding: Binding, body: dict, fds: list[int]) -> dict:
        stream = self._drain_worker_events(binding)
        session = self.store.session(binding.key())
        worker = self.workers.get(binding.key())
        alive = bool(worker and worker.process.poll() is None)
        return {"state": session["state"], "worker_alive": alive,
                "release_safe": session["state"] == State.ACTIVE_VALIDATED and alive,
                "event_stream": stream, "evidence": self.store.evidence_status(binding.key())}

    def _evidence(self, binding: Binding, body: dict, fds: list[int]) -> dict:
        raw = body["event"]
        normalized = {
            "schema": "guardd.kmx.io/evidence/v1alpha1", "session_id": binding.session_id,
            "attempt": binding.attempt, "generation": binding.generation,
            "policy_digest": binding.policy_digest, "gadget_digest": binding.gadget_digest,
            "cgroup": self.store.session(binding.key())["cgroup_identity"],
            "source_policy": body.get("source_policy"), "source_rule": body.get("source_rule"),
            "observed_at_ns": time.time_ns(), "raw": raw, "loss": body.get("loss", 0),
        }
        sequence = self.store.add_evidence(binding.key(), normalized)
        normalized["sequence"] = sequence
        return normalized

    def _quarantine(self, binding: Binding, body: dict, fds: list[int]) -> dict:
        return self._freeze(binding, body, fds)

    def _freeze(self, binding: Binding, body: dict, fds: list[int]) -> dict:
        fd = self.cgroup_fds.get(binding.key())
        if fd is None:
            raise ValueError("no registered cgroup fd")
        self.store.transition(binding.key(), State.FREEZE_DESIRED)
        set_freeze(fd, True)
        deadline = time.monotonic() + self.config.freeze_timeout_s
        while time.monotonic() < deadline:
            if read_events(fd).get("frozen") == 1:
                self.store.transition(binding.key(), State.FROZEN_CONFIRMED)
                return {"state": State.FROZEN_CONFIRMED, "tasks": task_ids(fd)}
            time.sleep(0.02)
        self.store.transition(binding.key(), State.FROZEN_UNCERTAIN, error="freeze confirmation timeout")
        raise TimeoutError("freeze not confirmed")

    def _resume(self, binding: Binding, body: dict, fds: list[int]) -> dict:
        session = self.store.session(binding.key())
        state = State(session["state"])
        if state not in {State.FROZEN_CONFIRMED, State.RESUME_PREPARED}:
            raise ValueError("resume requires confirmed frozen or prepared state")
        incident = body["incident_id"]
        if not isinstance(incident, str) or not incident or len(incident.encode()) > 128 or body["remediation_generation"] != binding.generation:
            raise ValueError("invalid remediation binding")
        fd = self.cgroup_fds.get(binding.key())
        worker = self.workers.get(binding.key())
        policy_pair = self.policies.get(binding.key())
        if fd is None or worker is None or policy_pair is None or worker.process.poll() is not None:
            raise ValueError("attachment not healthy")
        proof = None
        if state == State.FROZEN_CONFIRMED:
            if read_events(fd).get("frozen") != 1:
                self.store.transition(binding.key(), State.FROZEN_UNCERTAIN, error="expected frozen cgroup before quarantine clear")
                raise ValueError("cgroup not confirmed frozen before quarantine clear")
            policy, policy_raw = policy_pair
            proof = self.inventory.clear_quarantine(worker.process.pid, {
                "cgroup_id": session["cgroup_identity"]["cgroup_id"], "generation": binding.generation,
                "policy_digest": binding.policy_digest, "policy": policy, "policy_raw": policy_raw,
                "minimum_counts": {"program": 1, "map": 4, "link": 1},
            })
            if proof["after_quarantined"] is not False or proof["readback"]["policy_digest"] != binding.policy_digest:
                raise ValueError("daemon quarantine clear readback failed")
            self.store.transition(binding.key(), State.RESUME_PREPARED)
        set_freeze(fd, False)
        deadline = time.monotonic() + self.config.freeze_timeout_s
        while time.monotonic() < deadline:
            if read_events(fd).get("frozen") == 0:
                self.store.transition(binding.key(), State.RELEASED)
                result = {"state": State.RELEASED, "incident_id": incident}
                if proof is not None:
                    result["daemon_clear_proof"] = proof
                return result
            time.sleep(0.02)
        self.store.transition(binding.key(), State.FROZEN_UNCERTAIN, error="thaw confirmation timeout")
        raise TimeoutError("thaw not confirmed")

    def _terminate_handoff(self, binding: Binding, body: dict, fds: list[int]) -> dict:
        self.store.transition(binding.key(), State.TERMINATING)
        return {"state": State.TERMINATING, "enforcement_attached": True}

    def _deactivate(self, binding: Binding, body: dict, fds: list[int]) -> dict:
        key = binding.key()
        state = State(self.store.session(key)["state"])
        if state not in {State.TERMINATING, State.EMPTY_CONFIRMED}:
            raise ValueError("deactivate requires termination handoff or empty-confirmed retry")
        fd = self.cgroup_fds.get(key)
        if state == State.TERMINATING:
            if fd is None:
                raise ValueError("no registered cgroup fd")
            start = time.monotonic()
            while True:
                if read_events(fd).get("populated") != 0 or task_ids(fd):
                    raise ValueError("cgroup not empty")
                if time.monotonic() - start >= self.config.stable_empty_s:
                    break
                time.sleep(0.02)
            self.store.transition(key, State.EMPTY_CONFIRMED)
        worker = self.workers.get(key)
        if worker is not None:
            self._drain_worker_events(binding)
            self.runtime.terminate(worker)
            self._drain_worker_events(binding)
            if hasattr(self.inventory, "release"):
                self.inventory.release(worker.process.pid)
        # Descriptor cleanup precedes the terminal journal transition. If the
        # transition fails, EMPTY_CONFIRMED plus retained worker ownership makes
        # a same-process retry safe; a process crash closes every descriptor and
        # Store.recover() forces RECONCILING rather than claiming DEACTIVATED.
        fd = self.cgroup_fds.pop(key, None)
        if fd is not None:
            close_fd(fd)
        self.store.transition(key, State.DEACTIVATED)
        self.workers.pop(key, None)
        self.policies.pop(key, None)
        return {"state": State.DEACTIVATED, "detached": True}

    def _reconcile(self, binding: Binding, body: dict, fds: list[int]) -> dict:
        """Reacquire the exact frozen cgroup after daemon restart.

        Recovery never trusts a pathname or stale inode from the journal alone.
        KMX must pass a fresh cgroup-v2 FD; only an identity match plus kernel
        frozen confirmation permits orderly empty-cgroup cleanup.
        """
        key = binding.key()
        session = self.store.session(key)
        if session["state"] != State.RECONCILING:
            return {"state": session["state"], "changed": False}
        identity = validate_cgroup_fd(fds[0])
        expected = CgroupIdentity(**{name: int(session["cgroup_identity"][name])
                                     for name in ("dev", "ino", "mount_id", "cgroup_id")})
        if identity != expected:
            raise ValueError("reconcile cgroup identity mismatch")
        owned = os.dup(fds[0])
        try:
            events = read_events(owned)
            if events.get("frozen") != 1:
                raise ValueError("reconcile requires confirmed frozen cgroup")
            prior = self.cgroup_fds.pop(key, None)
            self.cgroup_fds[key] = owned
            owned = -1
            if prior is not None:
                close_fd(prior)
            self.store.transition(key, State.TERMINATING,
                                  error="daemon restarted; frozen cgroup FD reacquired for cleanup")
            return {"state": State.TERMINATING, "changed": True,
                    "held_or_frozen_required": True, "frozen": True,
                    "cgroup_identity": identity.dict()}
        finally:
            if owned >= 0:
                close_fd(owned)

