import copy
import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from protocol_helpers import AUTHORIZER, envelope as signed_envelope

from ig_kmx_guardd.cgroup import CgroupIdentity
from ig_kmx_guardd.model import API_VERSION, Binding, Envelope, State, canonical, sha256_bytes
from ig_kmx_guardd.receipt import Signer, verify_chain, verify_receipt
from ig_kmx_guardd.service import Config, GuardService
from ig_kmx_guardd.store import Store

GADGET = "sha256:" + "f" * 64
AUTH = b"a" * 32


class Process:
    pid = 9191
    def poll(self):
        return None


class Worker:
    process = Process()
    pidfd = 7


class Runtime:
    def __init__(self):
        self.terminated = []

    def verify(self):
        return {"ig_sha256": "sha256:" + "1" * 64, "oci_archive_sha256": "sha256:" + "2" * 64}
    def start(self, cgroup_id, policy_raw):
        return Worker()
    def terminate(self, worker):
        self.terminated.append(worker.process.pid)


class Inventory:
    def __init__(self):
        self.clear_calls = 0

    def correlate(self, pid, expected):
        spec = expected["policy"]["spec"]
        readback = {
            "verified": True, "state": "ACTIVE", "quarantined": False,
            "generation": expected["generation"], "failure_closed": True,
            "target_cgroup_id": expected["cgroup_id"],
            "policy_digest": sha256_bytes(expected["policy_raw"]),
            "exec_rules": len(spec.get("denyExecutables", [])),
            "write_rules": len(spec.get("denyWrites", [])), "network_rules": 0,
            "map_ids": {"policy_state": 1, "exec_rules": 2, "write_rules": 3, "network_rules": 4},
        }
        return {"worker_pid": pid, "counts": {"program": 1, "map": 5, "link": 1},
                "objects": [], "map_readback": readback, "assurance": "worker_fd_policy_map_readback"}

    def clear_quarantine(self, pid, expected):
        self.clear_calls += 1
        return {"operation": "daemon_owned_policy_state_update", "map_id": 1,
                "before_quarantined": True, "after_quarantined": False,
                "readback": {"policy_digest": expected["policy_digest"]}}

    def release(self, pid):
        return None


def policy():
    return {
        "apiVersion": "agentpolicy.gadget/v1alpha1", "kind": "AgentPolicy",
        "metadata": {"name": "secure", "digest": "sha256:" + "9" * 64},
        "spec": {"subject": {"taskUID": "task", "sessionID": "sess"}, "failureMode": "closed",
                 "denyExecutables": [{"id": 1, "path": "/bin/forbidden"}],
                 "denyWrites": [{"id": 2, "path": "/tmp/forbidden"}], "denyNetworks": []},
    }


class SecurityRegressionTests(unittest.TestCase):
    def env(self, action, binding, body, request_id="request", nonce=None, issued=None, expected_state_version=None, **kwargs):
        if expected_state_version is None:
            expected_state_version = 0
            if binding is not None and action != "activate":
                try:
                    expected_state_version = self.store.session(binding.key())["state_version"]
                except KeyError:
                    pass
        return signed_envelope(action, binding, body, request_id, nonce, issued, expected_state_version=expected_state_version, **kwargs)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.policy = policy()
        self.binding = Binding("sess", "attempt", 1, sha256_bytes(canonical(self.policy)), GADGET, "node")
        self.store = Store(self.tmp.name + "/state.db")
        self.signer = Signer(b"test-only-signing-seed")
        self.inventory = Inventory()
        self.runtime = Runtime()
        self.service = GuardService(
            Config("node", frozenset({1000}), GADGET, frozenset()), self.store, self.signer,
            AUTHORIZER, self.runtime, self.inventory, boot_id="boot",
        )

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def activate(self, policy_value=None, request="request-1", nonce="nonce-1"):
        policy_value = policy_value if policy_value is not None else self.policy
        with patch("ig_kmx_guardd.service.validate_cgroup_fd", return_value=CgroupIdentity(1, 55, 2, 55)), patch("ig_kmx_guardd.service.os.dup", return_value=77):
            return self.service.dispatch(1000, self.env("activate", self.binding, {"policy": policy_value}, request, nonce), [6])

    def test_empty_malformed_and_schema_invalid_policy_rejected_without_session(self):
        invalid = [{}, {"apiVersion": "wrong"}, {**self.policy, "unknown": True}]
        for index, item in enumerate(invalid):
            binding = Binding("sess", f"bad-{index}", 1, sha256_bytes(canonical(item)), GADGET, "node")
            with self.assertRaises(ValueError):
                with patch("ig_kmx_guardd.service.validate_cgroup_fd", return_value=CgroupIdentity(1, 55, 2, 55)):
                    self.service.dispatch(1000, self.env("activate", binding, {"policy": item}, f"r-{index}", f"n-{index}"), [6])
            with self.assertRaises(KeyError):
                self.store.session(binding.key())

    def test_policy_subject_must_bind_session(self):
        item = copy.deepcopy(self.policy)
        item["spec"]["subject"]["sessionID"] = "other"
        binding = Binding("sess", "wrong-subject", 1, sha256_bytes(canonical(item)), GADGET, "node")
        with self.assertRaisesRegex(ValueError, "session"):
            with patch("ig_kmx_guardd.service.validate_cgroup_fd", return_value=CgroupIdentity(1, 55, 2, 55)):
                self.service.dispatch(1000, self.env("activate", binding, {"policy": item}), [6])

    def test_failed_request_is_durable_and_not_replayed(self):
        bad = copy.deepcopy(self.policy)
        bad["spec"]["failureMode"] = "open"
        env = self.env("activate", self.binding, {"policy": bad})
        with self.assertRaises(ValueError):
            self.service.dispatch(1000, env, [6])
        row = self.store.db.execute("SELECT status,response,error FROM requests").fetchone()
        self.assertEqual(row[0], "FAILED")
        self.assertIsNone(row[1])
        with self.assertRaisesRegex(RuntimeError, "prior request failed closed"):
            self.service.dispatch(1000, env, [6])

    def test_recover_fails_in_progress_request_closed(self):
        request_hash = "sha256:" + "1" * 64
        self.store.request_reserve(1000, "r", "n", request_hash)
        self.store.request_begin(1000, "r", request_hash)
        self.store.recover()
        with self.assertRaisesRegex(RuntimeError, "restarted"):
            self.store.request_lookup(1000, "r", request_hash)

    def test_asymmetric_receipt_tampering_wrong_key_and_chain_fail(self):
        result = self.activate()
        receipts = result["result"]["receipts"]
        with tempfile.NamedTemporaryFile(suffix=".pem") as public:
            import subprocess
            subprocess.run(("openssl", "pkey", "-in", self.signer.private_key_path, "-pubout", "-out", public.name), check=True)
            self.assertTrue(verify_chain(receipts, public.name, self.binding.dict()))
            tampered = receipts[-1][:-1] + bytes([receipts[-1][-1] ^ 1])
            self.assertFalse(verify_receipt(tampered, public.name))
            reordered = receipts[:]
            reordered[0], reordered[1] = reordered[1], reordered[0]
            self.assertFalse(verify_chain(reordered, public.name, self.binding.dict()))
            other = Signer(b"different-test-signing-seed")
            with tempfile.NamedTemporaryFile(suffix=".pem") as wrong:
                subprocess.run(("openssl", "pkey", "-in", other.private_key_path, "-pubout", "-out", wrong.name), check=True)
                self.assertFalse(verify_receipt(receipts[-1], wrong.name))


    def test_dead_worker_never_receives_release_receipt(self):
        with patch.object(Process, "poll", return_value=9):
            with self.assertRaisesRegex(RuntimeError, "exited 9"):
                self.activate()
        self.assertNotIn(self.binding.key(), self.service.workers)
        self.assertEqual(self.runtime.terminated, [Process.pid])
        stages = [row[0] for row in self.store.db.execute("SELECT stage FROM receipts")] if self.store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='receipts'").fetchone() else []
        self.assertNotIn("ACTIVATION_VALIDATED", stages)

    def test_worker_exit_during_final_revalidation_fails_closed(self):
        with patch.object(Process, "poll", side_effect=[None, None, 9]):
            with self.assertRaisesRegex(RuntimeError, "exited 9"):
                self.activate()
        self.assertNotIn(self.binding.key(), self.service.workers)
        self.assertEqual(self.runtime.terminated, [Process.pid])


    def test_worker_exit_after_response_persistence_is_not_returned(self):
        # Six activation-boundary polls pass; the post-persistence poll fails.
        with patch.object(Process, "poll", side_effect=[None] * 6 + [17]):
            with self.assertRaisesRegex(RuntimeError, "exited 17"):
                self.activate()
        self.assertNotIn(self.binding.key(), self.service.workers)
        self.assertEqual(self.runtime.terminated, [Process.pid])
        row = self.store.db.execute("SELECT status,error FROM requests").fetchone()
        self.assertEqual(row[0], "FAILED")
        self.assertIn("exited 17", row[1])

    def test_completion_write_failure_retires_active_worker(self):
        with patch.object(self.store, "request_complete", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                self.activate()
        self.assertNotIn(self.binding.key(), self.service.workers)
        self.assertNotIn(self.binding.key(), self.service.cgroup_fds)
        self.assertEqual(self.runtime.terminated, [Process.pid])
        row = self.store.db.execute("SELECT status,error FROM requests").fetchone()
        self.assertEqual(row[0], "FAILED")
        self.assertIn("disk full", row[1])
        self.assertEqual(self.store.session(self.binding.key())["state"], State.FREEZE_DESIRED)

    def test_resume_rejects_caller_claim_before_reservation_or_effect(self):
        self.activate()
        key = self.binding.key()
        self.store.transition(key, State.FREEZE_DESIRED)
        self.store.transition(key, State.FROZEN_CONFIRMED)
        self.service.cgroup_fds[key] = 88
        count = self.store.db.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        with self.assertRaisesRegex(ValueError, "unknown=.*quarantine_cleared_readback"):
            self.service.dispatch(1000, self.env("resume", self.binding, {
                "incident_id": "incident", "remediation_generation": 1,
                "quarantine_cleared_readback": False,
            }, "resume-1", "resume-nonce"), [])
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM requests").fetchone()[0], count)
        self.assertEqual(self.inventory.clear_calls, 0)
        self.assertEqual(self.store.session(key)["state"], State.FROZEN_CONFIRMED)


if __name__ == "__main__":
    unittest.main()
