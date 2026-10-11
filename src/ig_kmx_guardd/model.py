"""Versioned guardd domain models and strict validation.

The source AgentPolicy is canonical JSON because that is the portable policy
contract. The local API is *not* JSON: ``Envelope`` is constructed from the
strict protobuf frame in :mod:`ig_kmx_guardd.proto`; its binding/body are
canonical CBOR and its authorization is COSE_Sign1.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
import hashlib
import json
import re
import time

from . import cbor
from .proto import PROTOCOL_VERSION, RequestFrame

API_VERSION = PROTOCOL_VERSION
MAX_FRAME = 1 << 20
MAX_ID = 128
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class Stage(StrEnum):
    REQUEST_ACCEPTED = "REQUEST_ACCEPTED"
    ARTIFACT_VERIFIED = "ARTIFACT_VERIFIED"
    POLICY_PROVISIONED = "POLICY_PROVISIONED"
    IG_PROCESS_STARTED = "IG_PROCESS_STARTED"
    KERNEL_OBJECTS_CORRELATED = "KERNEL_OBJECTS_CORRELATED"
    ACTIVATION_VALIDATED = "ACTIVATION_VALIDATED"
    FAIL_SAFE_GUARDIAN_ARMED = "FAIL_SAFE_GUARDIAN_ARMED"


class State(StrEnum):
    HELD = "HELD"
    ACTIVATING = "ACTIVATING"
    ACTIVE_VALIDATED = "ACTIVE_VALIDATED"
    RELEASED = "RELEASED"
    FREEZE_DESIRED = "FREEZE_DESIRED"
    FROZEN_CONFIRMED = "FROZEN_CONFIRMED"
    FROZEN_UNCERTAIN = "FROZEN_UNCERTAIN"
    RESUME_PREPARED = "RESUME_PREPARED"
    TERMINATING = "TERMINATING"
    EMPTY_CONFIRMED = "EMPTY_CONFIRMED"
    DEACTIVATED = "DEACTIVATED"
    RECONCILING = "RECONCILING"
    FAILED = "FAILED"


TRANSITIONS = {
    State.HELD: {State.ACTIVATING, State.TERMINATING, State.FAILED},
    State.ACTIVATING: {State.ACTIVE_VALIDATED, State.FREEZE_DESIRED, State.TERMINATING, State.FAILED},
    State.ACTIVE_VALIDATED: {State.RELEASED, State.FREEZE_DESIRED, State.TERMINATING, State.FAILED},
    State.RELEASED: {State.FREEZE_DESIRED, State.TERMINATING, State.FAILED},
    State.FREEZE_DESIRED: {State.FROZEN_CONFIRMED, State.FROZEN_UNCERTAIN, State.TERMINATING, State.FAILED},
    State.FROZEN_CONFIRMED: {State.RESUME_PREPARED, State.TERMINATING, State.FAILED},
    State.FROZEN_UNCERTAIN: {State.TERMINATING, State.FAILED},
    State.RESUME_PREPARED: {State.RELEASED, State.TERMINATING, State.FAILED},
    State.TERMINATING: {State.EMPTY_CONFIRMED, State.FAILED},
    State.EMPTY_CONFIRMED: {State.DEACTIVATED, State.FAILED},
    State.RECONCILING: {State.TERMINATING, State.FAILED},
    State.DEACTIVATED: set(),
    State.FAILED: {State.TERMINATING},
}


def canonical(obj: object) -> bytes:
    """Canonical JSON exclusively for policy and SQLite diagnostics."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def digest(value: str, field: str = "digest") -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


def identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or not IDENT.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


@dataclass(frozen=True)
class Binding:
    session_id: str
    attempt: str
    generation: int
    policy_digest: str
    gadget_digest: str
    node_id: str

    def __post_init__(self) -> None:
        for field in ("session_id", "attempt", "node_id"):
            identifier(getattr(self, field), field)
        if type(self.generation) is not int or not 1 <= self.generation <= 2**63 - 1:
            raise ValueError("generation out of range")
        digest(self.policy_digest, "policy_digest")
        digest(self.gadget_digest, "gadget_digest")

    def key(self) -> str:
        return f"{self.session_id}/{self.attempt}/{self.generation}"

    def dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: object) -> "Binding":
        if not isinstance(value, dict) or set(value) != {
            "session_id", "attempt", "generation", "policy_digest", "gadget_digest", "node_id"
        }:
            raise ValueError("binding fields mismatch")
        return cls(**value)


@dataclass
class Envelope:
    api_version: str
    action: str
    request_id: str
    nonce: bytes
    issued_at: int
    expires_at: int
    issuer_id: str
    key_id: str
    boot_id: str
    expected_state_version: int
    binding: Binding | None
    body: dict
    authorization: bytes
    signed_payload: bytes

    @classmethod
    def from_frame(cls, raw: bytes, *, now: int | None = None) -> "Envelope":
        frame = RequestFrame.decode(raw)
        if frame.protocol_version != API_VERSION:
            raise ValueError("unsupported protocol version")
        action = identifier(frame.method, "method")
        request_id = identifier(frame.request_id, "request_id")
        identifier(frame.issuer_id, "issuer_id")
        identifier(frame.key_id, "key_id")
        identifier(frame.boot_id, "boot_id")
        if not 16 <= len(frame.nonce) <= 64:
            raise ValueError("nonce must be 16..64 bytes")
        current = int(time.time()) if now is None else now
        if frame.issued_at > current + 30 or frame.issued_at < current - 300:
            raise ValueError("stale issued_at")
        if frame.expires_at < current or frame.expires_at > frame.issued_at + 300:
            raise ValueError("invalid/expired expires_at")
        if frame.expected_state_version < 0 or frame.expected_state_version > 2**63 - 1:
            raise ValueError("expected_state_version out of range")
        binding_value = cbor.loads(frame.binding_cbor)
        body = cbor.loads(frame.payload_cbor)
        if binding_value is not None and not isinstance(binding_value, dict):
            raise ValueError("binding CBOR must be map or null")
        if not isinstance(body, dict):
            raise ValueError("payload CBOR must be map")
        binding = None if binding_value is None else Binding.from_dict(binding_value)
        signed_payload = authorization_payload(frame)
        return cls(
            frame.protocol_version, action, request_id, frame.nonce, frame.issued_at,
            frame.expires_at, frame.issuer_id, frame.key_id, frame.boot_id,
            frame.expected_state_version, binding, body, frame.authorization_cose,
            signed_payload,
        )

    def unsigned_claims(self) -> dict:
        return {
            "protocol_version": self.api_version,
            "method": self.action,
            "request_id": self.request_id,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "issuer_id": self.issuer_id,
            "key_id": self.key_id,
            "boot_id": self.boot_id,
            "expected_state_version": self.expected_state_version,
            "binding": self.binding.dict() if self.binding else None,
            "payload": self.body,
        }


def authorization_payload(frame: RequestFrame) -> bytes:
    return cbor.dumps({
        "protocol_version": frame.protocol_version,
        "method": frame.method,
        "request_id": frame.request_id,
        "nonce": frame.nonce,
        "issued_at": frame.issued_at,
        "expires_at": frame.expires_at,
        "issuer_id": frame.issuer_id,
        "key_id": frame.key_id,
        "boot_id": frame.boot_id,
        "expected_state_version": frame.expected_state_version,
        "binding": cbor.loads(frame.binding_cbor),
        "payload": cbor.loads(frame.payload_cbor),
    })
