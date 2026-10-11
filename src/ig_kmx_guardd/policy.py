"""Strict validation of the effective AgentPolicy contract.

This module intentionally mirrors the standalone gadget Go parser. Validation is
performed before any session row, receipt, worker, or kernel side effect exists.
"""
from __future__ import annotations

import posixpath
import re
from typing import Any

from .model import DIGEST, canonical

API_VERSION = "agentpolicy.gadget/v1alpha1"
KIND = "AgentPolicy"
MAX_DOCUMENT = 256 * 1024
MAX_EXEC = 64
MAX_WRITES = 128
MAX_PATH_BYTES = 255
MAX_SUBJECT_BYTES = 127
NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62})$")


def _exact_object(value: Any, required: set[str], optional: set[str], label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise ValueError(f"{label} missing fields: {sorted(missing)}")
    if unknown:
        raise ValueError(f"{label} unknown fields: {sorted(unknown)}")
    return value


def _bounded_text(value: Any, label: str, maximum: int, *, nonempty: bool = True) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    size = len(value.encode("utf-8"))
    if (nonempty and size == 0) or size > maximum or "\x00" in value:
        raise ValueError(f"{label} length must be {'1' if nonempty else '0'}..{maximum} bytes")
    return value


def _path_rules(value: Any, label: str, maximum: int, ids: set[int]) -> list[dict]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    if len(value) > maximum:
        raise ValueError(f"{label} exceeds bounded map capacity")
    paths: set[str] = set()
    result: list[dict] = []
    for index, raw in enumerate(value):
        rule = _exact_object(raw, {"id", "path"}, set(), f"{label}[{index}]")
        rule_id = rule["id"]
        if type(rule_id) is not int or not 1 <= rule_id <= 0xFFFFFFFF or rule_id in ids:
            raise ValueError("rule id must be a nonzero globally unique uint32")
        path = _bounded_text(rule["path"], f"{label}[{index}].path", MAX_PATH_BYTES)
        if not path.startswith("/") or posixpath.normpath(path) != path or path.startswith("//"):
            raise ValueError("policy paths must be absolute canonical paths")
        if path in paths:
            raise ValueError(f"duplicate {label} path")
        ids.add(rule_id)
        paths.add(path)
        result.append({"id": rule_id, "path": path})
    return result


def validate_policy(policy: Any, *, binding_session_id: str, expected_digest: str, max_bytes: int = MAX_DOCUMENT) -> bytes:
    """Validate and return canonical policy bytes or raise before side effects.

    The first production slice accepts only file rules, requires fail-closed mode,
    rejects unknown fields, and binds the policy subject session to the request.
    ``metadata.digest`` is retained as source-policy identity; the KMX binding
    digest remains the digest of these canonical bytes.
    """
    root = _exact_object(policy, {"apiVersion", "kind", "metadata", "spec"}, set(), "policy")
    if root["apiVersion"] != API_VERSION:
        raise ValueError("unsupported policy apiVersion")
    if root["kind"] != KIND:
        raise ValueError("policy kind must be AgentPolicy")

    metadata = _exact_object(root["metadata"], {"name", "digest"}, set(), "metadata")
    name = _bounded_text(metadata["name"], "metadata.name", 63)
    if not NAME.fullmatch(name):
        raise ValueError("metadata.name contains unsupported characters")
    if not isinstance(metadata["digest"], str) or not DIGEST.fullmatch(metadata["digest"]):
        raise ValueError("metadata.digest must be lowercase sha256")

    spec = _exact_object(
        root["spec"],
        {"subject", "failureMode"},
        {"denyExecutables", "denyWrites", "denyNetworks"},
        "spec",
    )
    subject = _exact_object(spec["subject"], {"taskUID", "sessionID"}, set(), "spec.subject")
    _bounded_text(subject["taskUID"], "spec.subject.taskUID", MAX_SUBJECT_BYTES)
    session_id = _bounded_text(subject["sessionID"], "spec.subject.sessionID", MAX_SUBJECT_BYTES)
    if session_id != binding_session_id:
        raise ValueError("policy subject session does not match binding")
    if spec["failureMode"] != "closed":
        raise ValueError("first production slice requires failureMode closed")

    networks = spec.get("denyNetworks", [])
    if not isinstance(networks, list):
        raise ValueError("spec.denyNetworks must be an array")
    if networks:
        raise ValueError("network enforcement is unsupported in the first slice")

    ids: set[int] = set()
    executable_rules = _path_rules(spec.get("denyExecutables", []), "denyExecutables", MAX_EXEC, ids)
    write_rules = _path_rules(spec.get("denyWrites", []), "denyWrites", MAX_WRITES, ids)
    if not executable_rules and not write_rules:
        raise ValueError("policy must contain at least one supported file rule")

    encoded = canonical(root)
    if len(encoded) > min(max_bytes, MAX_DOCUMENT):
        raise ValueError("policy too large")
    from .model import sha256_bytes
    if sha256_bytes(encoded) != expected_digest:
        raise ValueError("policy digest mismatch")
    return encoded
