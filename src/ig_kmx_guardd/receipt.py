"""Canonical CBOR COSE_Sign1 lifecycle receipts.

A receipt is the COSE_Sign1 byte string itself.  Its embedded payload is a
canonical CBOR map, so any verifier with the allowlisted public key can validate
it without guardd or its SQLite database.  Chains hash the exact COSE bytes,
not an unsigned JSON projection.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
import time

from . import cbor, cose
from .model import Binding, Stage, sha256_bytes

RECEIPT_SCHEMA = "guardd.kmx.io/receipt/v1"
RECEIPT_AAD = b"guardd.kmx.io/receipt/v1"


class Signer:
    """Ed25519 COSE signer; test seeds are never accepted by the launcher."""

    def __init__(self, private_key_path: str | bytes, public_key_path: str | None = None):
        if isinstance(private_key_path, bytes):
            # Unit-test-only deterministic PKCS#8 key from a seed.
            seed = hashlib.sha256(private_key_path).digest()
            prefix = bytes.fromhex("302e020100300506032b657004220420")
            handle = tempfile.NamedTemporaryFile(prefix="guardd-test-ed25519-", delete=False)
            handle.write(prefix + seed)
            handle.close()
            os.chmod(handle.name, 0o600)
            self.private_key_path = handle.name
            self._temporary = handle.name
        else:
            self.private_key_path = cose.secure_private_path(private_key_path)
            self._temporary = None
        self.public_der = cose.public_der_from_private(self.private_key_path)
        if public_key_path is not None and cose.public_der_from_path(public_key_path) != self.public_der:
            raise ValueError("receipt public/private key mismatch")
        self.kid = cose.key_id(self.public_der)
        self.key_id = "sha256:" + hashlib.sha256(self.public_der).hexdigest()

    def __del__(self):
        temporary = getattr(self, "_temporary", None)
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:  # AUDITED: DELIBERATE — best-effort unit-test key cleanup
                pass

    def issue(
        self, binding: Binding, stage: Stage, sequence: int, prior_hash: str,
        claims: dict, boot_id: str, state_version: int,
    ) -> bytes:
        payload = cbor.dumps({
            "schema": RECEIPT_SCHEMA,
            "stage": str(stage),
            "binding": binding.dict(),
            "sequence": sequence,
            "prior_receipt_hash": prior_hash,
            "boot_id": boot_id,
            "state_version": state_version,
            "issued_at_ns": time.time_ns(),
            "claims": claims,
        })
        return cose.sign1(payload, self.private_key_path, self.kid, RECEIPT_AAD)

    def verify(self, receipt: bytes) -> bool:
        try:
            cose.verify1(receipt, self.public_der, self.kid, RECEIPT_AAD)
            return True
        except (OSError, ValueError, TypeError):
            return False


def decode_receipt(receipt: bytes, public_key_path: str | None = None, *, der: bool = False) -> dict:
    """Verify (when a key is supplied) and decode one canonical receipt."""
    if public_key_path is None:
        _protected, _kid, payload, _signature = cose.parse_sign1(receipt)
    else:
        public_der = open(public_key_path, "rb").read() if der else cose.public_der_from_path(public_key_path)
        payload = cose.verify1(receipt, public_der, cose.key_id(public_der), RECEIPT_AAD)
    value = cbor.loads(payload)
    required = {
        "schema", "stage", "binding", "sequence", "prior_receipt_hash", "boot_id",
        "state_version", "issued_at_ns", "claims",
    }
    if not isinstance(value, dict) or set(value) != required or value["schema"] != RECEIPT_SCHEMA:
        raise ValueError("receipt payload schema mismatch")
    return value


def verify_receipt(receipt: bytes, public_key_path: str, der: bool = False) -> bool:
    try:
        decode_receipt(receipt, public_key_path, der=der)
        return True
    except (OSError, ValueError, TypeError, KeyError):
        return False


def verify_chain(
    receipts: list[bytes], public_key_path: str, expected_binding: dict | None = None,
    expected_boot_id: str | None = None,
) -> bool:
    prior = ""
    previous_state_version = -1
    for sequence, receipt in enumerate(receipts, 1):
        try:
            payload = decode_receipt(receipt, public_key_path)
        except (OSError, ValueError, TypeError, KeyError):
            return False
        if payload["sequence"] != sequence or payload["prior_receipt_hash"] != prior:
            return False
        if expected_binding is not None and payload["binding"] != expected_binding:
            return False
        if expected_boot_id is not None and payload["boot_id"] != expected_boot_id:
            return False
        state_version = payload["state_version"]
        if type(state_version) is not int or state_version < previous_state_version:
            return False
        previous_state_version = state_version
        prior = sha256_bytes(receipt)
    return bool(receipts)
