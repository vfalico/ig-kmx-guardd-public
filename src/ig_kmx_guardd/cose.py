"""Canonical COSE_Sign1 (RFC 9052) with Ed25519/EdDSA (RFC 9053).

Only the production profile is accepted: protected {1:-8,4:kid}, empty
unprotected headers, embedded byte-string payload, and a 64-byte Ed25519
signature.  The signed structure is deterministic CBOR and domain separation is
provided by COSE's ``Signature1`` context plus caller-supplied external AAD.
"""
from __future__ import annotations

import os
import stat
import subprocess
import tempfile
from pathlib import Path

from . import cbor

ALG_EDDSA = -8
HEADER_ALG = 1
HEADER_KID = 4


def _openssl(*args: str, input_data: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ("openssl", *args), input=input_data,
        stdin=None if input_data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=5.0,
    )
    if completed.returncode:
        raise ValueError(f"openssl failed: {completed.stderr.decode(errors='replace')[:300]}")
    return completed.stdout


def secure_private_path(path: str) -> str:
    resolved = str(Path(path).resolve(strict=True))
    info = os.stat(resolved, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError("COSE private key must be root-owned regular file mode 0600")
    return resolved


def public_der_from_private(path: str) -> bytes:
    return _openssl("pkey", "-in", path, "-pubout", "-outform", "DER")


def public_der_from_path(path: str) -> bytes:
    return _openssl("pkey", "-pubin", "-in", str(Path(path).resolve(strict=True)), "-outform", "DER")


def key_id(public_der: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(public_der).digest()[:16]


def sign1(payload: bytes, private_key_path: str, kid: bytes, external_aad: bytes = b"") -> bytes:
    protected = cbor.dumps({HEADER_ALG: ALG_EDDSA, HEADER_KID: kid})
    to_sign = cbor.dumps(["Signature1", protected, external_aad, payload])
    # OpenSSL 3 Ed25519 is one-shot and requires a seekable input to know size.
    with tempfile.NamedTemporaryFile(prefix="guardd-cose-input-") as message:
        message.write(to_sign)
        message.flush()
        signature = _openssl("pkeyutl", "-sign", "-rawin", "-inkey", private_key_path, "-in", message.name)
    if len(signature) != 64:
        raise ValueError("unexpected Ed25519 signature length")
    return cbor.dumps([protected, {}, payload, signature])


def parse_sign1(encoded: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    value = cbor.loads(encoded)
    if not isinstance(value, list) or len(value) != 4:
        raise ValueError("COSE_Sign1 must be a four-item array")
    protected, unprotected, payload, signature = value
    if not isinstance(protected, bytes) or unprotected != {} or not isinstance(payload, bytes):
        raise ValueError("invalid COSE_Sign1 structure")
    headers = cbor.loads(protected)
    if not isinstance(headers, dict) or set(headers) != {HEADER_ALG, HEADER_KID}:
        raise ValueError("unsupported COSE protected headers")
    if headers[HEADER_ALG] != ALG_EDDSA or not isinstance(headers[HEADER_KID], bytes):
        raise ValueError("unsupported COSE algorithm or key identifier")
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError("invalid COSE signature")
    return protected, headers[HEADER_KID], payload, signature


def verify1(encoded: bytes, public_der: bytes, expected_kid: bytes, external_aad: bytes = b"") -> bytes:
    protected, kid, payload, signature = parse_sign1(encoded)
    if kid != expected_kid:
        raise ValueError("COSE key identifier mismatch")
    to_verify = cbor.dumps(["Signature1", protected, external_aad, payload])
    with tempfile.TemporaryDirectory(prefix="guardd-cose-verify-") as directory:
        public_path = Path(directory, "public.der")
        signature_path = Path(directory, "signature.bin")
        public_path.write_bytes(public_der)
        signature_path.write_bytes(signature)
        message_path = Path(directory, "message.bin")
        message_path.write_bytes(to_verify)
        completed = subprocess.run(
            ("openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
             "-inkey", str(public_path), "-sigfile", str(signature_path), "-in", str(message_path)),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=5.0,
        )
    if completed.returncode:
        raise ValueError("COSE signature verification failed")
    return payload
