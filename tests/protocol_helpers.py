"""Shared real protobuf/CBOR/COSE request fixtures for unit tests."""
from __future__ import annotations

import atexit
import hashlib
import os
import tempfile

from ig_kmx_guardd.client import RequestBuilder
from ig_kmx_guardd.service import Authorizer

_seed = hashlib.sha256(b"guardd-test-kmx-authorization-seed").digest()
_pkcs8 = bytes.fromhex("302e020100300506032b657004220420") + _seed
_handle = tempfile.NamedTemporaryFile(prefix="guardd-test-kmx-", delete=False)
_handle.write(_pkcs8)
_handle.close()
os.chmod(_handle.name, 0o600)
atexit.register(lambda: os.path.exists(_handle.name) and os.unlink(_handle.name))

BUILDER = RequestBuilder("kmx-test", _handle.name, "boot")
AUTHORIZER = Authorizer({"kmx-test": (BUILDER.key_id, BUILDER.public_der)})


def envelope(action, binding, body, request_id="request", nonce=None, issued=None,
             expected_state_version=0, boot_id="boot", expires_at=None):
    builder = BUILDER if boot_id == "boot" else RequestBuilder("kmx-test", _handle.name, boot_id)
    nonce_bytes = nonce if isinstance(nonce, bytes) else hashlib.sha256(str(nonce or request_id).encode()).digest()
    return builder.envelope(
        action, request_id, binding, body, expected_state_version=expected_state_version,
        nonce=nonce_bytes, issued_at=issued, expires_at=expires_at,
    )
