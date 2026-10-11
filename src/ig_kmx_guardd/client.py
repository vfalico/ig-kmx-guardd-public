"""Reference guardd v1 client framing and COSE request builder.

Orka's Go implementation mirrors this fixed schema.  This Python client is used
by installation smoke tests, fault injection, and independent protocol vectors;
it is not a JSON compatibility shim.
"""
from __future__ import annotations

import hashlib
import os
import socket
import time

from . import cbor, cose
from .model import API_VERSION, Binding, authorization_payload
from .proto import RequestFrame, ResponseFrame, pack_packet, unpack_packet
from .service import Authorizer


class RequestBuilder:
    def __init__(self, issuer_id: str, private_key_path: str, boot_id: str):
        self.issuer_id = issuer_id
        self.private_key_path = private_key_path
        self.boot_id = boot_id
        self.public_der = cose.public_der_from_private(private_key_path)
        self.cose_kid = cose.key_id(self.public_der)
        self.key_id = "sha256:" + hashlib.sha256(self.public_der).hexdigest()

    def frame(
        self, method: str, request_id: str, binding: Binding | None, body: dict,
        *, expected_state_version: int = 0, nonce: bytes | None = None,
        issued_at: int | None = None, expires_at: int | None = None,
    ) -> RequestFrame:
        issued = int(time.time()) if issued_at is None else issued_at
        expires = issued + 60 if expires_at is None else expires_at
        unsigned = RequestFrame(
            API_VERSION, method, request_id, nonce or os.urandom(32), issued, expires,
            self.issuer_id, self.key_id, self.boot_id, expected_state_version,
            cbor.dumps(binding.dict() if binding else None), cbor.dumps(body), b"",
        )
        authorization = cose.sign1(
            authorization_payload(unsigned), self.private_key_path, self.cose_kid,
            Authorizer.AAD,
        )
        return RequestFrame(
            unsigned.protocol_version, unsigned.method, unsigned.request_id,
            unsigned.nonce, unsigned.issued_at, unsigned.expires_at,
            unsigned.issuer_id, unsigned.key_id, unsigned.boot_id,
            unsigned.expected_state_version, unsigned.binding_cbor,
            unsigned.payload_cbor, authorization,
        )

    def envelope(self, *args, **kwargs):
        from .model import Envelope
        return Envelope.from_frame(self.frame(*args, **kwargs).encode())

    def packet(self, *args, **kwargs) -> bytes:
        return pack_packet(self.frame(*args, **kwargs).encode())


def transact(socket_path: str, packet: bytes, cgroup_fd: int | None = None, timeout: float = 3.0) -> ResponseFrame:
    ancillary = []
    if cgroup_fd is not None:
        import array
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [cgroup_fd]))]
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client.settimeout(timeout)
    try:
        client.connect(socket_path)
        client.sendmsg([packet], ancillary)
        return ResponseFrame.decode(unpack_packet(client.recv(1 << 20)))
    finally:
        client.close()
