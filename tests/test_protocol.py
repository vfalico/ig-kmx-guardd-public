"""Negative and round-trip tests for the production protobuf/CBOR/COSE wire."""
from __future__ import annotations

import hashlib
import os
import sys
import time
import unittest
from dataclasses import replace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from protocol_helpers import AUTHORIZER, BUILDER
from ig_kmx_guardd import cbor
from ig_kmx_guardd.model import Binding, Envelope
from ig_kmx_guardd.proto import RequestFrame, pack_packet, unpack_packet

D = "sha256:" + "a" * 64


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.binding = Binding("session", "attempt", 1, D, D, "node")

    def frame(self):
        return BUILDER.frame("status", "request", self.binding, {}, expected_state_version=7)

    def test_exact_round_trip_and_authorization(self):
        frame = self.frame()
        env = Envelope.from_frame(frame.encode())
        AUTHORIZER.verify(env)
        self.assertEqual(env.expected_state_version, 7)
        self.assertEqual(env.boot_id, "boot")
        self.assertEqual(unpack_packet(pack_packet(frame.encode())), frame.encode())

    def test_duplicate_and_unknown_protobuf_fields_rejected(self):
        raw = self.frame().encode()
        with self.assertRaisesRegex(ValueError, "duplicate protobuf field"):
            RequestFrame.decode(raw + b"\x0a\x01x")
        with self.assertRaisesRegex(ValueError, "unknown protobuf field"):
            RequestFrame.decode(raw + b"\x72\x00")

    def test_nonminimal_varint_and_length_mismatch_rejected(self):
        raw = self.frame().encode()
        with self.assertRaisesRegex(ValueError, "non-minimal protobuf varint"):
            RequestFrame.decode(b"\x8a\x00" + raw[1:])
        with self.assertRaisesRegex(ValueError, "length mismatch"):
            unpack_packet((len(raw) + 1).to_bytes(4, "big") + raw)

    def test_noncanonical_cbor_and_duplicate_map_key_rejected(self):
        # 0 encoded with uint8 argument instead of shortest direct representation.
        with self.assertRaisesRegex(ValueError, "non-minimal"):
            cbor.loads(b"\x18\x00")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            cbor.loads(b"\xa2\x61a\x01\x61a\x02", require_canonical=False)
        frame = replace(self.frame(), payload_cbor=b"\xb8\x00")
        with self.assertRaisesRegex(ValueError, "non-minimal"):
            Envelope.from_frame(frame.encode())

    def test_signature_payload_key_expiry_and_boot_mutations_fail(self):
        frame = self.frame()
        env = Envelope.from_frame(frame.encode())
        env.authorization = env.authorization[:-1] + bytes([env.authorization[-1] ^ 1])
        with self.assertRaisesRegex(PermissionError, "COSE"):
            AUTHORIZER.verify(env)

        wrong_key = replace(frame, key_id="sha256:" + "0" * 64)
        env = Envelope.from_frame(wrong_key.encode())
        with self.assertRaisesRegex(PermissionError, "key id"):
            AUTHORIZER.verify(env)

        altered = replace(frame, expected_state_version=8)
        env = Envelope.from_frame(altered.encode())
        with self.assertRaisesRegex(PermissionError, "does not bind"):
            AUTHORIZER.verify(env)

        now = int(time.time())
        expired = BUILDER.frame("status", "expired", self.binding, {}, issued_at=now - 61, expires_at=now - 1)
        with self.assertRaisesRegex(ValueError, "expired"):
            Envelope.from_frame(expired.encode(), now=now)

    def test_nonce_is_binary_and_bounded(self):
        for nonce in (b"short", b"x" * 65):
            with self.subTest(length=len(nonce)):
                frame = BUILDER.frame("status", "nonce", self.binding, {}, nonce=nonce)
                with self.assertRaisesRegex(ValueError, "nonce"):
                    Envelope.from_frame(frame.encode())


if __name__ == "__main__":
    unittest.main()
