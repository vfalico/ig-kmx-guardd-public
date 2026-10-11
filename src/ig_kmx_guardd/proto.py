"""Strict fixed-schema protobuf wire codec for guardd v1.

The project intentionally checks in this small generated-equivalent codec so the
offline release has no build-time protoc/runtime dependency.  It implements only
wire types used by api/proto/v1/guardd.proto, rejects duplicate/unknown fields,
non-minimal varints and malformed lengths, and never accepts protobuf's usual
"last value wins" ambiguity at the authorization boundary.
"""
from __future__ import annotations

from dataclasses import dataclass

MAX_FIELD = 1 << 20
PROTOCOL_VERSION = "guardd.kmx.io/v1"


def _varint(value: int) -> bytes:
    if type(value) is not int or value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("protobuf uint64 out of range")
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    start = offset
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError("truncated protobuf varint")
        byte = data[offset]
        offset += 1
        if shift == 63 and byte > 1:
            raise ValueError("protobuf varint overflow")
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if data[start:offset] != _varint(value):
                raise ValueError("non-minimal protobuf varint")
            return value, offset
    raise ValueError("protobuf varint too long")


def _bytes_field(number: int, value: bytes) -> bytes:
    if len(value) > MAX_FIELD:
        raise ValueError("protobuf field too large")
    return _varint(number << 3 | 2) + _varint(len(value)) + value


def _text_field(number: int, value: str) -> bytes:
    return _bytes_field(number, value.encode("utf-8"))


def _uint_field(number: int, value: int) -> bytes:
    return _varint(number << 3) + _varint(value)


@dataclass(frozen=True)
class RequestFrame:
    protocol_version: str
    method: str
    request_id: str
    nonce: bytes
    issued_at: int
    expires_at: int
    issuer_id: str
    key_id: str
    boot_id: str
    expected_state_version: int
    binding_cbor: bytes
    payload_cbor: bytes
    authorization_cose: bytes

    def encode(self) -> bytes:
        fields = (
            _text_field(1, self.protocol_version), _text_field(2, self.method),
            _text_field(3, self.request_id), _bytes_field(4, self.nonce),
            _uint_field(5, self.issued_at), _uint_field(6, self.expires_at),
            _text_field(7, self.issuer_id), _text_field(8, self.key_id),
            _text_field(9, self.boot_id), _uint_field(10, self.expected_state_version),
            _bytes_field(11, self.binding_cbor), _bytes_field(12, self.payload_cbor),
            _bytes_field(13, self.authorization_cose),
        )
        return b"".join(fields)

    @classmethod
    def decode(cls, data: bytes) -> "RequestFrame":
        values = _decode(data, {
            1: "text", 2: "text", 3: "text", 4: "bytes", 5: "uint", 6: "uint",
            7: "text", 8: "text", 9: "text", 10: "uint", 11: "bytes",
            12: "bytes", 13: "bytes",
        })
        missing = set(range(1, 14)) - set(values)
        if missing:
            raise ValueError(f"protobuf request missing fields: {sorted(missing)}")
        return cls(*(values[number] for number in range(1, 14)))


@dataclass(frozen=True)
class ResponseFrame:
    protocol_version: str
    request_id: str
    ok: bool
    payload_cbor: bytes
    error_code: str = ""
    error_message: str = ""

    def encode(self) -> bytes:
        return b"".join((
            _text_field(1, self.protocol_version), _text_field(2, self.request_id),
            _uint_field(3, int(self.ok)), _bytes_field(4, self.payload_cbor),
            _text_field(5, self.error_code), _text_field(6, self.error_message),
        ))

    @classmethod
    def decode(cls, data: bytes) -> "ResponseFrame":
        values = _decode(data, {1: "text", 2: "text", 3: "uint", 4: "bytes", 5: "text", 6: "text"})
        missing = set(range(1, 7)) - set(values)
        if missing:
            raise ValueError(f"protobuf response missing fields: {sorted(missing)}")
        if values[3] not in (0, 1):
            raise ValueError("invalid protobuf boolean")
        return cls(values[1], values[2], bool(values[3]), values[4], values[5], values[6])


def _decode(data: bytes, schema: dict[int, str]) -> dict[int, object]:
    if not isinstance(data, bytes) or len(data) > MAX_FIELD:
        raise ValueError("invalid protobuf frame size")
    offset = 0
    result: dict[int, object] = {}
    while offset < len(data):
        tag, offset = _read_varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if number not in schema:
            raise ValueError(f"unknown protobuf field {number}")
        if number in result:
            raise ValueError(f"duplicate protobuf field {number}")
        kind = schema[number]
        if kind == "uint":
            if wire != 0:
                raise ValueError("protobuf wire type mismatch")
            result[number], offset = _read_varint(data, offset)
            continue
        if wire != 2:
            raise ValueError("protobuf wire type mismatch")
        length, offset = _read_varint(data, offset)
        end = offset + length
        if length > MAX_FIELD or end > len(data):
            raise ValueError("truncated/oversized protobuf field")
        raw = data[offset:end]
        offset = end
        if kind == "bytes":
            result[number] = raw
        else:
            try:
                result[number] = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("invalid protobuf UTF-8") from exc
    return result


def pack_packet(message: bytes) -> bytes:
    """Prepend the architecture-mandated 32-bit network-order frame length."""
    if not isinstance(message, bytes) or not message or len(message) > MAX_FIELD - 4:
        raise ValueError("invalid protobuf message size")
    return len(message).to_bytes(4, "big") + message


def unpack_packet(packet: bytes) -> bytes:
    if len(packet) < 4:
        raise ValueError("missing 32-bit frame length")
    declared = int.from_bytes(packet[:4], "big")
    if declared == 0 or declared > MAX_FIELD - 4 or declared != len(packet) - 4:
        raise ValueError("protobuf frame length mismatch")
    return packet[4:]
