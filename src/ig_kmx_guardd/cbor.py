"""Minimal deterministic CBOR codec for the guardd security boundary.

This is deliberately a closed RFC 8949 subset: integers, bytes, UTF-8 text,
arrays, maps, booleans and null.  Indefinite lengths, floats, tags and duplicate
map keys are rejected.  Decoding also requires byte-for-byte deterministic
re-encoding, preventing alternate encodings of signed data.
"""
from __future__ import annotations

from typing import Any

MAX_DEPTH = 32
MAX_ITEMS = 65536


def _head(major: int, value: int) -> bytes:
    if value < 0:
        raise ValueError("negative CBOR argument")
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")
    raise ValueError("CBOR integer out of range")


def dumps(value: Any, _depth: int = 0) -> bytes:
    if _depth > MAX_DEPTH:
        raise ValueError("CBOR nesting too deep")
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if type(value) is int:
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _head(3, len(encoded)) + encoded
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_ITEMS:
            raise ValueError("CBOR array too large")
        return _head(4, len(value)) + b"".join(dumps(item, _depth + 1) for item in value)
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS:
            raise ValueError("CBOR map too large")
        encoded = [(dumps(key, _depth + 1), dumps(item, _depth + 1)) for key, item in value.items()]
        encoded.sort(key=lambda pair: (len(pair[0]), pair[0]))
        return _head(5, len(encoded)) + b"".join(key + item for key, item in encoded)
    raise TypeError(f"unsupported CBOR type: {type(value).__name__}")


def _argument(data: bytes, offset: int, additional: int) -> tuple[int, int]:
    widths = {24: 1, 25: 2, 26: 4, 27: 8}
    if additional < 24:
        return additional, offset
    if additional not in widths:
        raise ValueError("indefinite/reserved CBOR argument")
    width = widths[additional]
    end = offset + width
    if end > len(data):
        raise ValueError("truncated CBOR argument")
    value = int.from_bytes(data[offset:end], "big")
    minimum = {24: 24, 25: 256, 26: 65536, 27: 4294967296}[additional]
    if value < minimum:
        raise ValueError("non-minimal CBOR argument")
    return value, end


def _load(data: bytes, offset: int, depth: int, budget: list[int]) -> tuple[Any, int]:
    if depth > MAX_DEPTH or offset >= len(data):
        raise ValueError("invalid CBOR nesting or truncation")
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError("CBOR item budget exceeded")
    first = data[offset]
    offset += 1
    major, additional = first >> 5, first & 31
    if major == 7:
        if additional == 20:
            return False, offset
        if additional == 21:
            return True, offset
        if additional == 22:
            return None, offset
        raise ValueError("unsupported CBOR simple/float value")
    value, offset = _argument(data, offset, additional)
    if major in (0, 1):
        return (value if major == 0 else -1 - value), offset
    if major in (2, 3):
        end = offset + value
        if end > len(data):
            raise ValueError("truncated CBOR string")
        raw = data[offset:end]
        if major == 2:
            return raw, end
        try:
            return raw.decode("utf-8"), end
        except UnicodeDecodeError as exc:
            raise ValueError("invalid CBOR UTF-8") from exc
    if major == 4:
        if value > MAX_ITEMS:
            raise ValueError("CBOR array too large")
        result = []
        for _ in range(value):
            item, offset = _load(data, offset, depth + 1, budget)
            result.append(item)
        return result, offset
    if major == 5:
        if value > MAX_ITEMS:
            raise ValueError("CBOR map too large")
        result = {}
        for _ in range(value):
            key, offset = _load(data, offset, depth + 1, budget)
            if not isinstance(key, (int, str, bytes)) or key in result:
                raise ValueError("unsupported or duplicate CBOR map key")
            item, offset = _load(data, offset, depth + 1, budget)
            result[key] = item
        return result, offset
    raise ValueError("unsupported CBOR major type")


def loads(data: bytes, *, require_canonical: bool = True) -> Any:
    if not isinstance(data, bytes):
        raise TypeError("CBOR input must be bytes")
    value, offset = _load(data, 0, 0, [MAX_ITEMS])
    if offset != len(data):
        raise ValueError("trailing CBOR bytes")
    if require_canonical and dumps(value) != data:
        raise ValueError("CBOR is not deterministic encoding")
    return value
