"""Validated, installable production launcher for ig-kmx-guardd."""
from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path

from .guardian_integration import FailSafeGuardService
from .model import digest
from .receipt import Signer
from .runtime import KernelInventory, VanillaIGRuntime
from .service import Authorizer, Config
from .store import Store

REQUIRED = {
    "node_id", "allowed_uids", "gadget_digest", "policy_digest_allowlist",
    "ig_path", "ig_sha256", "oci_archive", "oci_sha256", "socket_path",
    "state_db", "authorization_public_key_file", "authorization_issuer_id", "receipt_private_key_file",
    "receipt_public_key_file",
}
OPTIONAL = {
    "bpftool_path", "socket_mode", "freeze_timeout_s", "stable_empty_s",
    "max_policy_bytes", "receive_timeout_s", "max_workers", "listen_backlog",
    "max_evidence", "max_event_queue",
}


def secret_file(path: str) -> bytes:
    resolved = Path(path).resolve(strict=True)
    info = resolved.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"secret is not regular file: {resolved}")
    if info.st_uid != 0:
        raise ValueError(f"secret not root-owned: {resolved}")
    if info.st_mode & 0o077:
        raise ValueError(f"secret permissions too broad: {resolved}")
    value = resolved.read_bytes()
    if len(value) < 32:
        raise ValueError(f"secret too short: {resolved}")
    return value


def load(path: str) -> dict:
    config_path = Path(path).resolve(strict=True)
    if not stat.S_ISREG(config_path.stat().st_mode):
        raise ValueError("configuration must be a regular file")
    data = json.loads(config_path.read_text())
    if not isinstance(data, dict) or set(data) - REQUIRED - OPTIONAL or REQUIRED - set(data):
        raise ValueError("configuration fields mismatch")
    uids = data["allowed_uids"]
    if not isinstance(uids, list) or not uids or any(type(uid) is not int or uid < 0 for uid in uids):
        raise ValueError("invalid allowed_uids")
    policies = data["policy_digest_allowlist"]
    if not isinstance(policies, list):
        raise ValueError("invalid policy_digest_allowlist")
    for item in policies:
        digest(item, "policy digest")
    if not isinstance(data["node_id"], str) or not data["node_id"]:
        raise ValueError("invalid node_id")
    if not isinstance(data["authorization_issuer_id"], str) or not data["authorization_issuer_id"]:
        raise ValueError("invalid authorization_issuer_id")
    digest(data["gadget_digest"], "gadget_digest")
    digest(data["ig_sha256"], "ig_sha256")
    digest(data["oci_sha256"], "oci_sha256")
    for field in (
        "ig_path", "oci_archive", "socket_path", "state_db", "authorization_public_key_file",
        "receipt_private_key_file", "receipt_public_key_file",
    ):
        if not isinstance(data[field], str) or not os.path.isabs(data[field]):
            raise ValueError(f"{field} must be absolute")
    for name, default, minimum, maximum in (
        ("max_policy_bytes", 262144, 1024, 1 << 20),
        ("max_workers", 8, 1, 64),
        ("listen_backlog", 32, 1, 256),
        ("max_evidence", 10000, 1, 1_000_000),
        ("max_event_queue", 4096, 1, 1_000_000),
    ):
        value = data.get(name, default)
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError(f"{name} outside [{minimum}, {maximum}]")
    for name, default, minimum, maximum in (
        ("receive_timeout_s", 2.0, 0.05, 60.0),
        ("freeze_timeout_s", 5.0, 0.05, 60.0),
        ("stable_empty_s", 0.2, 0.0, 10.0),
    ):
        value = data.get(name, default)
        if type(value) not in (int, float) or not minimum <= float(value) <= maximum:
            raise ValueError(f"{name} outside [{minimum}, {maximum}]")
    return data


def build_server(data: dict):
    from .server import Server

    runtime = VanillaIGRuntime(
        data["ig_path"], data["ig_sha256"], data["oci_archive"], data["oci_sha256"],
        max_event_queue=int(data.get("max_event_queue", 4096)),
    )
    runtime.verify()
    config = Config(
        node_id=data["node_id"], allowed_uids=frozenset(data["allowed_uids"]),
        gadget_digest=data["gadget_digest"], policy_digest_allowlist=frozenset(data["policy_digest_allowlist"]),
        max_policy_bytes=int(data.get("max_policy_bytes", 262144)),
        freeze_timeout_s=float(data.get("freeze_timeout_s", 5.0)),
        stable_empty_s=float(data.get("stable_empty_s", 0.2)),
    )
    store = Store(data["state_db"], max_evidence=int(data.get("max_evidence", 10000)))
    store.recover()
    service = FailSafeGuardService(
        config, store,
        Signer(data["receipt_private_key_file"], data["receipt_public_key_file"]),
        Authorizer.from_public_key(data["authorization_issuer_id"], data["authorization_public_key_file"]), runtime,
        KernelInventory(data.get("bpftool_path", "/usr/sbin/bpftool")),
    )
    server = Server(
        data["socket_path"], service, int(str(data.get("socket_mode", "0660")), 8),
        receive_timeout_s=float(data.get("receive_timeout_s", 2.0)),
        max_workers=int(data.get("max_workers", 8)),
        listen_backlog=int(data.get("listen_backlog", 32)),
    )
    return server, store


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="KMX/IG node-local guard daemon")
    parser.add_argument("--config", required=True, help="absolute validated JSON configuration path")
    args = parser.parse_args(argv)
    data = load(args.config)
    server, store = build_server(data)
    try:
        server.serve_forever()
    finally:
        server.close()
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
