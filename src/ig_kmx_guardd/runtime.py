"""Pinned vanilla-IG supervision and daemon-owned BPF ownership/readback proof."""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import subprocess
import tarfile
import threading
from collections import deque
import time
from dataclasses import dataclass
from pathlib import Path

from .model import digest, sha256_bytes


class EventStream:
    """Continuously drain newline-delimited IG JSON into a bounded queue.

    Kernel enforcement remains independent of this userspace path. Overflow is
    explicit and monotonic: oldest events are discarded and the exact count is
    transferred into durable evidence by GuardService.
    """
    def __init__(self, pipe, maximum: int = 4096):
        if not 1 <= maximum <= 1_000_000:
            raise ValueError("event queue limit outside [1, 1000000]")
        self.pipe = pipe
        self.maximum = maximum
        self.items = deque()
        self.total = 0
        self.dropped = 0
        self.malformed = 0
        self._reported_dropped = 0
        self._reported_malformed = 0
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._read, name="ig-event-drain", daemon=True)
        self.thread.start()

    def _read(self) -> None:
        for line in iter(self.pipe.readline, b""):
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("event is not an object")
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                with self.lock:
                    self.malformed += 1
                continue
            with self.lock:
                self.total += 1
                if len(self.items) == self.maximum:
                    self.items.popleft()
                    self.dropped += 1
                self.items.append(event)

    def drain(self) -> tuple[list[dict], dict]:
        with self.lock:
            events = list(self.items)
            self.items.clear()
            delta_dropped = self.dropped - self._reported_dropped
            delta_malformed = self.malformed - self._reported_malformed
            self._reported_dropped = self.dropped
            self._reported_malformed = self.malformed
            status = {"total": self.total, "queued": 0, "dropped": self.dropped,
                      "malformed": self.malformed, "new_dropped": delta_dropped,
                      "new_malformed": delta_malformed}
        return events, status

    def status(self) -> dict:
        with self.lock:
            return {"total": self.total, "queued": len(self.items), "dropped": self.dropped,
                    "malformed": self.malformed}

    def close(self) -> None:
        if self.pipe and not self.pipe.closed:
            self.pipe.close()
        self.thread.join(timeout=1.0)


@dataclass
class Worker:
    process: subprocess.Popen
    pidfd: int | None
    started_ns: int
    command: tuple[str, ...]
    events: EventStream | None = None


class VanillaIGRuntime:
    def __init__(self, ig_path: str, ig_sha256: str, oci_archive: str, oci_sha256: str,
                 timeout_s: float = 15.0, max_event_queue: int = 4096):
        self.ig_path = os.path.realpath(ig_path)
        self.oci_archive = os.path.realpath(oci_archive)
        self.ig_sha256 = digest(ig_sha256, "ig_sha256")
        self.oci_sha256 = digest(oci_sha256, "oci_sha256")
        self.timeout_s = timeout_s
        if not 1 <= max_event_queue <= 1_000_000:
            raise ValueError("max_event_queue outside [1, 1000000]")
        self.max_event_queue = max_event_queue
        self.gadget_image: str | None = None

    def _hash_file(self, path: str) -> str:
        hasher = hashlib.sha256()
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            while chunk := os.read(fd, 1 << 20):
                hasher.update(chunk)
        finally:
            os.close(fd)
        return "sha256:" + hasher.hexdigest()

    def _archive_image(self) -> str:
        try:
            with tarfile.open(self.oci_archive, "r:*") as archive:
                member = archive.getmember("index.json")
                if not member.isfile() or member.size > 1 << 20:
                    raise ValueError("invalid OCI index.json")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("OCI index.json is unreadable")
                index = json.load(stream)
        except (KeyError, tarfile.TarError, json.JSONDecodeError) as exc:
            raise ValueError("invalid OCI archive") from exc
        manifests = index.get("manifests") if isinstance(index, dict) else None
        if not isinstance(manifests, list):
            raise ValueError("OCI index manifests missing")
        references = {
            annotations["org.opencontainers.image.ref.name"]
            for manifest in manifests if isinstance(manifest, dict)
            for annotations in [manifest.get("annotations")]
            if isinstance(annotations, dict)
            and isinstance(annotations.get("org.opencontainers.image.ref.name"), str)
        }
        if len(references) != 1:
            raise ValueError("OCI archive must declare exactly one image reference")
        image = references.pop()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,511}", image):
            raise ValueError("invalid OCI image reference")
        return image

    def _import_archive(self) -> None:
        completed = subprocess.run(
            (self.ig_path, "image", "import", self.oci_archive),
            stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=self.timeout_s,
        )
        if completed.returncode != 0:
            diagnostic = (completed.stderr or completed.stdout or b"").decode(errors="replace")[-4096:].strip()
            raise ValueError(f"IG image import failed: {diagnostic or f'exit {completed.returncode}'}")

    def verify(self) -> dict:
        stat_result = os.stat(self.ig_path, follow_symlinks=False)
        if not stat_result.st_mode & 0o111:
            raise ValueError("IG binary is not executable")
        actual_ig = self._hash_file(self.ig_path)
        actual_oci = self._hash_file(self.oci_archive)
        if actual_ig != self.ig_sha256:
            raise ValueError("IG binary digest mismatch")
        if actual_oci != self.oci_sha256:
            raise ValueError("OCI archive digest mismatch")
        gadget_image = self._archive_image()
        self._import_archive()
        self.gadget_image = gadget_image
        return {
            "ig_binary": self.ig_path,
            "ig_sha256": actual_ig,
            "oci_archive": self.oci_archive,
            "oci_archive_sha256": actual_oci,
            "gadget_image": self.gadget_image,
        }

    def start(self, target_cgroup_id: int, policy_json: bytes) -> Worker:
        if not 0 < target_cgroup_id < 2**64:
            raise ValueError("invalid target cgroup id")
        if len(policy_json) > 262144:
            raise ValueError("policy too large")
        if not isinstance(json.loads(policy_json), dict):
            raise ValueError("policy must be object")
        if self.gadget_image is None:
            raise ValueError("IG runtime is not verified")
        argv = (
            self.ig_path, "run", self.gadget_image, "--verify-image=false", "--pull=never", "--runtimes=",
            f"--target-cgroup-id={target_cgroup_id}", "--fail-closed=true", f"--policy={policy_json.decode()}", "-o", "json",
        )
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, start_new_session=False, text=False, bufsize=0,
        )
        pidfd = os.pidfd_open(process.pid, 0) if hasattr(os, "pidfd_open") else None
        if process.stdout is None:
            process.terminate()
            raise RuntimeError("IG event pipe unavailable")
        return Worker(process, pidfd, time.time_ns(), argv, EventStream(process.stdout, self.max_event_queue))

    def terminate(self, worker: Worker, grace_s: float = 3.0) -> str:
        """Idempotently terminate a worker and return bounded diagnostic stderr."""
        if worker.process.poll() is None:
            worker.process.terminate()
            try:
                worker.process.wait(timeout=grace_s)
            except subprocess.TimeoutExpired:
                worker.process.kill()
                worker.process.wait(timeout=grace_s)
        diagnostic = b""
        if worker.events is not None:
            worker.events.close()
        if worker.process.stderr and not worker.process.stderr.closed:
            # The process is reaped, so reading the bounded tail cannot block.
            diagnostic = worker.process.stderr.read(16384) or b""
            worker.process.stderr.close()
        if worker.pidfd is not None:
            os.close(worker.pidfd)
            worker.pidfd = None
        return diagnostic.decode(errors="replace")[-4096:].strip()


class KernelInventory:
    """Correlate worker FDs and independently read/update exact policy maps."""

    def __init__(self, bpftool_path: str = "/usr/sbin/bpftool", command_timeout_s: float = 4.0):
        self.bpftool_path = os.path.realpath(bpftool_path)
        self.command_timeout_s = command_timeout_s
        self._claims: dict[tuple[str, int], int] = {}
        self._lock = threading.RLock()

    def _run(self, *args: object) -> bytes:
        completed = subprocess.run(
            (self.bpftool_path, *map(str, args)), stdin=subprocess.DEVNULL,
            capture_output=True, check=False, timeout=self.command_timeout_s,
        )
        if completed.returncode:
            raise ValueError(f"bpftool failed: {completed.stderr.decode(errors='replace')[:300]}")
        return completed.stdout

    def _run_json(self, *args: object):
        try:
            return json.loads(self._run("-j", *args))
        except json.JSONDecodeError as exc:
            raise ValueError("invalid bpftool JSON") from exc

    @staticmethod
    def _bytes(value) -> bytes:
        if isinstance(value, list):
            output = bytearray()
            for item in value:
                if isinstance(item, int):
                    if not 0 <= item <= 255:
                        raise ValueError("bpftool byte outside uint8")
                    output.append(item)
                elif isinstance(item, str):
                    text = item.removeprefix("0x")
                    if len(text) != 2:
                        raise ValueError("invalid bpftool hex byte")
                    output.append(int(text, 16))
                else:
                    raise ValueError("unsupported bpftool list byte")
            return bytes(output)
        if isinstance(value, str):
            return bytes.fromhex(value.removeprefix("0x").replace(" ", "").replace(":", ""))
        if isinstance(value, dict):
            for key in ("bytes", "data"):
                if key in value:
                    return KernelInventory._bytes(value[key])
        raise ValueError("unsupported bpftool byte encoding")

    def _objects(self, pid: int) -> list[dict]:
        fdroot = Path(f"/proc/{pid}/fd")
        if not fdroot.is_dir():
            raise ValueError("worker disappeared")
        objects: list[dict] = []
        for entry in fdroot.iterdir():
            try:
                lines = Path(f"/proc/{pid}/fdinfo/{entry.name}").read_text().splitlines()
            except (FileNotFoundError, PermissionError, OSError):  # AUDITED: DELIBERATE — worker descriptors race
                continue
            attrs = {}
            for line in lines:
                if ":" in line:
                    key, value = line.split(":", 1)
                    attrs[key.strip()] = value.strip()
            if "prog_id" in attrs:
                objects.append({"fd": int(entry.name), "kind": "program", "id": int(attrs["prog_id"])})
            if "map_id" in attrs:
                objects.append({"fd": int(entry.name), "kind": "map", "id": int(attrs["map_id"])})
            if "link_id" in attrs:
                objects.append({
                    "fd": int(entry.name), "kind": "link", "id": int(attrs["link_id"]),
                    "prog_id": int(attrs.get("prog_id", 0)),
                })
        return objects

    def _owned_catalog(self, pid: int, expected_minimum: dict | None = None) -> tuple[list[tuple[str, int]], dict, dict[str, int]]:
        objects = self._objects(pid)
        counts = {kind: sum(obj["kind"] == kind for obj in objects) for kind in ("program", "map", "link")}
        minimum = expected_minimum or {"program": 1, "map": 1, "link": 1}
        if any(counts[kind] < minimum.get(kind, 1) for kind in counts):
            raise ValueError(f"insufficient worker-owned BPF objects: {counts}")
        unique = sorted(set((obj["kind"], obj["id"]) for obj in objects))
        with self._lock:
            collisions = [item for item in unique if item in self._claims and self._claims[item] != pid]
        if collisions:
            raise ValueError(f"BPF object already claimed by another worker: {collisions}")
        map_ids = {identity for kind, identity in unique if kind == "map"}
        return unique, counts, self._map_catalog(map_ids)

    def _map_catalog(self, map_ids: set[int]) -> dict[str, int]:
        result: dict[str, int] = {}
        for map_id in map_ids:
            info = self._run_json("map", "show", "id", map_id)
            if isinstance(info, list):
                info = info[0]
            name = info.get("name")
            if not isinstance(name, str) or not name:
                raise ValueError(f"unnamed worker map {map_id}")
            if name in result:
                raise ValueError(f"duplicate worker map name {name}")
            result[name] = map_id
        return result

    def _dump(self, map_id: int) -> list[tuple[bytes, bytes]]:
        raw = self._run_json("map", "dump", "id", map_id)
        if not isinstance(raw, list):
            raise ValueError("map dump is not an array")
        return [(self._bytes(row["key"]), self._bytes(row["value"])) for row in raw]

    @staticmethod
    def _fnv64(path: str) -> int:
        value = 14695981039346656037
        for octet in path.encode():
            value = ((value ^ octet) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
        return value

    @staticmethod
    def _path(raw: bytes) -> str:
        try:
            return raw.split(b"\0", 1)[0].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("non-UTF-8 kernel policy path") from exc

    def _policy_readback(self, catalog: dict[str, int], expected: dict) -> dict:
        required = {".rodata", "policy_state", "exec_rules", "write_rules", "network_rules"}
        missing = sorted(required - set(catalog))
        if missing:
            raise ValueError(f"missing policy maps: {missing}")
        rodata_rows = self._dump(catalog[".rodata"])
        if len(rodata_rows) != 1 or rodata_rows[0][0] != b"\0\0\0\0" or len(rodata_rows[0][1]) != 9:
            raise ValueError("invalid gadget .rodata map")
        target_cgroup_id = struct.unpack_from("<Q", rodata_rows[0][1])[0]
        ro_fail_closed = rodata_rows[0][1][8]
        if target_cgroup_id != expected["cgroup_id"] or ro_fail_closed != 1:
            raise ValueError("target cgroup/fail-closed .rodata mismatch")
        state_rows = self._dump(catalog["policy_state"])
        if len(state_rows) != 1 or state_rows[0][0] != b"\0\0\0\0" or len(state_rows[0][1]) < 16:
            raise ValueError("invalid policy_state map")
        state, quarantined, generation, failure_closed = struct.unpack_from("<IIII", state_rows[0][1])
        expected_quarantined = expected.get("expected_quarantined", False)
        if (state, generation, failure_closed) != (1, expected["generation"], 1):
            raise ValueError("policy_state readback mismatch")
        if expected_quarantined is not None and quarantined != int(bool(expected_quarantined)):
            raise ValueError("policy_state quarantine readback mismatch")
        policy = expected["policy"]
        spec = policy["spec"]
        expected_exec = sorted((rule["path"], int(rule["id"]), 0) for rule in spec.get("denyExecutables", []))
        actual_exec = []
        for key, value in self._dump(catalog["exec_rules"]):
            if len(value) < 8:
                raise ValueError("short exec rule value")
            rule_id, quarantine = struct.unpack_from("<II", value)
            actual_exec.append((self._path(key), rule_id, quarantine))
        expected_write = sorted((self._fnv64(rule["path"]), int(rule["id"]), 0, rule["path"]) for rule in spec.get("denyWrites", []))
        actual_write = []
        for key, value in self._dump(catalog["write_rules"]):
            if len(key) != 8 or len(value) < 264:
                raise ValueError("invalid write rule entry")
            rule_id, quarantine = struct.unpack_from("<II", value)
            actual_write.append((struct.unpack("<Q", key)[0], rule_id, quarantine, self._path(value[8:264])))
        if sorted(actual_exec) != expected_exec:
            raise ValueError("exec_rules readback mismatch")
        if sorted(actual_write) != expected_write:
            raise ValueError("write_rules readback mismatch")
        if self._dump(catalog["network_rules"]):
            raise ValueError("network_rules must be empty")
        return {
            "verified": True, "state": "ACTIVE", "quarantined": bool(quarantined),
            "generation": generation, "failure_closed": True, "target_cgroup_id": target_cgroup_id,
            "policy_digest": sha256_bytes(expected["policy_raw"]),
            "policy_digest_source": "authenticated canonical request; enforcement projection independently read back",
            "exec_rules": len(actual_exec), "write_rules": len(actual_write), "network_rules": 0,
            "map_ids": {name: catalog[name] for name in sorted(required)},
        }

    def correlate(self, pid: int, expected: dict) -> dict:
        deadline = time.monotonic() + float(expected.get("timeout_s", 15.0))
        last_error = None
        while time.monotonic() < deadline:
            if not Path(f"/proc/{pid}").exists():
                raise ValueError("worker disappeared")
            try:
                unique, counts, catalog = self._owned_catalog(pid, expected.get("minimum_counts"))
                readback = self._policy_readback(catalog, expected)
                with self._lock:
                    for item in unique:
                        self._claims[item] = pid
                return {
                    "worker_pid": pid,
                    "objects": [{"kind": kind, "id": identity} for kind, identity in unique],
                    "counts": counts, "target_cgroup_id": expected["cgroup_id"],
                    "map_readback": readback, "assurance": "worker_fd_policy_map_readback",
                }
            except (ValueError, subprocess.TimeoutExpired, OSError) as exc:
                last_error = exc
                time.sleep(0.05)
        raise ValueError(f"kernel correlation/readback timeout: {last_error}")

    def clear_quarantine(self, pid: int, expected: dict) -> dict:
        """Idempotently clear the sticky latch and independently read it back."""
        _unique, _counts, catalog = self._owned_catalog(pid, expected.get("minimum_counts"))
        before = self._policy_readback(catalog, dict(expected, expected_quarantined=None))
        map_id = catalog["policy_state"]
        if before["quarantined"]:
            value = struct.pack("<IIII", 1, 0, expected["generation"], 1)
            self._run(
                "map", "update", "id", map_id,
                "key", "hex", "00", "00", "00", "00",
                "value", "hex", *[f"{octet:02x}" for octet in value], "any",
            )
        after = self._policy_readback(catalog, dict(expected, expected_quarantined=False))
        return {
            "operation": "daemon_owned_policy_state_update",
            "map_id": map_id,
            "before_quarantined": before["quarantined"],
            "after_quarantined": after["quarantined"],
            "already_clear": not before["quarantined"],
            "readback": after,
        }

    def release(self, pid: int) -> None:
        with self._lock:
            for item, owner in list(self._claims.items()):
                if owner == pid:
                    del self._claims[item]
