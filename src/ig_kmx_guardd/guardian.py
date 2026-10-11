"""Independent per-session cgroup fail-safe guardian.

A guardian is a separate process holding duplicated kernel handles. It freezes
the exact cgroup if vanilla IG, guardd, or the IG event consumer dies. It never
thaws and accepts only a one-byte orderly-disarm command inherited from guardd.
"""
from __future__ import annotations

import argparse
import json
import os
import select
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .cgroup import CgroupIdentity, read_events, set_freeze, validate_cgroup_fd


@dataclass
class GuardianHandle:
    process: subprocess.Popen
    control: socket.socket
    cgroup_identity: CgroupIdentity
    cause: str | None = None
    frozen: bool = False
    error: str | None = None

    def confirm_armed(self, timeout_s: float) -> dict:
        """Synchronize with the live guardian immediately before release."""
        try:
            self.control.sendall(b"P")
        except OSError as exc:
            raise RuntimeError(f"guardian challenge failed: {exc}") from exc
        timeout_ms = max(1, round(min(max(timeout_s, 0.1), 5.0) * 1000))
        poller = select.poll()
        poller.register(self.control.fileno(), select.POLLIN | select.POLLHUP | select.POLLERR)
        events = dict(poller.poll(timeout_ms))
        if not events:
            raise TimeoutError("guardian challenge timed out")
        payload = self.control.recv(4096)
        if not payload:
            raise RuntimeError(f"guardian exited during challenge with status {self.process.poll()}")
        try:
            notice = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError(f"invalid guardian challenge response: {exc}") from exc
        if notice != {"armed": True} or self.process.poll() is not None:
            raise RuntimeError(f"guardian is not armed: {notice}")
        return notice

    def refresh(self) -> dict:
        """Drain bounded guardian notices without blocking."""
        while True:
            try:
                payload = self.control.recv(4096, socket.MSG_DONTWAIT)
            except BlockingIOError:
                break
            except OSError as exc:
                self.error = str(exc)
                break
            if not payload:
                break
            try:
                notice = json.loads(payload)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                self.error = f"invalid guardian notice: {exc}"
                continue
            self.cause = notice.get("cause")
            self.frozen = notice.get("frozen") is True
            self.error = notice.get("error")
        return {"alive": self.process.poll() is None, "cause": self.cause,
                "frozen": self.frozen, "error": self.error, "pid": self.process.pid}

    def disarm(self, timeout_s: float = 2.0) -> dict:
        """Disarm only during validated empty-cgroup teardown or orderly stop."""
        try:
            self.control.sendall(b"D")
        except (BrokenPipeError, OSError):
            pass
        try:
            self.process.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=timeout_s)
            self.error = "guardian forced down after disarm timeout"
        try:
            self.control.close()
        except OSError:
            pass
        if self.process.stderr is not None:
            self.process.stderr.close()
        return {"alive": False, "cause": self.cause, "frozen": self.frozen,
                "error": self.error, "pid": self.process.pid}


def launch(cgroup_fd: int, worker_pidfd: int | None, event_consumer_fd: int,
           identity: CgroupIdentity, timeout_s: float) -> GuardianHandle:
    if worker_pidfd is None or not hasattr(os, "pidfd_open"):
        raise RuntimeError("pidfd support is mandatory for fail-safe activation")
    if event_consumer_fd < 0:
        raise RuntimeError("event-consumer liveness fd is mandatory")
    guardian_side, daemon_side = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    guardian_side.set_inheritable(True)
    owned_cgroup = os.dup(cgroup_fd)
    owned_worker = os.dup(worker_pidfd)
    owned_consumer = os.dup(event_consumer_fd)
    parent_pidfd = os.pidfd_open(os.getpid(), 0)
    for fd in (owned_cgroup, owned_worker, owned_consumer, parent_pidfd):
        os.set_inheritable(fd, True)
    argv = (
        sys.executable, "-m", "ig_kmx_guardd.guardian",
        "--cgroup-fd", str(owned_cgroup), "--worker-pidfd", str(owned_worker),
        "--event-consumer-fd", str(owned_consumer),
        "--parent-pidfd", str(parent_pidfd), "--control-fd", str(guardian_side.fileno()),
        "--identity", json.dumps(identity.dict(), sort_keys=True, separators=(",", ":")),
        "--timeout", str(timeout_s),
    )
    environment = dict(os.environ)
    package_root = str(Path(__file__).resolve().parent.parent)
    prior_path = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = package_root if not prior_path else package_root + os.pathsep + prior_path
    inherited = (owned_cgroup, owned_worker, owned_consumer, parent_pidfd, guardian_side.fileno())
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, env=environment, pass_fds=inherited,
            close_fds=True, start_new_session=False,
        )
    finally:
        guardian_side.close()
        for fd in (owned_cgroup, owned_worker, owned_consumer, parent_pidfd):
            os.close(fd)
    daemon_side.setblocking(False)
    handle = GuardianHandle(process, daemon_side, identity)
    try:
        _await_ready(process, daemon_side, timeout_s)
    except Exception as exc:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2.0)
        diagnostic = process.stderr.read(4096).decode(errors="replace").strip() if process.stderr else ""
        daemon_side.close()
        raise RuntimeError(f"fail-safe guardian failed to arm: {exc}; {diagnostic}".rstrip("; ")) from exc
    return handle


def _await_ready(process: subprocess.Popen, control: socket.socket, timeout_s: float) -> None:
    timeout_ms = max(1, round(min(max(timeout_s, 0.1), 5.0) * 1000))
    poller = select.poll()
    poller.register(control.fileno(), select.POLLIN | select.POLLHUP | select.POLLERR)
    events = dict(poller.poll(timeout_ms))
    if not events:
        raise TimeoutError("guardian readiness timed out")
    payload = control.recv(4096)
    if not payload:
        raise RuntimeError(f"guardian exited before readiness with status {process.poll()}")
    try:
        notice = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"invalid guardian readiness notice: {exc}") from exc
    if notice != {"ready": True}:
        raise RuntimeError(f"guardian rejected readiness: {notice}")
    if process.poll() is not None:
        raise RuntimeError(f"guardian exited during readiness with status {process.returncode}")


def _notice(control: socket.socket, cause: str, frozen: bool, error: str | None = None) -> None:
    payload = json.dumps({"cause": cause, "frozen": frozen, "error": error},
                         sort_keys=True, separators=(",", ":")).encode()
    try:
        control.send(payload)
    except OSError:
        pass


def _confirm_frozen(cgroup_fd: int, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if read_events(cgroup_fd).get("frozen") == 1:
            return True
        time.sleep(0.01)
    return False


def _guardd_loss_cause(parent_pidfd: int, parent_reported: bool, fallback: str) -> str:
    if parent_reported:
        return "guardd_died"
    probe = select.poll()
    probe.register(parent_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return "guardd_died" if probe.poll(100) else fallback


def guard(cgroup_fd: int, worker_pidfd: int, event_consumer_fd: int,
          parent_pidfd: int, control_fd: int, expected: CgroupIdentity,
          timeout_s: float) -> int:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    control = socket.socket(fileno=control_fd)
    if validate_cgroup_fd(cgroup_fd) != expected:
        _notice(control, "identity_mismatch", False, "cgroup identity changed before guardian arm")
        return 70
    poller = select.poll()
    mask = select.POLLIN | select.POLLHUP | select.POLLERR
    for fd in (control_fd, worker_pidfd, event_consumer_fd, parent_pidfd):
        poller.register(fd, mask)
    control.send(json.dumps({"ready": True}, separators=(",", ":")).encode())
    worker_watched = True
    while True:
        events = dict(poller.poll())
        event = events.get(control_fd, 0)
        if parent_pidfd in events:
            cause = "guardd_died"
        elif event & select.POLLIN:
            command = control.recv(16)
            if command == b"D":
                _notice(control, "orderly_disarm", False)
                return 0
            if command == b"P":
                if validate_cgroup_fd(cgroup_fd) != expected:
                    cause = "identity_mismatch"
                else:
                    control.send(json.dumps({"armed": True}, separators=(",", ":")).encode())
                    continue
            elif command == b"":
                cause = "guardd_control_lost"
            else:
                cause = "invalid_control"
        elif event & (select.POLLHUP | select.POLLERR):
            cause = "guardd_control_lost"
        elif worker_watched and worker_pidfd in events:
            cause = "ig_worker_died"
        elif event_consumer_fd in events:
            # IG exit closes stdout and therefore the consumer sentinel a few
            # scheduler ticks before its pidfd may become readable. Give the
            # kernel pidfd a bounded grace interval so one physical worker
            # death is attributed as such; a live-worker consumer exit remains
            # independently classified.
            worker_probe = select.poll()
            worker_probe.register(worker_pidfd, mask)
            cause = "ig_worker_died" if worker_probe.poll(100) else "event_consumer_died"
        else:
            continue
        try:
            if validate_cgroup_fd(cgroup_fd) != expected:
                raise RuntimeError("cgroup identity changed before fail-safe freeze")
            set_freeze(cgroup_fd, True)
            if not _confirm_frozen(cgroup_fd, timeout_s):
                raise TimeoutError("cgroup freeze was not confirmed")
            # The worker is outside the workload cgroup. Once frozen=1 is
            # confirmed, retire it by the pidfd bound at activation whenever
            # its supervisor or evidence consumer has been lost.
            if cause in {"guardd_died", "guardd_control_lost", "event_consumer_died"}:
                signal.pidfd_send_signal(worker_pidfd, signal.SIGKILL)
            if cause in {"guardd_control_lost", "event_consumer_died"}:
                cause = _guardd_loss_cause(parent_pidfd, False, cause)
            _notice(control, cause, True)
        except ProcessLookupError:
            _notice(control, cause, True)
        except Exception as exc:
            _notice(control, cause, False, str(exc))
            return 71
        if cause != "ig_worker_died":
            return 0
        poller.unregister(worker_pidfd)
        poller.unregister(event_consumer_fd)
        worker_watched = False


def parse(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cgroup-fd", required=True, type=int)
    parser.add_argument("--worker-pidfd", required=True, type=int)
    parser.add_argument("--event-consumer-fd", required=True, type=int)
    parser.add_argument("--parent-pidfd", required=True, type=int)
    parser.add_argument("--control-fd", required=True, type=int)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse(argv)
    raw = json.loads(args.identity)
    expected = CgroupIdentity(**{key: int(raw[key]) for key in ("dev", "ino", "mount_id", "cgroup_id")})
    return guard(args.cgroup_fd, args.worker_pidfd, args.event_consumer_fd,
                 args.parent_pidfd, args.control_fd, expected, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
