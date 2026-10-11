import json
import os
import socket
import threading
from types import SimpleNamespace

import pytest

from ig_kmx_guardd.cgroup import CgroupIdentity
from ig_kmx_guardd.guardian import GuardianHandle, _await_ready, _guardd_loss_cause
from ig_kmx_guardd.guardian_integration import FailSafeGuardService


class _Process:
    returncode = None

    def poll(self):
        return self.returncode


def test_guardian_readiness_requires_explicit_ready_notice():
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        sender.send(json.dumps({"ready": True}).encode())
        _await_ready(_Process(), receiver, 0.1)
    finally:
        sender.close()
        receiver.close()


def test_guardian_readiness_times_out_without_notice():
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        with pytest.raises(TimeoutError, match="readiness timed out"):
            _await_ready(_Process(), receiver, 0.01)
    finally:
        sender.close()
        receiver.close()


def test_guardian_readiness_rejects_failure_notice():
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        sender.send(json.dumps({"cause": "identity_mismatch", "frozen": False}).encode())
        with pytest.raises(RuntimeError, match="rejected readiness"):
            _await_ready(_Process(), receiver, 0.1)
    finally:
        sender.close()
        receiver.close()


def test_guardian_challenge_requires_live_armed_response():
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        sender.send(json.dumps({"armed": True}).encode())
        handle = GuardianHandle(
            _Process(), receiver, CgroupIdentity(dev=1, ino=2, mount_id=3, cgroup_id=4)
        )
        assert handle.confirm_armed(0.1) == {"armed": True}
        assert sender.recv(16) == b"P"
    finally:
        sender.close()
        receiver.close()


def test_guardian_challenge_rejects_queued_failure():
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        sender.send(json.dumps({"cause": "guardd_died", "frozen": False}).encode())
        handle = GuardianHandle(
            _Process(), receiver, CgroupIdentity(dev=1, ino=2, mount_id=3, cgroup_id=4)
        )
        with pytest.raises(RuntimeError, match="not armed"):
            handle.confirm_armed(0.1)
    finally:
        sender.close()
        receiver.close()


def test_event_consumer_sentinel_closes_when_drain_thread_exits():
    release = threading.Event()
    drain = threading.Thread(target=release.wait)
    drain.start()
    worker = SimpleNamespace(
        process=SimpleNamespace(pid=os.getpid()),
        events=SimpleNamespace(thread=drain),
    )
    read_fd, watcher = FailSafeGuardService._event_consumer_sentinel(worker)
    try:
        release.set()
        watcher.join(timeout=1.0)
        assert not watcher.is_alive()
        assert os.read(read_fd, 1) == b""
    finally:
        release.set()
        drain.join(timeout=1.0)
        os.close(read_fd)


def test_guardd_loss_prefers_reported_parent_exit():
    assert _guardd_loss_cause(-1, True, "event_consumer_died") == "guardd_died"


def test_guardd_loss_distinguishes_live_and_exited_parent():
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(write_fd)
        os.read(read_fd, 1)
        os._exit(0)
    os.close(read_fd)
    pidfd = os.pidfd_open(pid, 0)
    waited = False
    try:
        assert _guardd_loss_cause(pidfd, False, "guardd_control_lost") == "guardd_control_lost"
        assert _guardd_loss_cause(pidfd, False, "event_consumer_died") == "event_consumer_died"
        os.write(write_fd, b"x")
        os.close(write_fd)
        write_fd = -1
        os.waitpid(pid, 0)
        waited = True
        assert _guardd_loss_cause(pidfd, False, "event_consumer_died") == "guardd_died"
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        if not waited:
            os.waitpid(pid, 0)
        os.close(pidfd)
