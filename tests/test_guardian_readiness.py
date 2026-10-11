import json
import socket

import pytest

from ig_kmx_guardd.cgroup import CgroupIdentity
from ig_kmx_guardd.guardian import GuardianHandle, _await_ready


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
