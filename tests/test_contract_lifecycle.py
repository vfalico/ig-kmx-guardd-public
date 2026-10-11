"""Fault-injection regressions for strict transport and retry-safe lifecycle boundaries."""
import hashlib
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from protocol_helpers import AUTHORIZER, envelope as signed_envelope

from ig_kmx_guardd.cgroup import CgroupIdentity
from ig_kmx_guardd.model import API_VERSION, Binding, Envelope, State, canonical, sha256_bytes
from ig_kmx_guardd.receipt import Signer
from ig_kmx_guardd.service import Config, GuardService
from ig_kmx_guardd.store import Store

GADGET = "sha256:" + "f" * 64
AUTH = b"a" * 32


def policy():
    return {
        "apiVersion": "agentpolicy.gadget/v1alpha1", "kind": "AgentPolicy",
        "metadata": {"name": "secure", "digest": "sha256:" + "9" * 64},
        "spec": {"subject": {"taskUID": "task", "sessionID": "sess"}, "failureMode": "closed",
                 "denyExecutables": [{"id": 1, "path": "/bin/blocked"}], "denyWrites": [], "denyNetworks": []},
    }


class Process:
    pid = 8181
    def poll(self):
        return None


class Worker:
    process = Process()
    pidfd = None


class Runtime:
    def __init__(self):
        self.terminate_calls = 0
        self.fail_terminate = False

    def verify(self):
        return {"ig_sha256": "sha256:" + "1" * 64, "oci_archive_sha256": "sha256:" + "2" * 64}

    def start(self, _cgroup_id, _policy_raw):
        return Worker()

    def terminate(self, _worker):
        self.terminate_calls += 1
        if self.fail_terminate:
            self.fail_terminate = False
            raise OSError("terminate fault")


class Inventory:
    def __init__(self):
        self.clear_calls = 0
        self.release_calls = 0
        self.fail_clear = False
        self.fail_release = False

    def correlate(self, pid, expected):
        return {
            "worker_pid": pid, "objects": [], "counts": {"program": 1, "map": 4, "link": 1},
            "attachments": [
                {"program_name": "agentpolicy_exec", "program_id": 6, "link_id": 7,
                 "attach_type": "lsm/bprm_check_security", "target": f"cgroup:{expected['cgroup_id']}"},
            ],
            "map_readback": {
                "verified": True, "state": "ACTIVE", "quarantined": False,
                "generation": expected["generation"], "failure_closed": True,
                "target_cgroup_id": expected["cgroup_id"],
                "policy_digest": sha256_bytes(expected["policy_raw"]),
                "exec_rules": 1, "write_rules": 0, "network_rules": 0,
                "map_ids": {"policy_state": 1, "exec_rules": 2, "write_rules": 3, "network_rules": 4},
            }, "assurance": "worker_fd_policy_map_readback",
        }

    def clear_quarantine(self, _pid, expected):
        self.clear_calls += 1
        if self.fail_clear:
            self.fail_clear = False
            raise OSError("clear fault")
        return {"operation": "daemon_owned_policy_state_update", "map_id": 1,
                "before_quarantined": self.clear_calls == 1, "after_quarantined": False,
                "already_clear": self.clear_calls > 1,
                "readback": {"policy_digest": expected["policy_digest"]}}

    def release(self, _pid):
        self.release_calls += 1
        if self.fail_release:
            self.fail_release = False
            raise OSError("release fault")


class LifecycleContractTests(unittest.TestCase):
    def env(self, action, binding, body, request_id="request", nonce=None, issued=None, expected_state_version=None, **kwargs):
        if expected_state_version is None:
            expected_state_version = 0
            if binding is not None and action != "activate":
                try:
                    expected_state_version = self.store.session(binding.key())["state_version"]
                except KeyError:
                    pass
        return signed_envelope(action, binding, body, request_id, nonce, issued, expected_state_version=expected_state_version, **kwargs)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name + "/state.db")
        self.runtime = Runtime()
        self.inventory = Inventory()
        self.service = GuardService(
            Config("node", frozenset({1000}), GADGET, frozenset(), stable_empty_s=0),
            self.store, Signer(b"test-only-signing-seed"), AUTHORIZER,
            self.runtime, self.inventory, boot_id="boot",
        )
        self.policy = policy()
        self.binding = Binding("sess", "attempt", 1, sha256_bytes(canonical(self.policy)), GADGET, "node")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def activate(self):
        with patch("ig_kmx_guardd.service.validate_cgroup_fd", return_value=CgroupIdentity(1, 55, 2, 55)), \
             patch("ig_kmx_guardd.service.os.dup", return_value=77):
            return self.service.dispatch(1000, self.env("activate", self.binding, {"policy": self.policy}, "activate", "n-activate"), [6])

    def frozen(self):
        self.activate()
        key = self.binding.key()
        self.store.transition(key, State.FREEZE_DESIRED)
        self.store.transition(key, State.FROZEN_CONFIRMED)
        return key

    def terminating(self):
        self.activate()
        key = self.binding.key()
        self.store.transition(key, State.TERMINATING)
        return key

    def test_every_action_rejects_wrong_fd_count_before_reservation(self):
        bodies = {
            "activate": {"policy": self.policy}, "status": {}, "health": {},
            "evidence": {"event": {}}, "quarantine": {}, "freeze": {},
            "resume": {"incident_id": "incident", "remediation_generation": 1},
            "terminate_handoff": {}, "deactivate": {}, "reconcile": {},
        }
        for index, (action, body) in enumerate(bodies.items()):
            wrong = [] if action in {"activate", "reconcile"} else [90]
            env = self.env(action, self.binding, body, f"wrong-{index}", f"nonce-{index}")
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, "requires exactly"):
                self.service.dispatch(1000, env, wrong)
        capability = self.env("capabilities", None, {}, "cap", "nonce-cap")
        with self.assertRaisesRegex(ValueError, "zero fds"):
            self.service.dispatch(1000, capability, [91])
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM requests").fetchone()[0], 0)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)

    def test_activate_rejects_extra_fd_before_reservation(self):
        env = self.env("activate", self.binding, {"policy": self.policy}, "extra", "nonce-extra")
        with self.assertRaisesRegex(ValueError, "exactly 1"):
            self.service.dispatch(1000, env, [6, 7])
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM requests").fetchone()[0], 0)

    def test_resume_clear_failure_never_thaws_and_retry_succeeds(self):
        key = self.frozen()
        self.inventory.fail_clear = True
        with patch("ig_kmx_guardd.service.read_events", return_value={"frozen": 1}), \
             patch("ig_kmx_guardd.service.set_freeze") as freeze:
            with self.assertRaisesRegex(OSError, "clear fault"):
                self.service.dispatch(1000, self.env("resume", self.binding, {
                    "incident_id": "incident", "remediation_generation": 1,
                }, "resume-1", "nonce-resume-1"), [])
            freeze.assert_not_called()
        self.assertEqual(self.store.session(key)["state"], State.FROZEN_CONFIRMED)
        events = iter(({"frozen": 1}, {"frozen": 0}))
        with patch("ig_kmx_guardd.service.read_events", side_effect=lambda _fd: next(events)), \
             patch("ig_kmx_guardd.service.set_freeze") as freeze:
            result = self.service.dispatch(1000, self.env("resume", self.binding, {
                "incident_id": "incident", "remediation_generation": 1,
            }, "resume-2", "nonce-resume-2"), [])
        self.assertEqual(result["result"]["state"], State.RELEASED)
        freeze.assert_called_once_with(77, False)

    def test_resume_journal_failure_after_clear_is_idempotently_retryable(self):
        key = self.frozen()
        real_transition = self.store.transition
        failed = False

        def transition(session_key, target, error=None):
            nonlocal failed
            if target == State.RESUME_PREPARED and not failed:
                failed = True
                raise OSError("resume journal fault")
            return real_transition(session_key, target, error)

        with patch.object(self.store, "transition", side_effect=transition), \
             patch("ig_kmx_guardd.service.read_events", return_value={"frozen": 1}), \
             patch("ig_kmx_guardd.service.set_freeze") as freeze:
            with self.assertRaisesRegex(OSError, "resume journal fault"):
                self.service.dispatch(1000, self.env("resume", self.binding, {
                    "incident_id": "incident", "remediation_generation": 1,
                }, "resume-j1", "nonce-resume-j1"), [])
            freeze.assert_not_called()
        self.assertEqual(self.store.session(key)["state"], State.FROZEN_CONFIRMED)
        events = iter(({"frozen": 1}, {"frozen": 0}))
        with patch("ig_kmx_guardd.service.read_events", side_effect=lambda _fd: next(events)), \
             patch("ig_kmx_guardd.service.set_freeze"):
            result = self.service.dispatch(1000, self.env("resume", self.binding, {
                "incident_id": "incident", "remediation_generation": 1,
            }, "resume-j2", "nonce-resume-j2"), [])
        self.assertEqual(result["result"]["state"], State.RELEASED)
        self.assertEqual(self.inventory.clear_calls, 2)

    def test_deactivate_termination_failure_retains_ownership_for_retry(self):
        key = self.terminating()
        self.runtime.fail_terminate = True
        with patch("ig_kmx_guardd.service.read_events", return_value={"populated": 0}), \
             patch("ig_kmx_guardd.service.task_ids", return_value=[]), \
             patch("ig_kmx_guardd.service.close_fd") as close:
            with self.assertRaisesRegex(OSError, "terminate fault"):
                self.service.dispatch(1000, self.env("deactivate", self.binding, {}, "deact-1", "nonce-deact-1"), [])
            close.assert_not_called()
        self.assertEqual(self.store.session(key)["state"], State.EMPTY_CONFIRMED)
        self.assertIn(key, self.service.workers)
        self.assertIn(key, self.service.cgroup_fds)
        with patch("ig_kmx_guardd.service.close_fd") as close:
            result = self.service.dispatch(1000, self.env("deactivate", self.binding, {}, "deact-2", "nonce-deact-2"), [])
        self.assertEqual(result["result"]["state"], State.DEACTIVATED)
        close.assert_called_once_with(77)
        self.assertNotIn(key, self.service.workers)

    def test_deactivate_release_failure_retains_handles_for_retry(self):
        key = self.terminating()
        self.inventory.fail_release = True
        with patch("ig_kmx_guardd.service.read_events", return_value={"populated": 0}), \
             patch("ig_kmx_guardd.service.task_ids", return_value=[]), \
             patch("ig_kmx_guardd.service.close_fd") as close:
            with self.assertRaisesRegex(OSError, "release fault"):
                self.service.dispatch(1000, self.env("deactivate", self.binding, {}, "release-1", "nonce-release-1"), [])
            close.assert_not_called()
        self.assertEqual(self.store.session(key)["state"], State.EMPTY_CONFIRMED)
        self.assertIn(key, self.service.workers)
        with patch("ig_kmx_guardd.service.close_fd"):
            self.service.dispatch(1000, self.env("deactivate", self.binding, {}, "release-2", "nonce-release-2"), [])
        self.assertEqual(self.store.session(key)["state"], State.DEACTIVATED)
        self.assertEqual(self.inventory.release_calls, 2)

    def test_deactivate_terminal_journal_failure_retries_without_fd(self):
        key = self.terminating()
        real_transition = self.store.transition
        failed = False

        def transition(session_key, target, error=None):
            nonlocal failed
            if target == State.DEACTIVATED and not failed:
                failed = True
                raise OSError("terminal journal fault")
            return real_transition(session_key, target, error)

        with patch.object(self.store, "transition", side_effect=transition), \
             patch("ig_kmx_guardd.service.read_events", return_value={"populated": 0}), \
             patch("ig_kmx_guardd.service.task_ids", return_value=[]), \
             patch("ig_kmx_guardd.service.close_fd") as close:
            with self.assertRaisesRegex(OSError, "terminal journal fault"):
                self.service.dispatch(1000, self.env("deactivate", self.binding, {}, "journal-1", "nonce-journal-1"), [])
            close.assert_called_once_with(77)
        self.assertEqual(self.store.session(key)["state"], State.EMPTY_CONFIRMED)
        self.assertNotIn(key, self.service.cgroup_fds)
        self.assertIn(key, self.service.workers)
        with patch("ig_kmx_guardd.service.close_fd") as close:
            result = self.service.dispatch(1000, self.env("deactivate", self.binding, {}, "journal-2", "nonce-journal-2"), [])
            close.assert_not_called()
        self.assertEqual(result["result"]["state"], State.DEACTIVATED)
        self.assertNotIn(key, self.service.workers)


if __name__ == "__main__":
    unittest.main()
