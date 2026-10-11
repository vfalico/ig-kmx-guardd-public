"""GuardService integration for the independent fail-safe guardian."""
from __future__ import annotations

import os
import threading
import time

from .cgroup import read_events, task_ids
from .guardian import GuardianHandle, launch
from .model import Stage, State
from .service import GuardService


class FailSafeGuardService(GuardService):
    """Arm one independent cgroup guardian for every validated attachment."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.guardians: dict[str, GuardianHandle] = {}
        self._consumer_watchers: dict[str, threading.Thread] = {}

    @staticmethod
    def _event_consumer_sentinel(worker) -> tuple[int, threading.Thread]:
        """Return a pipe whose read side reaches EOF if the drain thread exits.

        The watcher owns the only write end and performs no work other than
        joining the concrete EventStream thread. Process death also closes the
        write end, so the external guardian receives a kernel-observable EOF in
        both thread-failure and daemon-failure cases.
        """
        if worker.events is None or not worker.events.thread.is_alive():
            raise RuntimeError("event consumer is not alive")
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)

        def watch() -> None:
            try:
                worker.events.thread.join()
            finally:
                os.close(write_fd)

        watcher = threading.Thread(
            target=watch, name=f"ig-event-liveness-{worker.process.pid}", daemon=True
        )
        watcher.start()
        return read_fd, watcher

    def _activate(self, binding, body, fds):
        result = super()._activate(binding, body, fds)
        key = binding.key()
        worker = self.workers.get(key)
        cgroup_fd = self.cgroup_fds.get(key)
        if worker is None or cgroup_fd is None:
            raise RuntimeError("validated activation lost worker or cgroup ownership")
        event_consumer_fd = -1
        try:
            identity = self.guardians[key].cgroup_identity if key in self.guardians else None
            if identity is None:
                from .cgroup import validate_cgroup_fd
                identity = validate_cgroup_fd(cgroup_fd)
            event_consumer_fd, watcher = self._event_consumer_sentinel(worker)
            guardian = launch(
                cgroup_fd, worker.pidfd, event_consumer_fd,
                identity, self.config.freeze_timeout_s,
            )
            self.guardians[key] = guardian
            self._consumer_watchers[key] = watcher
            guardian.confirm_armed(self.config.freeze_timeout_s)
            result["fail_safe_guardian"] = {
                "armed": True, "pid": guardian.process.pid,
                "watches": [
                    "guardd_pidfd", "ig_worker_pidfd",
                    "event_consumer_liveness", "cgroup_fd",
                ],
                "action": "freeze_exact_cgroup",
            }
            final = self._receipt(binding, Stage.FAIL_SAFE_GUARDIAN_ARMED, {
                "held": True,
                "cgroup": identity.dict(),
                "guardian": result["fail_safe_guardian"],
            })
            result["receipts"].append(final)
            result["release_eligible_receipt"] = final
            guardian.confirm_armed(self.config.freeze_timeout_s)
            return result
        except Exception as exc:
            # Parent activation has not yet returned to Orka; freeze before
            # propagating failure so no release-eligible response can escape.
            try:
                super()._freeze(binding, {}, [])
            except Exception:  # AUDITED: DELIBERATE — original arm failure remains primary; state records uncertainty
                pass
            worker = self.workers.pop(key, None)
            cleanup_errors = []

            def cleanup(label, operation):
                try:
                    operation()
                except Exception as cleanup_exc:
                    cleanup_errors.append(f"{label}: {cleanup_exc}")

            guardian = self.guardians.pop(key, None)
            if guardian is not None:
                cleanup("guardian", guardian.disarm)
            if worker is not None:
                cleanup("worker", lambda: self.runtime.terminate(worker))
                if hasattr(self.inventory, "release"):
                    cleanup("inventory", lambda: self.inventory.release(worker.process.pid))
            self.policies.pop(key, None)
            owned_cgroup = self.cgroup_fds.pop(key, None)
            if owned_cgroup is not None:
                cleanup("cgroup fd", lambda: os.close(owned_cgroup))
            self._consumer_watchers.pop(key, None)
            suffix = f"; cleanup errors: {'; '.join(cleanup_errors)}" if cleanup_errors else ""
            raise RuntimeError(f"fail-safe guardian arm failed: {exc}{suffix}") from exc
        finally:
            if event_consumer_fd >= 0:
                os.close(event_consumer_fd)

    def _guardian_status(self, key: str) -> dict:
        guardian = self.guardians.get(key)
        if guardian is None:
            return {"armed": False, "alive": False, "cause": None,
                    "frozen": False, "error": "guardian not owned by this daemon"}
        status = guardian.refresh()
        status["armed"] = True
        return status

    def _status(self, binding, body, fds):
        result = super()._status(binding, body, fds)
        result["fail_safe_guardian"] = self._guardian_status(binding.key())
        return result

    def _health(self, binding, body, fds):
        result = super()._health(binding, body, fds)
        guardian = self._guardian_status(binding.key())
        result["fail_safe_guardian"] = guardian
        if guardian["frozen"] or guardian["error"] or not guardian["alive"]:
            result["release_safe"] = False
        return result

    def _resume(self, binding, body, fds):
        guardian = self._guardian_status(binding.key())
        if guardian["frozen"] or not guardian["alive"]:
            raise ValueError("fail-safe guardian triggered; session retirement required")
        return super()._resume(binding, body, fds)

    def _deactivate(self, binding, body, fds):
        key = binding.key()
        state = State(self.store.session(key)["state"])
        if state not in {State.TERMINATING, State.EMPTY_CONFIRMED}:
            raise ValueError("deactivate requires termination handoff or empty-confirmed retry")
        fd = self.cgroup_fds.get(key)
        if state == State.TERMINATING:
            if fd is None:
                raise ValueError("no registered cgroup fd")
            start = time.monotonic()
            while True:
                if read_events(fd).get("populated") != 0 or task_ids(fd):
                    raise ValueError("cgroup not empty")
                if time.monotonic() - start >= self.config.stable_empty_s:
                    break
                time.sleep(0.02)
            self.store.transition(key, State.EMPTY_CONFIRMED)
        # Only stable-empty confirmation authorizes disarming the independent
        # crash guardian. There are no workload tasks left to expose while the
        # IG worker is subsequently stopped and detached.
        guardian = self.guardians.pop(key, None)
        if guardian is not None:
            guardian.disarm()
        self._consumer_watchers.pop(key, None)
        return super()._deactivate(binding, body, fds)

    def close_guardians_for_orderly_shutdown(self) -> None:
        """Intentionally do not disarm active guardians on daemon shutdown.

        Closing their control sockets triggers a fail-safe freeze. The caller
        only clears local references so object destruction cannot obscure that
        ownership was deliberately transferred to the guardians.
        """
        self.guardians.clear()
        self._consumer_watchers.clear()
