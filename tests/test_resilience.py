import os
import socket
import select
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ig_kmx_guardd.model import Binding, State
from ig_kmx_guardd.proto import ResponseFrame, unpack_packet
from protocol_helpers import BUILDER
from ig_kmx_guardd.server import Server
from ig_kmx_guardd.store import Store

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


class EchoService:
    def dispatch(self, uid, env, fds):
        return {"ok": True, "result": {"action": env.action, "uid": uid}}


def valid_frame(request_id="r1"):
    return BUILDER.packet("capabilities", request_id, None, {}, nonce=(request_id.encode() * 32)[:32])


class ServerResilienceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "guardd.sock")
        self.server = Server(
            self.path, EchoService(), receive_timeout_s=0.2,
            max_workers=2, listen_backlog=4,
        )
        self.errors = []

        def run():
            try:
                self.server.serve_forever()
            except Exception as exc:  # test captures any escaped daemon exception
                self.errors.append(exc)

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                probe.connect(self.path)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.01)
            finally:
                probe.close()
        else:
            self.fail("server did not accept connections before readiness deadline")

    def tearDown(self):
        self.server.close()
        self.thread.join(3)
        self.tmp.cleanup()

    def request(self, frame):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        client.settimeout(2)
        try:
            client.connect(self.path)
            client.sendall(frame)
            return ResponseFrame.decode(unpack_packet(client.recv(65536)))
        finally:
            client.close()

    def test_malformed_disconnect_does_not_kill_accept_loop(self):
        bad = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        bad.connect(self.path)
        bad.sendall(b"\x00\x00\x00\x02{")
        bad.close()
        time.sleep(0.05)
        response = self.request(valid_frame("after-malformed"))
        self.assertTrue(response.ok)
        self.assertTrue(self.thread.is_alive())
        self.assertEqual(self.errors, [])

    def test_idle_client_cannot_starve_second_request(self):
        idle = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        idle.connect(self.path)
        started = time.monotonic()
        response = self.request(valid_frame("parallel"))
        elapsed = time.monotonic() - started
        self.assertTrue(response.ok)
        self.assertLess(elapsed, 1.0)
        idle.close()
        time.sleep(0.25)
        again = self.request(valid_frame("after-idle"))
        self.assertTrue(again.ok)
        self.assertTrue(self.thread.is_alive())
        self.assertEqual(self.errors, [])

    def test_worker_bound_rejects_excess_without_unbounded_threads(self):
        clients = []
        try:
            for _ in range(3):
                client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                client.settimeout(1)
                client.connect(self.path)
                clients.append(client)

            # Accept scheduling does not promise that connection order equals
            # worker-slot order. Read every bounded response and assert the
            # security property: concurrent demand beyond max_workers is
            # explicitly rejected rather than spawning an unbounded worker.
            pending = set(clients)
            responses = []
            deadline = time.monotonic() + 1.0
            while pending and time.monotonic() < deadline:
                readable, _, _ = select.select(list(pending), [], [], deadline - time.monotonic())
                for client in readable:
                    responses.append(ResponseFrame.decode(unpack_packet(client.recv(65536))))
                    pending.remove(client)
            self.assertEqual(pending, set())
            self.assertIn("Busy", [response.error_code for response in responses])
            self.assertTrue(all(not response.ok for response in responses))
        finally:
            for client in clients:
                client.close()


class StoreOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "state.db"), max_evidence=2)
        self.a = Binding("session-a", "attempt", 1, DIGEST_A, DIGEST_B, "node")
        self.b = Binding("session-b", "attempt", 1, DIGEST_A, DIGEST_B, "node")
        self.identity = {"dev": 1, "ino": 10, "mount_id": 2, "cgroup_id": 10}

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_session_rebinding_requires_exact_cgroup_identity(self):
        self.store.create(self.a, self.identity)
        changed = dict(self.identity, ino=11, cgroup_id=11)
        with self.assertRaisesRegex(ValueError, "different cgroup identity"):
            self.store.create(self.a, changed)

    def test_nonterminal_cgroup_identity_is_exclusive(self):
        self.store.create(self.a, self.identity)
        with self.assertRaisesRegex(ValueError, "already owned"):
            self.store.create(self.b, self.identity)

    def test_terminal_identity_can_be_reused(self):
        self.store.create(self.a, self.identity)
        for state in (State.ACTIVATING, State.ACTIVE_VALIDATED, State.TERMINATING, State.EMPTY_CONFIRMED, State.DEACTIVATED):
            self.store.transition(self.a.key(), state)
        self.assertEqual(self.store.create(self.b, self.identity), State.HELD)

    def test_evidence_limit_is_per_session_with_durable_gap_counters(self):
        for sequence in range(4):
            self.store.add_evidence(self.a.key(), {"sequence": sequence})
        self.store.add_evidence(self.b.key(), {"sequence": 0})
        a_status = self.store.evidence_status(self.a.key())
        b_status = self.store.evidence_status(self.b.key())
        self.assertEqual(a_status["retained"], 2)
        self.assertEqual(a_status["dropped_count"], 2)
        self.assertEqual((a_status["first_dropped_seq"], a_status["last_dropped_seq"]), (1, 2))
        self.assertTrue(a_status["degraded"])
        self.assertEqual(b_status["retained"], 1)
        self.assertEqual(b_status["dropped_count"], 0)
        self.assertFalse(b_status["degraded"])


if __name__ == "__main__":
    unittest.main()
