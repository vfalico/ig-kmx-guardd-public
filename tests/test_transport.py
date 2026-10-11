import array
import os
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from ig_kmx_guardd.server import recv_packet


class FakeSocket:
    def __init__(self, data=b"{}", ancillary=None, flags=0):
        self.result = (data, ancillary or [], flags, None)
        self.receive_flags = None

    def recvmsg(self, frame_size, ancillary_size, flags=0):
        self.receive_flags = flags
        return self.result


def rights(*fds):
    payload = array.array("i", fds).tobytes()
    return [(socket.SOL_SOCKET, socket.SCM_RIGHTS, payload)]


class TransportTests(unittest.TestCase):
    def test_ctrunc_closes_all_installed_fds(self):
        readable, writable = os.pipe()
        conn = FakeSocket(ancillary=rights(readable, writable), flags=socket.MSG_CTRUNC)
        with self.assertRaisesRegex(ValueError, "truncated"):
            recv_packet(conn)
        for fd in (readable, writable):
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_frame_truncation_closes_received_fd(self):
        readable, writable = os.pipe()
        os.close(writable)
        conn = FakeSocket(ancillary=rights(readable), flags=socket.MSG_TRUNC)
        with self.assertRaisesRegex(ValueError, "truncated"):
            recv_packet(conn)
        with self.assertRaises(OSError):
            os.fstat(readable)

    def test_malformed_rights_closes_previously_parsed_fds(self):
        readable, writable = os.pipe()
        os.close(writable)
        ancillary = rights(readable) + [(socket.SOL_SOCKET, socket.SCM_RIGHTS, b"x")]
        with self.assertRaisesRegex(ValueError, "malformed"):
            recv_packet(FakeSocket(ancillary=ancillary))
        with self.assertRaises(OSError):
            os.fstat(readable)

    def test_success_transfers_descriptor_ownership_and_requests_cloexec(self):
        readable, writable = os.pipe()
        os.close(writable)
        conn = FakeSocket(data=b"request", ancillary=rights(readable))
        data, fds = recv_packet(conn)
        self.assertEqual(data, b"request")
        self.assertEqual(fds, [readable])
        self.assertEqual(conn.receive_flags, getattr(socket, "MSG_CMSG_CLOEXEC", 0))
        os.fstat(readable)
        os.close(readable)

    def test_too_many_descriptors_are_closed(self):
        fds = []
        for _ in range(3):
            readable, writable = os.pipe()
            os.close(writable)
            fds.append(readable)
        with patch("ig_kmx_guardd.server.MAX_FDS", 2):
            with self.assertRaisesRegex(ValueError, "too many"):
                recv_packet(FakeSocket(ancillary=rights(*fds)))
        for fd in fds:
            with self.assertRaises(OSError):
                os.fstat(fd)


if __name__ == "__main__":
    unittest.main()
