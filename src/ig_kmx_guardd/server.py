"""Bounded Unix SOCK_SEQPACKET transport with peer credentials and owned FD passing."""
from __future__ import annotations

import array
from concurrent.futures import ThreadPoolExecutor
import os
import socket
import stat
import struct
import threading

from . import cbor
from .model import Envelope, MAX_FRAME
from .proto import PROTOCOL_VERSION, ResponseFrame, pack_packet, unpack_packet

MAX_FDS = 2
_FD_ITEMSIZE = array.array("i").itemsize


def peer_uid(conn: socket.socket) -> int:
    _pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    return uid


def _close_all(fds: list[int]) -> None:
    for fd in fds:
        try:
            os.close(fd)
        except OSError:  # AUDITED: DELIBERATE — reject path owns possibly duplicated/invalid descriptors
            pass


def recv_packet(conn: socket.socket) -> tuple[bytes, list[int]]:
    """Receive one frame and transfer descriptor ownership only after validation."""
    receive_flags = getattr(socket, "MSG_CMSG_CLOEXEC", 0)
    data, ancillary, flags, _ = conn.recvmsg(
        MAX_FRAME + 1, socket.CMSG_SPACE(MAX_FDS * _FD_ITEMSIZE), receive_flags,
    )
    fds: list[int] = []
    try:
        for level, kind, payload in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                continue
            if len(payload) % _FD_ITEMSIZE:
                raise ValueError("malformed SCM_RIGHTS payload")
            received = array.array("i")
            received.frombytes(payload)
            fds.extend(received)
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise ValueError("truncated packet")
        if len(data) > MAX_FRAME:
            raise ValueError("frame too large")
        if len(fds) > MAX_FDS:
            raise ValueError("too many fds")
        return data, fds
    except Exception:
        _close_all(fds)
        raise


class Server:
    """A bounded local server whose failures are isolated per connection.

    At most ``max_workers`` accepted clients may consume receive buffers or
    execute service calls. Each accepted connection gets a receive/send
    deadline, so an idle or slow peer cannot occupy a worker indefinitely.
    """

    def __init__(
        self,
        path: str,
        service,
        mode: int = 0o660,
        *,
        receive_timeout_s: float = 2.0,
        max_workers: int = 8,
        listen_backlog: int = 32,
    ):
        if not 0.05 <= receive_timeout_s <= 60.0:
            raise ValueError("receive_timeout_s outside [0.05, 60]")
        if not 1 <= max_workers <= 64:
            raise ValueError("max_workers outside [1, 64]")
        if not 1 <= listen_backlog <= 256:
            raise ValueError("listen_backlog outside [1, 256]")
        self.path = path
        self.service = service
        self.mode = mode
        self.receive_timeout_s = receive_timeout_s
        self.max_workers = max_workers
        self.listen_backlog = listen_backlog
        self.sock: socket.socket | None = None
        self._slots = threading.BoundedSemaphore(max_workers)
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="guardd-client")
        self._stopping = threading.Event()

    def bind(self) -> None:
        parent = os.path.dirname(self.path)
        os.makedirs(parent, mode=0o750, exist_ok=True)
        try:
            stat_result = os.lstat(self.path)
            if not stat.S_ISSOCK(stat_result.st_mode):
                raise RuntimeError("refusing to replace non-socket")
            os.unlink(self.path)
        except FileNotFoundError:  # AUDITED: DELIBERATE — first bind normally has no stale socket
            pass
        old_umask = os.umask(0o117)
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            self.sock.bind(self.path)
            os.chmod(self.path, self.mode)
            self.sock.listen(self.listen_backlog)
        finally:
            os.umask(old_umask)

    @staticmethod
    def _send_best_effort(conn: socket.socket, encoded: bytes) -> bool:
        try:
            conn.sendall(encoded)
            return True
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            # AUDITED: DELIBERATE — a disconnected local peer cannot be allowed
            # to terminate the daemon; no response can be delivered to it.
            return False

    def handle(self, conn: socket.socket) -> None:
        fds: list[int] = []
        try:
            conn.settimeout(self.receive_timeout_s)
            try:
                raw, fds = recv_packet(conn)
                env = Envelope.from_frame(unpack_packet(raw))
                result = self.service.dispatch(peer_uid(conn), env, fds)
                encoded = pack_packet(ResponseFrame(
                    PROTOCOL_VERSION, env.request_id, True, cbor.dumps(result), "", ""
                ).encode())
            except Exception as exc:
                request_id = env.request_id if "env" in locals() else ""
                encoded = pack_packet(ResponseFrame(
                    PROTOCOL_VERSION, request_id, False, cbor.dumps({}),
                    type(exc).__name__, str(exc)[:512],
                ).encode())
            finally:
                _close_all(fds)
            self._send_best_effort(conn, encoded)
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            # AUDITED: DELIBERATE — final per-connection containment boundary.
            return

    def _run_connection(self, conn: socket.socket) -> None:
        try:
            with conn:
                self.handle(conn)
        finally:
            self._slots.release()

    def serve_forever(self) -> None:
        self.bind()
        assert self.sock is not None
        try:
            while not self._stopping.is_set():
                try:
                    conn, _ = self.sock.accept()
                except OSError:
                    if self._stopping.is_set():
                        break
                    raise
                if not self._slots.acquire(blocking=False):
                    conn.settimeout(self.receive_timeout_s)
                    self._send_best_effort(conn, pack_packet(ResponseFrame(
                        PROTOCOL_VERSION, "", False, cbor.dumps({}), "Busy",
                        "bounded connection capacity reached",
                    ).encode()))
                    conn.close()
                    continue
                try:
                    self._executor.submit(self._run_connection, conn)
                except Exception:
                    conn.close()
                    self._slots.release()
                    raise
        finally:
            self._executor.shutdown(wait=True, cancel_futures=True)

    def close(self) -> None:
        self._stopping.set()
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:  # AUDITED: DELIBERATE — shutdown may race an already-closed listener
                pass
            self.sock.close()


def main(argv=None) -> int:
    """Installed command delegates to the validated packaged launcher."""
    from .launcher import main as launcher_main
    return launcher_main(argv)
