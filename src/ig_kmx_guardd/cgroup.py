"""FD-based cgroup-v2 validation. Caller paths are never authorization inputs."""
from __future__ import annotations

import ctypes
import os
from dataclasses import asdict, dataclass

CGROUP2_SUPER_MAGIC = 0x63677270


@dataclass(frozen=True)
class CgroupIdentity:
    dev: int
    ino: int
    mount_id: int
    cgroup_id: int

    def dict(self) -> dict[str, int]:
        return asdict(self)


def _mount_id(fd: int) -> int:
    """Return the kernel mount ID carried by this FD.

    An FD received through SCM_RIGHTS can refer to a mount outside the receiver's
    mount namespace. Its mnt_id therefore need not occur in the receiver's
    /proc/self/mountinfo; it remains useful as an opaque identity component.
    """
    with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as stream:
        for line in stream:
            if line.startswith("mnt_id:"):
                return int(line.split()[1])
    raise ValueError("missing mount id")


def _filesystem_magic(fd: int) -> int:
    """Call Linux fstatfs(2) on an FD without trusting namespace paths."""
    # struct statfs begins with signed long f_type on every Linux architecture
    # supported by this package. A generously sized aligned buffer avoids
    # reproducing architecture-specific trailing fields.
    buffer = (ctypes.c_long * 32)()
    libc = ctypes.CDLL(None, use_errno=True)
    fstatfs = libc.fstatfs
    fstatfs.argtypes = (ctypes.c_int, ctypes.c_void_p)
    fstatfs.restype = ctypes.c_int
    if fstatfs(fd, ctypes.byref(buffer)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return int(buffer[0])


def validate_cgroup_fd(fd: int) -> CgroupIdentity:
    """Duplicate then identify a directory FD; reject non-cgroup2/zero identity."""
    if fd < 0:
        raise ValueError("missing cgroup fd")
    owned = os.dup(fd)
    try:
        metadata = os.fstat(owned)
        if not os.path.isdir(f"/proc/self/fd/{owned}"):
            raise ValueError("cgroup fd is not directory")
        if _filesystem_magic(owned) != CGROUP2_SUPER_MAGIC:
            raise ValueError("fd is not on cgroup2")
        mount_id = _mount_id(owned)
        if metadata.st_ino <= 0:
            raise ValueError("zero cgroup identity")
        # procfs exposes the kernel dentry state for an open-but-removed
        # cgroup as a " (deleted)" suffix. cgroupfs does not reliably drop
        # st_nlink, so reject using this kernel-owned FD link, not a path
        # supplied by the caller.
        if os.readlink(f"/proc/self/fd/{owned}").endswith(" (deleted)"):
            raise ValueError("cgroup fd refers to an unlinked cgroup")
        return CgroupIdentity(metadata.st_dev, metadata.st_ino, mount_id, metadata.st_ino)
    finally:
        os.close(owned)


def read_events(fd: int) -> dict[str, int]:
    base = f"/proc/self/fd/{fd}"
    result = {}
    with open(base + "/cgroup.events", encoding="ascii") as stream:
        for line in stream:
            key, value = line.split()
            result[key] = int(value)
    return result


def task_ids(fd: int) -> list[int]:
    with open(f"/proc/self/fd/{fd}/cgroup.procs", encoding="ascii") as stream:
        return [int(value) for value in stream.read().split()]


def set_freeze(fd: int, frozen: bool) -> None:
    flags = os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    child = os.open("cgroup.freeze", flags, dir_fd=fd)
    try:
        os.write(child, b"1\n" if frozen else b"0\n")
    finally:
        os.close(child)
