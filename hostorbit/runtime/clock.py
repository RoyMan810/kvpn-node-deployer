"""Host-only clocks and fixed, read-only time-daemon telemetry on Ubuntu 24.04."""

import csv
import ctypes
import errno
import math
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import time

from ..errors import Denied
from .protocol import decode


BOOT_ID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
NANOSECOND = 10**9


def clocks():
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if re.fullmatch(BOOT_ID, boot) is None:
        raise Denied("TIME_BOOT_ID_INVALID")
    return {"boot_id": boot, "wall_ns": time.time_ns(), "tick_ns": time.clock_gettime_ns(time.CLOCK_BOOTTIME),
            "mono_ns": time.monotonic_ns()}


class _Timespec(ctypes.Structure):
    _fields_ = [("seconds", ctypes.c_long), ("nanoseconds", ctypes.c_long)]


class _Itimerspec(ctypes.Structure):
    _fields_ = [("interval", _Timespec), ("value", _Timespec)]


class ClockWatch:
    """CANCEL_ON_SET also remembers a forward-and-back step between polls."""
    def __init__(self):
        self.fd = None
        try:
            self.libc = ctypes.CDLL(None, use_errno=True)
            self.libc.timerfd_create.argtypes = (ctypes.c_int, ctypes.c_int)
            self.libc.timerfd_create.restype = ctypes.c_int
            self.libc.timerfd_settime.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.POINTER(_Itimerspec), ctypes.c_void_p)
            self.libc.timerfd_settime.restype = ctypes.c_int
            fd = self.libc.timerfd_create(time.CLOCK_REALTIME, os.O_CLOEXEC | os.O_NONBLOCK)
            if fd < 0:
                raise OSError(ctypes.get_errno(), "timerfd unavailable")
            self.fd = fd
            self._arm()
        except (OSError, AttributeError):
            self.close()

    def _arm(self):
        value = _Itimerspec(_Timespec(0, 0), _Timespec(int(time.time()) + 366 * 86400, 0))
        if self.libc.timerfd_settime(self.fd, 1 | 2, ctypes.byref(value), None) < 0:
            raise OSError(ctypes.get_errno(), "timerfd unavailable")

    def changed(self):
        if self.fd is None:
            raise Denied("TIME_WATCH_UNAVAILABLE")
        try:
            os.read(self.fd, 8)
        except BlockingIOError:
            return False
        except OSError as error:
            if error.errno != errno.ECANCELED:
                raise Denied("TIME_WATCH_UNAVAILABLE") from None
        self._arm()
        return True

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __del__(self):
        self.close()


def number(value, *, low=-86400, high=86400):
    if isinstance(value, bool):
        raise Denied("TIME_SOURCE_INVALID")
    try:
        value = float(value)
    except (TypeError, ValueError, OverflowError):
        raise Denied("TIME_SOURCE_INVALID") from None
    if not math.isfinite(value) or not low <= value <= high:
        raise Denied("TIME_SOURCE_INVALID")
    return value


def chrony_sample(raw):
    try:
        rows = list(csv.reader(raw.splitlines(), strict=True))
        row, = rows
        if len(row) != 14 or re.fullmatch(r"[0-9A-F]{8}", row[0]) is None:
            raise ValueError
        if row[0] in ("00000000", "7F7F0101") or row[13] != "Normal" or not 1 <= int(row[2]) <= 15:
            raise Denied("TIME_SOURCE_UNSYNCHRONIZED")
        reference = number(row[3], low=1, high=2**53)
        values = [number(item) for item in row[4:13]]
        correction, last_offset, rms, frequency, residual, skew, delay, dispersion, interval = values
        if rms < 0 or skew < 0 or dispersion < 0 or interval < 0:
            raise ValueError
    except (ValueError, csv.Error, TypeError):
        raise Denied("TIME_SOURCE_INVALID") from None
    return {"source": "chrony", "last_sync_utc": reference, "offset_ms": correction * 1000,
            "max_error_ms": (abs(delay) / 2 + dispersion) * 1000,
            "rate_ppm": max(500.0, abs(frequency) + abs(residual) + skew),
            "measurement_id": row[0] + ":" + row[3]}


def timesyncd_sample(raw, frequency, synchronized):
    value = decode(raw, canonical_required=False)
    if value.keys() != {"type", "data"} or value["type"] != "(uuuuittayttttbtt)":
        raise Denied("TIME_SOURCE_INVALID")
    row = value["data"]
    if not isinstance(row, list) or len(row) != 15:
        raise Denied("TIME_SOURCE_INVALID")
    for position in (*range(7), *range(8, 12), 13, 14):
        if type(row[position]) is not int or abs(row[position]) > 2**63 - 1:
            raise Denied("TIME_SOURCE_INVALID")
    leap, version, mode, stratum, precision, root_delay, dispersion, refid, origin, received, transmitted, destination, spike, count, jitter = row
    if (not isinstance(refid, list) or len(refid) != 4 or any(type(v) is not int or not 0 <= v <= 255 for v in refid)
            or type(spike) is not bool or not -64 <= precision <= 0
            or min(root_delay, dispersion, origin, received, transmitted, destination, jitter) < 0):
        raise Denied("TIME_SOURCE_INVALID")
    if synchronized is not True or leap != 0 or version not in (3, 4) or mode != 4 or not 1 <= stratum <= 15 or spike or count < 1:
        raise Denied("TIME_SOURCE_UNSYNCHRONIZED")
    delay = ((destination - origin) - (transmitted - received)) / 1e6
    if delay < -0.001 or delay > 10 or transmitted < received:
        raise Denied("TIME_SOURCE_INVALID")
    offset = ((received - origin) + (transmitted - destination)) / 2e6
    error = (root_delay / 2 + dispersion + jitter) / 1e6 + abs(delay) / 2 + 2.0**precision
    return {"source": "timesyncd", "last_sync_utc": destination / 1e6, "offset_ms": number(offset) * 1000,
            "max_error_ms": number(error, low=0) * 1000,
            "rate_ppm": 500 + abs(number(frequency / 65536)),
            "measurement_id": str(destination) + ":" + str(count)}


class HostSources:
    """No host/command/env parameters are accepted from a Worker or Web request."""
    @staticmethod
    def _command(*args, timeout=5):
        try:
            result = subprocess.run(args, capture_output=True, timeout=timeout,
                                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent"})
        except (OSError, subprocess.TimeoutExpired):
            raise Denied("TIME_SOURCE_UNAVAILABLE") from None
        if result.returncode or len(result.stdout) > 8192:
            raise Denied("TIME_SOURCE_UNAVAILABLE")
        return result.stdout

    def _active(self, name):
        try:
            return self._command("/usr/bin/systemctl", "is-active", name, timeout=2).strip() == b"active"
        except Denied:
            return False

    def __call__(self):
        chrony, timesyncd = self._active("chrony.service"), self._active("systemd-timesyncd.service")
        if chrony and timesyncd:
            raise Denied("TIME_SOURCE_AMBIGUOUS")
        if chrony:
            path = Path("/run/chrony/chronyd.sock")
            info, parent = path.lstat(), path.parent.lstat()
            account = pwd.getpwnam("_chrony")
            if (not stat.S_ISSOCK(info.st_mode) or info.st_uid not in (0, account.pw_uid)
                    or not stat.S_ISDIR(parent.st_mode) or parent.st_uid not in (0, account.pw_uid)
                    or parent.st_mode & 0o022):
                raise Denied("TIME_SOURCE_INVALID")
            # chronyc creates its reply socket beside chronyd.sock. PID 1 runs
            # this fixed read-only query as the daemon UID; the supervisor keeps
            # an empty capability set and no access to Broker/Vault private data.
            user = pwd.getpwuid(info.st_uid)
            raw = self._command("/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
                "--property=User=" + user.pw_name, "--property=Group=" + str(user.pw_gid),
                "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=",
                "--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=PrivateTmp=yes",
                "--property=RestrictAddressFamilies=AF_UNIX", "--property=ReadWritePaths=/run/chrony",
                "--property=RuntimeMaxSec=3", "--property=UMask=0077", "/usr/bin/chronyc",
                "-n", "-c", "-h", str(path), "tracking")
            return chrony_sample(raw.decode("ascii"))
        if timesyncd:
            prefix = ("/usr/bin/busctl", "--system", "--json=short", "--auto-start=no", "get-property",
                      "org.freedesktop.timesync1", "/org/freedesktop/timesync1", "org.freedesktop.timesync1.Manager")
            raw = self._command(*prefix, "NTPMessage", timeout=2)
            frequency = decode(self._command(*prefix, "Frequency", timeout=2), canonical_required=False)
            if frequency.get("type") != "x" or type(frequency.get("data")) is not int:
                raise Denied("TIME_SOURCE_INVALID")
            synced = self._command("/usr/bin/timedatectl", "show", "--property=NTPSynchronized", "--value", timeout=2).strip() == b"yes"
            return timesyncd_sample(raw, frequency["data"], synced)
        raise Denied("TIME_SOURCE_UNAVAILABLE")
