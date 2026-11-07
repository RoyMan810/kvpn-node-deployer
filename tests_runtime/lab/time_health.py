#!/usr/bin/env python3
"""Real time daemons and kernel clock-step detection in a disposable VM only."""

import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
from threading import Event, Thread
import time

from hostorbit.errors import Denied
from hostorbit.runtime.authority import Authority, verify_host_time
from hostorbit.runtime.clock import HostSources
from hostorbit.runtime.ipc import Client, activated_socket, serve
from hostorbit.runtime.policy import Policy


WORKER, STRANGER = 23102, 23105
UNIT = "hostorbit-time-lab"
PLAN, APPROVAL = "01JCYQZ4T9V8MNVYEH3D2M7Q1A", "01JCYQZ4T9V8MNVYEH3D2M7Q1D"


def run(*args, check=True, timeout=30, **kwargs):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, timeout=timeout, **kwargs)
    if check and result.returncode:
        raise RuntimeError("Lab command failed: " + Path(str(args[0])).name)
    return result


def wait_for(check, message, seconds=50):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            value = check()
            if value:
                return value
        except (Denied, OSError):
            pass
        time.sleep(0.2)
    raise RuntimeError(message)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        stream.write(value)
    path.chmod(0o644)


def timestamp():
    now = time.time_ns()
    return struct.pack("!II", now // 10**9 + 2208988800, (now % 10**9) * 2**32 // 10**9)


class NTPFixture:
    """An explicit local protocol fixture, not an independent UTC reference."""
    def __init__(self):
        self.stop = Event()
        self.respond, self.requests = True, 0
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 123))
        self.socket.settimeout(0.2)
        self.thread = Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        while not self.stop.is_set():
            try:
                request, address = self.socket.recvfrom(512)
            except socket.timeout:
                continue
            if len(request) < 48 or request[0] & 7 != 3:
                continue
            self.requests += 1
            if not self.respond:
                continue
            received = timestamp()
            header = struct.pack("!BBbbII4s", 0x24, 2, 4, -20, 65, 65, b"LAB1")
            response = header + timestamp() + request[40:48] + received + timestamp()
            self.socket.sendto(response, address)

    def close(self):
        self.stop.set()
        self.thread.join(2)
        self.socket.close()


def service(root):
    authority = Authority(root / "gate", Policy([]))
    authority.recover()
    try:
        serve(activated_socket(root / "gate.sock"), authority.dispatch,
              {(0, 0): "updater", (WORKER, WORKER): "worker"}, poll=authority.poll_time)
    finally:
        authority.close()


def worker_client(root):
    try:
        proof = Client(root / "gate.sock", server_uids={0}).call("time.health", {})
        report = verify_host_time(proof, (root / "gate.pub").read_bytes())
        assert report["source"] in ("timesyncd", "chrony")
        assert report["state"] == "FRESH"
        print("VERIFIED_HOST_TIME")
    except Denied as error:
        print(error.code)


def configure_source(root, source):
    run("/usr/bin/systemctl", "stop", "chrony.service", "systemd-timesyncd.service", check=False)
    if source == "timesyncd":
        path = Path("/run/systemd/timesyncd.conf.d/99-hostorbit-time-lab.conf")
        write(path, "[Time]\nNTP=\nNTP=127.0.0.1\nFallbackNTP=\nPollIntervalMinSec=16s\nPollIntervalMaxSec=16s\n")
        unit = "systemd-timesyncd.service"
    else:
        config = root / "chrony.conf"
        write(config, "server 127.0.0.1 port 123 iburst minpoll 0 maxpoll 0\nport 0\ncmdport 0\n"
              "bindcmdaddress /run/chrony/chronyd.sock\npidfile /run/chrony/hostorbit-time-lab.pid\n"
              "driftfile /run/chrony/hostorbit-time-lab.drift\n")
        write(Path("/run/systemd/system/chrony.service.d/99-hostorbit-time-lab.conf"),
              "[Service]\nType=simple\nPIDFile=\nExecStart=\n"
              f"ExecStart=/usr/sbin/chronyd -d -x -U -u _chrony -f {config}\n")
        unit = "chrony.service"
    run("/usr/bin/systemctl", "daemon-reload")
    return unit


def start_authority(root):
    authority = Authority.initialize(root / "gate", Policy([]))
    (root / "gate.pub").write_bytes(bytes(authority.key.verify_key))
    (root / "gate.pub").chmod(0o644)
    authority.close()
    code = root / "code"
    shutil.copytree(Path(__file__).resolve().parents[2] / "hostorbit", code / "hostorbit",
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copyfile(__file__, code / "lab.py")
    for path in code.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    code.chmod(0o755)
    write(Path(f"/run/systemd/system/{UNIT}.socket"),
          f"[Unit]\nDescription=Disposable TimeHealth test socket\n[Socket]\nListenStream={root}/gate.sock\nSocketMode=0666\n")
    write(Path(f"/run/systemd/system/{UNIT}.service"),
          f"[Unit]\nRequires={UNIT}.socket\nAfter={UNIT}.socket\n[Service]\n"
          f"ExecStart={Path(sys.executable).resolve()} {code}/lab.py --serve --root {root}\n"
          f"Environment=PYTHONPATH={code}\nUser=root\nGroup=root\nUMask=0077\n"
          "NoNewPrivileges=yes\nCapabilityBoundingSet=\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n"
          f"ReadWritePaths={root}/gate\nRestrictAddressFamilies=AF_UNIX\nLimitCORE=0\n")
    run("/usr/bin/systemctl", "daemon-reload")
    run("/usr/bin/systemctl", "start", UNIT + ".socket", UNIT + ".service")
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-vm", action="store_true")
    parser.add_argument("--source", choices=("chrony", "timesyncd"))
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--client", action="store_true")
    parser.add_argument("--root", type=Path)
    args = parser.parse_args()
    if args.serve:
        if os.geteuid() != 0:
            raise SystemExit("Root-only lab service")
        service(args.root)
        return
    if args.client:
        worker_client(args.root)
        return
    if (not args.isolated_vm or not args.source or os.geteuid() != 0
            or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Requires an explicitly disposable GitHub-hosted VM")
    for path in (Path(f"/run/systemd/system/{UNIT}.service"), Path(f"/run/systemd/system/{UNIT}.socket"),
                 Path("/var/lib/hostorbit")):
        if path.exists():
            raise SystemExit("Lab namespace already exists")
    with tempfile.TemporaryDirectory(prefix="hostorbit-time-lab-", dir="/run") as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        source_unit = configure_source(root, args.source)
        ntp = NTPFixture()
        try:
            run("/usr/bin/systemctl", "start", source_unit)
            collector = HostSources()
            sample = wait_for(collector, "Actual time daemon did not accept the NTP fixture")
            assert sample["source"] == args.source
            assert abs(sample["offset_ms"]) + sample["max_error_ms"] <= 2000
            print("Actual " + args.source + " telemetry accepted through the fixed local collector.", flush=True)
            # Real upstream packet loss: requests continue, accepted measurement
            # identity must not be fabricated by repeated status queries.
            ntp.respond = False
            time.sleep(0.5)
            stopped_measurement = collector()["measurement_id"]
            count = ntp.requests
            wait_for(lambda: ntp.requests > count, "Time daemon did not retry the dropped NTP response", seconds=40)
            assert collector()["measurement_id"] == stopped_measurement
            ntp.respond = True
            wait_for(lambda: collector()["measurement_id"] != stopped_measurement, "Time daemon did not recover after packet loss")
            print("Dropped upstream NTP replies did not become a new synchronization sample; real daemon recovered.", flush=True)
            code = start_authority(root)
            client = Client(root / "gate.sock", server_uids={0})
            key = (root / "gate.pub").read_bytes()
            def report():
                return verify_host_time(client.call("time.health", {}), key)
            wait_for(lambda: report()["state"] == "FRESH", "Sandboxed host authority could not verify time")
            environment = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(code), "PYTHONDONTWRITEBYTECODE": "1"}
            response = run(sys.executable, code / "lab.py", "--client", "--root", root,
                           user=WORKER, group=WORKER, extra_groups=[], env=environment)
            assert response.stdout.strip() == b"VERIFIED_HOST_TIME", response.stdout
            denied = run(sys.executable, code / "lab.py", "--client", "--root", root,
                         user=STRANGER, group=WORKER, extra_groups=[], env=environment)
            assert denied.stdout.strip() == b"RPC_PEER_DENIED", denied.stdout
            print("Distinct Worker UID verified a signed host report; a same-group stranger was denied.", flush=True)
            anchor = client.call("time.anchor", {"plan_id": PLAN, "revision": 1})
            ticket = client.call("update.quiesce", {"kind": "application", "plan_id": PLAN, "revision": 1,
                "plan_digest": "a" * 64, "approval_id": APPROVAL, "time_anchor": anchor})
            client.call("update.maintenance", ticket)
            # Only this disposable VM's wall clock is touched. Restore it before
            # any network/tool interaction, even if the first set/read fails.
            wall, boot = time.time_ns(), time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            try:
                time.clock_settime_ns(time.CLOCK_REALTIME, wall + 3 * 10**9)
            finally:
                elapsed = time.clock_gettime_ns(time.CLOCK_BOOTTIME) - boot
                time.clock_settime_ns(time.CLOCK_REALTIME, wall + elapsed)
            changed = report()
            assert changed["state"] == "UNTRUSTED" and changed["clock_step_detected"], changed
            assert changed["gate_state"] == "RECOVERY_HOLD", changed
            try:
                client.call("update.resuming", ticket)
                raise AssertionError("Old update ticket resumed after a clock step")
            except Denied:
                pass
            run("/usr/bin/systemctl", "restart", UNIT + ".service")
            assert report()["gate_state"] == "RECOVERY_HOLD"
            print("Real forward-and-back clock_settime cancelled the timerfd; maintenance entered durable RECOVERY_HOLD across restart.", flush=True)
        except Exception:
            for unit in (source_unit, UNIT + ".service"):
                logs = run("/usr/bin/journalctl", "--unit", unit, "--no-pager", "--lines", "35", check=False)
                print(logs.stdout.decode(errors="replace"), file=sys.stderr)
            raise
        finally:
            run("/usr/bin/systemctl", "stop", UNIT + ".service", UNIT + ".socket", source_unit, check=False)
            ntp.close()


if __name__ == "__main__":
    main()
