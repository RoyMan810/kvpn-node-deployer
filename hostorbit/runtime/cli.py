"""Host-installed service entry points driven by root-owned configuration."""

import argparse
from contextlib import contextmanager
import os
import json
from pathlib import Path
import signal
import sys
from threading import Event

from ..auth import AuthService
from ..config import Settings
from ..database import DataAccess, Store
from ..errors import Denied
from ..queue import JobQueue
from ..worker import Worker
from .authority import Authority, verify_host_time
from .broker import Broker
from .ipc import Client, activated_socket, serve
from .policy import Policy
from .protocol import fields, integer, text, decode
from .storage import new_private_file, process_lock, protected_bytes
from .vault import Vault
from .timehealth import TimeHealth


@contextmanager
def worker_shutdown():
    """PID 1 must handle TERM explicitly; release its lock only after the job."""
    stop, previous = Event(), {}
    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, lambda *_: stop.set())
        yield stop
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def configuration(path):
    value = decode(protected_bytes(path, owner=0, maximum=16384), canonical_required=False)
    fields(value, ("v", "database", "app_uid", "app_gid", "worker_uid", "worker_gid", "broker_uid", "broker_gid",
                   "broker_rpc_gid", "gate_rpc_gid", "public_origin", "trusted_proxies", "api_port", "targets",
                   "supervisor_directory", "broker_directory", "vault_directory", "vault_credential", "public_verify_key",
                   "gate_socket", "broker_socket", *(["api_bind"] if "api_bind" in value else [])))
    if type(value["v"]) is not int or value["v"] != 1:
        raise Denied("RUNTIME_CONFIG_INVALID")
    for key in ("app_uid", "app_gid", "worker_uid", "worker_gid", "broker_uid", "broker_gid", "broker_rpc_gid", "gate_rpc_gid"):
        integer(value[key], 1, 2**31 - 1)
    if len({value[k] for k in ("app_uid", "worker_uid", "broker_uid")}) != 3 or len({value[k] for k in ("app_gid", "broker_rpc_gid", "gate_rpc_gid")}) != 3:
        raise Denied("RUNTIME_IDENTITIES_OVERLAP")
    for key in ("database", "targets", "supervisor_directory", "broker_directory", "vault_directory", "vault_credential", "public_verify_key", "gate_socket", "broker_socket"):
        if not isinstance(value[key], str) or not Path(value[key]).is_absolute() or ".." in Path(value[key]).parts:
            raise Denied("RUNTIME_PATH_INVALID")
    integer(value["api_port"], 1024, 65535)
    if value.get("api_bind", "127.0.0.1") not in ("127.0.0.1", "0.0.0.0"):
        raise Denied("API_BIND_INVALID")
    Settings(Path(value["database"]), value["public_origin"], tuple(value["trusted_proxies"]), value["app_uid"], value["app_gid"])
    return value


def run(config, command, *, once=False, listener=None, import_args=None):
    expected = {"supervisor": 0, "initialize-supervisor": 0, "api": config["app_uid"], "worker": config["worker_uid"],
                "broker": config["broker_uid"], "initialize-broker": config["broker_uid"], "import-key": config["broker_uid"],
                "register-observations": 0, "initialize-time-health": 0, "time-health": 0}[command]
    if os.geteuid() != expected:
        raise Denied("LOCAL_SERVICE_IDENTITY_INVALID")
    access = DataAccess(config["app_uid"], config["app_gid"])
    if command == "time-health":
        envelope = Client(config["gate_socket"], server_uids={0}).call("time.health", {})
        report = verify_host_time(envelope, protected_bytes(config["public_verify_key"], owner=0, maximum=32))
        print(json.dumps(report))
        return
    if command == "api":
        from ..api import create_app
        import uvicorn
        with Store(config["database"], access=access).connect():
            pass
        settings = Settings(Path(config["database"]), config["public_origin"], tuple(config["trusted_proxies"]), access.owner_uid, access.shared_gid)
        uvicorn.run(create_app(settings), host=config.get("api_bind", "127.0.0.1"), port=config["api_port"], proxy_headers=False, access_log=False)
        return
    policy = Policy.load(config["targets"], owner=0)
    if command == "initialize-time-health":
        with Authority(config["supervisor_directory"], policy).journal.connect():
            pass
        health = TimeHealth.initialize(Path(config["supervisor_directory"]) / "time-health")
        health.close()
        return
    if command == "initialize-supervisor":
        authority = Authority.initialize(config["supervisor_directory"], policy)
        new_private_file(config["public_verify_key"], bytes(authority.key.verify_key))
        Path(config["public_verify_key"]).chmod(0o644)
        return
    if command == "supervisor":
        authority = Authority(config["supervisor_directory"], policy)
        identities = {(config["worker_uid"], config["worker_gid"]): "worker", (config["broker_uid"], config["broker_gid"]): "broker", (0, 0): "updater"}
        with process_lock(Path(config["supervisor_directory"]) / "authority.lock"):
            try:
                authority.recover()
                serve(listener or activated_socket(config["gate_socket"]), authority.dispatch, identities, poll=authority.poll_time)
            finally:
                authority.close()
        return
    if command == "register-observations":
        queue = JobQueue(Store(config["database"], access=access))
        for target in policy.targets.values():
            queue.register_resource(target.id, target.scope_digest, target.revision)
        return
    if command == "worker":
        worker = Worker(JobQueue(Store(config["database"], access=access)), Client(config["gate_socket"], server_uids={0}),
                        Client(config["broker_socket"], server_uids={0, config["broker_uid"]}),
                        secret_refs={t.id: t.value["secret_ref"] for t in policy.targets.values()})
        with worker_shutdown() as stop:
            return worker.run(once=once, stop=stop)
    managed_credential = "CREDENTIALS_DIRECTORY" in os.environ
    credential = Path(os.environ["CREDENTIALS_DIRECTORY"]) / "broker-dek" if managed_credential else Path(config["vault_credential"])
    if command == "initialize-broker":
        Vault.initialize(config["vault_directory"], credential, systemd_credential=managed_credential)
        Broker.initialize(config["broker_directory"], policy)
        return
    vault = Vault(config["vault_directory"], credential, systemd_credential=managed_credential)
    if command == "import-key":
        key = protected_bytes(import_args.key_file, owner=config["broker_uid"], maximum=8192, private=True)
        reference = vault.import_ssh(import_args.secret_id, import_args.version, key, owner_id=import_args.owner_id,
                                     worker_uid=config["worker_uid"], target=import_args.target)
        print(reference)
        return
    gate = Client(config["gate_socket"], server_uids={0})
    verify_key = protected_bytes(config["public_verify_key"], owner=0, maximum=32)
    broker = Broker(config["broker_directory"], policy, vault, gate, verify_key, worker_uid=config["worker_uid"])
    with process_lock(Path(config["broker_directory"]) / "broker.lock"):
        broker.recover()
        serve(listener or activated_socket(config["broker_socket"]), broker.dispatch, {(config["worker_uid"], config["worker_gid"]): "worker"})


def main(argv=None):
    parser = argparse.ArgumentParser(prog="hostorbit-runtime")
    parser.add_argument("--config", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("initialize-supervisor", "initialize-broker", "initialize-time-health", "time-health",
                 "register-observations", "supervisor", "broker", "api"):
        commands.add_parser(name)
    worker = commands.add_parser("worker")
    worker.add_argument("--once", action="store_true")
    key = commands.add_parser("import-key")
    key.add_argument("--key-file", type=Path, required=True)
    key.add_argument("--secret-id", required=True)
    key.add_argument("--owner-id", required=True)
    key.add_argument("--target", required=True)
    key.add_argument("--version", type=int, default=1)
    args = parser.parse_args(argv)
    try:
        run(configuration(args.config), args.command, once=getattr(args, "once", False), import_args=args)
    except (Denied, OSError, RuntimeError, ValueError) as error:
        print(error.code if isinstance(error, Denied) else "RUNTIME_UNAVAILABLE", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
