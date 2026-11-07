"""One bounded request per AF_UNIX connection; identity always comes from SO_PEERCRED."""

from dataclasses import dataclass
import os
import socket
import stat
import struct
import time

from ..errors import Denied
from .protocol import MAX_FRAME, canonical, decode, fields


_CREDENTIALS = struct.Struct("=iII")
_LENGTH = struct.Struct("!I")


@dataclass(frozen=True)
class Peer:
    pid: int
    uid: int
    gid: int


def peer(connection):
    return Peer(*_CREDENTIALS.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _CREDENTIALS.size)))


def exact(connection, size):
    parts = bytearray()
    while len(parts) < size:
        chunk = connection.recv(size - len(parts))
        if not chunk:
            raise Denied("RPC_INCOMPLETE_FRAME")
        parts.extend(chunk)
    return bytes(parts)


def receive(connection, *, eof=False):
    size, = _LENGTH.unpack(exact(connection, 4))
    if not 0 < size <= MAX_FRAME:
        raise Denied("RPC_FRAME_TOO_LARGE")
    value = decode(exact(connection, size))
    if eof and connection.recv(1):
        raise Denied("RPC_TRAILING_DATA")
    return value


def send(connection, value):
    body = canonical(value)
    if not 0 < len(body) <= MAX_FRAME:
        raise Denied("RPC_FRAME_TOO_LARGE")
    connection.sendall(_LENGTH.pack(len(body)) + body)


class Client:
    def __init__(self, path, *, server_uids, timeout=20):
        self.path, self.server_uids, self.timeout = str(path), frozenset(server_uids), timeout

    def call(self, operation, payload):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout)
                connection.connect(self.path)
                if peer(connection).uid not in self.server_uids:
                    raise Denied("RPC_SERVER_IDENTITY")
                send(connection, {"v": 1, "operation": operation, "payload": payload})
                connection.shutdown(socket.SHUT_WR)
                response = receive(connection)
        except OSError:
            raise Denied("RPC_UNAVAILABLE", 503) from None
        if not isinstance(response, dict) or response.get("v") != 1 or type(response.get("ok")) is not bool:
            raise Denied("RPC_INVALID_RESPONSE", 503)
        if not response["ok"]:
            fields(response, ("v", "ok", "code"))
            from .protocol import text
            raise Denied(text(response["code"], r"[A-Z][A-Z0-9_]{1,63}"))
        fields(response, ("v", "ok", "result"))
        return response["result"]


def handle(connection, handler, identities):
    connection.settimeout(3)
    try:
        identity = peer(connection)
        role = identities.get((identity.uid, identity.gid))
        if role is None:
            # Drain at most one bounded frame so closing the stream cannot discard the denial reply.
            try:
                receive(connection, eof=True)
            except (Denied, OSError):
                pass
            raise Denied("RPC_PEER_DENIED")
        request = fields(receive(connection, eof=True), ("v", "operation", "payload"))
        if type(request["v"]) is not int or request["v"] != 1:
            raise Denied("RPC_VERSION")
        response = {"v": 1, "ok": True, "result": handler(role, identity, request["operation"], request["payload"])}
    except Denied as error:
        response = {"v": 1, "ok": False, "code": error.code}
    except Exception:
        # No exception messages, requests, subprocess output or credentials cross this boundary.
        response = {"v": 1, "ok": False, "code": "RPC_STORAGE_OR_SERVICE_UNAVAILABLE"}
    try:
        send(connection, response)
    except (OSError, Denied):
        pass


def serve(listener, handler, identities, *, poll=None):
    next_poll = 0
    if poll is not None:
        listener.settimeout(30)
    while True:
        if poll is not None and time.monotonic() >= next_poll:
            poll()
            next_poll = time.monotonic() + 30
        try:
            connection, _ = listener.accept()
        except TimeoutError:
            continue
        with connection:
            handle(connection, handler, identities)


def activated_socket(path):
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        raise Denied("SOCKET_ACTIVATION_REQUIRED")
    listener = socket.socket(fileno=3)
    if (listener.family != socket.AF_UNIX or listener.type != socket.SOCK_STREAM
            or listener.getsockname() != str(path) or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
            or not stat.S_ISSOCK(os.fstat(3).st_mode)):
        raise Denied("SOCKET_ACTIVATION_INVALID")
    listener.set_inheritable(False)
    return listener
