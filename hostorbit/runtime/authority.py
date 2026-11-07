"""Durable host-local admission authority, separate from the application database."""

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from ..errors import Denied
from . import policy as policy_module
from .protocol import SHA256, ULID, canonical, checksum, fields, integer, text
from .storage import Journal, new_private_file, protected_bytes
from .timehealth import ANCHOR_FIELDS, TimeHealth


_SCHEMA = """
CREATE TABLE gate(id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL, epoch INTEGER NOT NULL,
    policy_digest TEXT NOT NULL, instance_id TEXT NOT NULL, host_binding TEXT NOT NULL,
    update_ticket TEXT, activated INTEGER NOT NULL CHECK(activated IN (0,1)));
CREATE TABLE attempts(job_id TEXT PRIMARY KEY, claims TEXT NOT NULL, nonce TEXT NOT NULL UNIQUE,
    target TEXT NOT NULL, mutating INTEGER NOT NULL, state TEXT NOT NULL,
    result_digest TEXT, result_code TEXT);
CREATE UNIQUE INDEX one_mutator ON attempts((1)) WHERE mutating=1 AND state IN ('ISSUED','DISPATCHING','UNKNOWN_OUTCOME');
CREATE TABLE incidents(job_id TEXT PRIMARY KEY REFERENCES attempts(job_id), closure TEXT NOT NULL);
"""
_BINDING_FIELDS = ("job_id", "plan_id", "revision", "plan_digest", "approval_id", "actor_id", "target", "capability", "scope_digest")


def host_binding():
    return hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()


def verify_permit(permit, verify_key, *, now):
    fields(permit, ("claims", "signature"))
    anchored = isinstance(permit["claims"], dict) and permit["claims"].get("mutating") is True
    claims = fields(permit["claims"], (*_BINDING_FIELDS, "v", "authority_id", "epoch", "nonce", "issued_at", "expires_at", "lock_closure_digest", "mutating", *(("time_anchor",) if anchored else ())))
    if type(claims["v"]) is not int or claims["v"] != 1 or type(claims["mutating"]) is not bool:
        raise Denied("PERMIT_PROTOCOL_INVALID")
    try:
        VerifyKey(verify_key).verify(canonical(claims), base64.b64decode(permit["signature"], validate=True))
    except (BadSignatureError, ValueError, TypeError):
        raise Denied("PERMIT_SIGNATURE_INVALID") from None
    if (type(claims["issued_at"]) is not int or type(claims["expires_at"]) is not int
            or not claims["issued_at"] <= now < claims["expires_at"] <= claims["issued_at"] + 60):
        raise Denied("PERMIT_EXPIRED")
    return claims


def verify_host_time(envelope, verify_key, *, kind="time.health"):
    fields(envelope, ("claims", "signature"))
    claims = envelope["claims"]
    if not isinstance(claims, dict) or claims.get("type") != kind or type(claims.get("v")) is not int or claims["v"] != 1:
        raise Denied("TIME_PROOF_INVALID")
    try:
        VerifyKey(verify_key).verify(canonical(claims), base64.b64decode(envelope["signature"], validate=True))
    except (BadSignatureError, ValueError, TypeError):
        raise Denied("TIME_PROOF_INVALID") from None
    return claims


class Authority:
    def __init__(self, directory, policy, *, clock=time.time, time_health=None):
        self.directory, self.policy, self.clock = Path(directory), policy, clock
        self.journal = Journal(self.directory / "gate.sqlite3")
        self.key = SigningKey(protected_bytes(self.directory / "signing.key", owner=os.geteuid(), maximum=32, exact_mode=0o600))
        self.time_health = time_health if time_health is not None else TimeHealth(self.directory / "time-health")

    @classmethod
    def initialize(cls, directory, policy, *, clock=time.time, time_health=None):
        from ..database import identifier
        directory = Path(directory)
        journal = Journal.initialize(directory / "gate.sqlite3", _SCHEMA)
        key = SigningKey.generate()
        new_private_file(directory / "signing.key", bytes(key))
        new_private_file(directory / "verify.key", bytes(key.verify_key))
        with journal.write() as db:
            db.execute("INSERT INTO gate VALUES(1,'NORMAL',0,?,?,?,NULL,1)", (policy.digest, identifier(), host_binding()))
        time_health = time_health if time_health is not None else TimeHealth.initialize(directory / "time-health")
        return cls(directory, policy, clock=clock, time_health=time_health)

    def _gate(self, db):
        row = db.execute("SELECT * FROM gate WHERE id=1").fetchone()
        if (row is None or row["policy_digest"] != self.policy.digest or row["host_binding"] != host_binding()
                or row["state"] not in ("NORMAL", "QUIESCING", "MAINTENANCE", "RESUMING", "RECOVERY_HOLD")):
            raise Denied("AUTHORITY_BINDING_INVALID")
        return row

    def recover(self):
        """Called under the lifetime process lock, before accepting any requests."""
        with self.journal.write() as db:
            gate = self._gate(db)
            active = db.execute("SELECT job_id,target,mutating FROM attempts WHERE state IN ('ISSUED','DISPATCHING')").fetchall()
            for row in active:
                db.execute("UPDATE attempts SET state='UNKNOWN_OUTCOME',result_code='AUTHORITY_RESTART' WHERE job_id=?", (row["job_id"],))
                if row["mutating"]:
                    db.execute("INSERT OR IGNORE INTO incidents VALUES(?,?)", (row["job_id"], canonical(self.policy.closure(row["target"])).decode()))
            hold = gate["state"] != "NORMAL" or any(row["mutating"] for row in active)
            db.execute("UPDATE gate SET epoch=epoch+1,state=? WHERE id=1", ("RECOVERY_HOLD" if hold else "NORMAL",))
        try:
            self.time_health.recover()
        except (OSError, RuntimeError, Denied, ValueError, TypeError, KeyError, sqlite3.Error):
            pass  # The unavailable time journal cannot authorize mutations.

    def _sign(self, claims):
        return {"claims": claims, "signature": base64.b64encode(self.key.sign(canonical(claims)).signature).decode()}

    def poll_time(self):
        report = self.time_health.poll()
        with self.journal.write() as db:
            gate = self._gate(db)
            if report["state"] == "UNTRUSTED" and gate["state"] in ("QUIESCING", "MAINTENANCE", "RESUMING"):
                db.execute("UPDATE gate SET state='RECOVERY_HOLD',epoch=epoch+1 WHERE id=1")
        return report

    def time_report(self):
        report = self.poll_time()
        with self.journal.connect() as db:
            gate = self._gate(db)
            return self._sign({**report, "type": "time.health", "authority_id": gate["instance_id"],
                               "gate_epoch": gate["epoch"], "gate_state": gate["state"]})

    def time_anchor(self, request):
        fields(request, ("plan_id", "revision"))
        with self.journal.connect() as db:
            gate = self._gate(db)
            if gate["state"] != "NORMAL" or not gate["activated"]:
                raise Denied("GATE_CLOSED")
            instance = gate["instance_id"]
        anchor = self.time_health.anchor(request["plan_id"], request["revision"])
        return self._sign({**anchor, "type": "time.anchor", "authority_id": instance})

    def _time_anchor(self, envelope, plan_id, revision, instance_id, *, active=False):
        claims = verify_host_time(envelope, bytes(self.key.verify_key), kind="time.anchor")
        fields(claims, (*ANCHOR_FIELDS, "type", "authority_id"))
        if claims["authority_id"] != instance_id:
            raise Denied("TIME_PROOF_INVALID")
        return self.time_health.validate({key: claims[key] for key in ANCHOR_FIELDS}, plan_id, revision, active=active)

    def admit(self, request):
        name = request.get("capability") if isinstance(request, dict) else None
        capability = policy_module.CAPABILITIES.get(name) if isinstance(name, str) else None
        anchored = capability is not None and capability.mutating
        fields(request, (*_BINDING_FIELDS, *(("time_anchor",) if anchored else ())))
        for key in ("job_id", "plan_id", "actor_id", "target"):
            text(request[key], ULID)
        text(request["approval_id"], ULID)
        integer(request["revision"], 1, 2**31 - 1)
        text(request["plan_digest"], SHA256)
        text(request["scope_digest"], SHA256)
        target = self.policy.target(request["target"], request["capability"], request["scope_digest"])
        mutating = policy_module.CAPABILITIES[request["capability"]].mutating
        with self.journal.write() as db:
            gate = self._gate(db)
            if mutating and (not gate["activated"] or gate["state"] != "NORMAL"):
                raise Denied("GATE_CLOSED")
            if mutating and db.execute("SELECT 1 FROM incidents").fetchone():
                raise Denied("OPEN_INCIDENT")
            if mutating and db.execute("SELECT 1 FROM attempts WHERE mutating=1 AND state IN ('ISSUED','DISPATCHING','UNKNOWN_OUTCOME')").fetchone():
                raise Denied("REMOTE_PERMIT_HELD")
            if db.execute("SELECT 1 FROM attempts WHERE job_id=?", (request["job_id"],)).fetchone():
                raise Denied("OPERATION_ALREADY_ADMITTED")
            if mutating:
                self._time_anchor(request["time_anchor"], request["plan_id"], request["revision"], gate["instance_id"])
            now = int(self.clock())
            claims = {**request, "v": 1, "authority_id": gate["instance_id"], "epoch": gate["epoch"], "nonce": secrets.token_hex(32),
                      "issued_at": now, "expires_at": now + 60, "lock_closure_digest": checksum(self.policy.closure(target.id)), "mutating": mutating}
            db.execute("INSERT INTO attempts(job_id,claims,nonce,target,mutating,state) VALUES(?,?,?,?,?,'ISSUED')",
                       (claims["job_id"], canonical(claims).decode(), claims["nonce"], target.id, int(mutating)))
            return {"claims": claims, "signature": base64.b64encode(self.key.sign(canonical(claims)).signature).decode()}

    def consume(self, permit):
        claims = verify_permit(permit, bytes(self.key.verify_key), now=int(self.clock()))
        with self.journal.write() as db:
            gate = self._gate(db)
            if claims["epoch"] != gate["epoch"] or (claims["mutating"] and gate["state"] != "NORMAL"):
                raise Denied("STALE_GATE_EPOCH")
            if claims["mutating"]:
                self._time_anchor(claims["time_anchor"], claims["plan_id"], claims["revision"], gate["instance_id"])
            self.policy.target(claims["target"], claims["capability"], claims["scope_digest"])
            changed = db.execute("UPDATE attempts SET state='DISPATCHING' WHERE job_id=? AND nonce=? AND claims=? AND state='ISSUED'",
                                 (claims["job_id"], claims["nonce"], canonical(claims).decode()))
            if changed.rowcount != 1:
                raise Denied("PERMIT_ALREADY_CONSUMED")
        return {"job_id": claims["job_id"], "nonce": claims["nonce"], "state": "DISPATCHING"}

    def complete(self, request):
        fields(request, ("job_id", "nonce", "outcome", "result_digest", "result_code"))
        text(request["job_id"], ULID)
        text(request["nonce"], SHA256)
        text(request["result_digest"], SHA256)
        text(request["result_code"], r"[A-Z][A-Z0-9_]{1,63}")
        if request["outcome"] not in ("SUCCEEDED", "FAILED", "UNKNOWN_OUTCOME"):
            raise Denied("RPC_INVALID_REQUEST")
        with self.journal.write() as db:
            gate = self._gate(db)
            row = db.execute("SELECT * FROM attempts WHERE job_id=? AND nonce=? AND state='DISPATCHING'", (request["job_id"], request["nonce"])).fetchone()
            if row is None:
                raise Denied("ATTEMPT_NOT_DISPATCHING")
            db.execute("UPDATE attempts SET state=?,result_digest=?,result_code=? WHERE job_id=?",
                       (request["outcome"], request["result_digest"], request["result_code"], request["job_id"]))
            if row["mutating"] and request["outcome"] == "UNKNOWN_OUTCOME":
                db.execute("INSERT INTO incidents VALUES(?,?)", (request["job_id"], canonical(self.policy.closure(row["target"])).decode()))
                if gate["state"] == "QUIESCING":
                    db.execute("UPDATE gate SET state='RECOVERY_HOLD',epoch=epoch+1 WHERE id=1")
        return self.status(request["job_id"])

    def status(self, job_id):
        text(job_id, ULID)
        with self.journal.connect() as db:
            self._gate(db)
            row = db.execute("SELECT job_id,nonce,state,result_digest,result_code FROM attempts WHERE job_id=?", (job_id,)).fetchone()
            if row is None:
                raise Denied("ATTEMPT_NOT_FOUND", 404)
            return dict(row)

    def cancel(self, request):
        fields(request, ("job_id", "nonce"))
        text(request["job_id"], ULID)
        text(request["nonce"], SHA256)
        with self.journal.write() as db:
            self._gate(db)
            changed = db.execute("UPDATE attempts SET state='CANCELLED_SAFE',result_code='CANCELLED_BEFORE_DISPATCH' WHERE job_id=? AND nonce=? AND state='ISSUED'",
                                 (request["job_id"], request["nonce"]))
            if changed.rowcount != 1:
                raise Denied("ATTEMPT_NOT_CANCELLABLE")
        return self.status(request["job_id"])

    def update(self, operation, request):
        failed_time = False
        with self.journal.write() as db:
            gate = self._gate(db)
            if operation == "update.quiesce":
                fields(request, ("kind", "plan_id", "revision", "plan_digest", "approval_id", "time_anchor"))
                if request["kind"] not in ("application", "self"):
                    raise Denied("RPC_INVALID_REQUEST")
                text(request["plan_digest"], SHA256)
                text(request["approval_id"], ULID)
                text(request["plan_id"], ULID)
                integer(request["revision"], 1, 2**31 - 1)
                if not gate["activated"] or gate["state"] != "NORMAL":
                    raise Denied("GATE_CLOSED")
                if db.execute("SELECT 1 FROM incidents").fetchone():
                    raise Denied("OPEN_INCIDENT")
                self._time_anchor(request["time_anchor"], request["plan_id"], request["revision"], gate["instance_id"])
                ticket = {**request, "epoch": gate["epoch"] + 1, "nonce": secrets.token_hex(32)}
                db.execute("UPDATE gate SET state='QUIESCING',epoch=epoch+1,update_ticket=? WHERE id=1", (canonical(ticket).decode(),))
                # No SSH send is legal before consumption. Revoking unconsumed permits is provably pre-effect.
                db.execute("UPDATE attempts SET state='CANCELLED_SAFE',result_code='QUIESCING_BEFORE_DISPATCH' WHERE state='ISSUED'")
                return ticket
            fields(request, ("kind", "plan_id", "revision", "plan_digest", "approval_id", "time_anchor", "epoch", "nonce"))
            transitions = {"update.maintenance": ("QUIESCING", "MAINTENANCE"), "update.resuming": ("MAINTENANCE", "RESUMING"), "update.normal": ("RESUMING", "NORMAL")}
            if operation not in transitions:
                raise Denied("RPC_OPERATION_DENIED")
            before, after = transitions[operation]
            if gate["state"] != before or gate["update_ticket"] != canonical(request).decode():
                raise Denied("INVALID_UPDATE_TICKET")
            if db.execute("SELECT 1 FROM incidents").fetchone():
                raise Denied("OPEN_INCIDENT")
            if db.execute("SELECT 1 FROM attempts WHERE mutating=1 AND state IN ('ISSUED','DISPATCHING','UNKNOWN_OUTCOME')").fetchone():
                raise Denied("REMOTE_PERMIT_HELD")
            try:
                self._time_anchor(request["time_anchor"], request["plan_id"], request["revision"], gate["instance_id"],
                                  active=operation in ("update.resuming", "update.normal"))
            except Denied:
                db.execute("UPDATE gate SET state='RECOVERY_HOLD',epoch=epoch+1 WHERE id=1")
                failed_time = True
            else:
                db.execute("UPDATE gate SET state=?,update_ticket=? WHERE id=1", (after, None if after == "NORMAL" else gate["update_ticket"]))
                result = {"state": after, "epoch": gate["epoch"]}
        if failed_time:
            raise Denied("TIME_UNTRUSTED")
        return result

    def dispatch(self, role, peer, operation, payload):
        if role in ("worker", "broker", "updater") and operation == "time.health":
            fields(payload, ())
            return self.time_report()
        if role in ("worker", "updater") and operation == "time.anchor":
            return self.time_anchor(payload)
        if role == "worker" and operation == "permit.admit":
            return self.admit(payload)
        if role == "broker" and operation == "permit.consume":
            return self.consume(payload)
        if role == "broker" and operation == "attempt.complete":
            return self.complete(payload)
        if role in ("worker", "broker") and operation == "permit.cancel":
            return self.cancel(payload)
        if role in ("worker", "broker", "updater") and operation == "attempt.status":
            fields(payload, ("job_id",))
            return self.status(payload["job_id"])
        if role == "updater" and isinstance(operation, str) and operation.startswith("update."):
            return self.update(operation, payload)
        raise Denied("RPC_OPERATION_DENIED")

    def close(self):
        self.time_health.close()
