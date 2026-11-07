import copy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hostorbit.database import identifier
from hostorbit.errors import Denied
from hostorbit.runtime.authority import Authority, verify_permit
from hostorbit.runtime.ipc import Peer
from hostorbit.runtime.policy import CAPABILITIES, Capability
from fixtures import ACTOR, BROKER_UID, TARGET, WORKER_UID, binding, policy, trusted_time


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.now = 1_800_000_000
        self.policy = policy()
        self.authority = Authority.initialize(self.directory / "gate", self.policy, clock=lambda: self.now)
        self.addCleanup(self.authority.close)

    def request(self):
        value = binding(self.policy, identifier())
        if CAPABILITIES[value["capability"]].mutating:
            value["time_anchor"] = self.authority.time_anchor({"plan_id": value["plan_id"], "revision": value["revision"]})
        return value

    def update_request(self, kind):
        plan_id = identifier()
        return {"kind": kind, "plan_id": plan_id, "revision": 1, "plan_digest": "b" * 64, "approval_id": ACTOR,
                "time_anchor": self.authority.time_anchor({"plan_id": plan_id, "revision": 1})}

    def test_signature_scope_epoch_and_replay_are_independent_guards(self):
        request = self.request()
        permit = self.authority.admit(request)
        changed = copy.deepcopy(permit)
        changed["claims"]["target"] = ACTOR
        with self.assertRaisesRegex(Denied, "SIGNATURE_INVALID"):
            verify_permit(changed, bytes(self.authority.key.verify_key), now=self.now)
        self.authority.consume(permit)
        with self.assertRaisesRegex(Denied, "ALREADY_CONSUMED"):
            self.authority.consume(permit)
        with self.assertRaisesRegex(Denied, "ALREADY_ADMITTED"):
            self.authority.admit(request)

    def test_worker_cannot_request_maintenance_or_report_own_success(self):
        peer = Peer(12, WORKER_UID, WORKER_UID)
        for operation, payload in (("update.quiesce", {"kind": "application"}), ("attempt.complete", {}), ("permit.consume", {})):
            with self.subTest(operation=operation), self.assertRaisesRegex(Denied, "OPERATION_DENIED"):
                self.authority.dispatch("worker", peer, operation, payload)
        request = self.request()
        request["capability"] = "docker.restart"
        with self.assertRaisesRegex(Denied, "CAPABILITY_DISABLED"):
            self.authority.admit(request)

    def test_recovery_invalidates_old_permit_and_policy_or_host_drift_fail_closed(self):
        permit = self.authority.admit(self.request())
        self.authority.recover()
        with self.assertRaisesRegex(Denied, "STALE_GATE_EPOCH"):
            self.authority.consume(permit)
        self.assertEqual(self.authority.status(permit["claims"]["job_id"])["state"], "UNKNOWN_OUTCOME")
        self.policy.targets[TARGET].value["policy_revision"] += 1
        with self.assertRaisesRegex(Denied, "BINDING_INVALID"):
            self.authority.recover()

    def mutating(self):
        self.enterContext(patch.dict(CAPABILITIES, {"lab.mutation": Capability(True, "vps:restart")}))
        self.policy = policy(capabilities=["lab.mutation"])
        self.authority = Authority.initialize(self.directory / "mutating", self.policy, clock=lambda: self.now,
            time_health=trusted_time(self.directory / "trusted-time", lambda: self.now))
        self.addCleanup(self.authority.close)

    def test_expired_mutating_permit_keeps_reservation_until_proven_pre_dispatch_cancel(self):
        self.mutating()
        permit = self.authority.admit(self.request())
        self.now += 60
        with self.assertRaisesRegex(Denied, "PERMIT_EXPIRED"):
            self.authority.consume(permit)
        with self.assertRaisesRegex(Denied, "REMOTE_PERMIT_HELD"):
            self.authority.admit(self.request())
        self.authority.cancel({"job_id": permit["claims"]["job_id"], "nonce": permit["claims"]["nonce"]})
        self.authority.admit(self.request())

    def test_quiesce_revokes_unconsumed_permits_and_never_overlaps_dispatch(self):
        self.mutating()
        permit = self.authority.admit(self.request())
        ticket = self.authority.update("update.quiesce", self.update_request("application"))
        self.assertEqual(self.authority.status(permit["claims"]["job_id"])["state"], "CANCELLED_SAFE")
        with self.assertRaises(Denied):
            self.authority.consume(permit)
        self.authority.update("update.maintenance", ticket)
        with self.assertRaisesRegex(Denied, "GATE_CLOSED"):
            self.authority.admit(self.request())
        self.authority.update("update.resuming", ticket)
        self.authority.update("update.normal", ticket)
        self.authority.admit(self.request())

    def test_pending_or_unknown_effect_blocks_update_and_is_never_rewritten_successful(self):
        self.mutating()
        permit = self.authority.admit(self.request())
        self.authority.consume(permit)
        ticket = self.authority.update("update.quiesce", self.update_request("self"))
        with self.assertRaisesRegex(Denied, "REMOTE_PERMIT_HELD"):
            self.authority.update("update.maintenance", ticket)
        result = {"job_id": permit["claims"]["job_id"], "nonce": permit["claims"]["nonce"], "outcome": "UNKNOWN_OUTCOME", "result_digest": "c" * 64, "result_code": "CONNECTION_LOST"}
        self.authority.complete(result)
        with self.assertRaisesRegex(Denied, "NOT_DISPATCHING"):
            self.authority.complete({**result, "outcome": "SUCCEEDED"})
        self.authority.recover()
        with self.authority.journal.connect() as db:
            self.assertEqual(db.execute("SELECT state FROM gate").fetchone()[0], "RECOVERY_HOLD")
        with self.assertRaises(Denied):
            self.authority.update("update.quiesce", self.update_request("application"))

    def test_race_between_dispatch_and_both_updates_has_one_effect_authority(self):
        self.mutating()
        permit = self.authority.admit(self.request())
        def contender(kind):
            try:
                if kind == "dispatch":
                    self.authority.consume(permit)
                    return "dispatch"
                ticket = self.authority.update("update.quiesce", self.update_request(kind))
                self.authority.update("update.maintenance", ticket)
                return "maintenance"
            except Denied:
                return "denied"
        with ThreadPoolExecutor(max_workers=3) as pool:
            values = list(pool.map(contender, ("dispatch", "application", "self")))
        self.assertEqual(sum(v in ("dispatch", "maintenance") for v in values), 1, values)
