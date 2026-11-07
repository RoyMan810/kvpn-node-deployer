import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey

from hostorbit.database import identifier
from hostorbit.errors import Denied
from hostorbit.runtime.authority import Authority, verify_host_time
from hostorbit.runtime.clock import chrony_sample, timesyncd_sample
from hostorbit.runtime.ipc import Peer
from hostorbit.runtime.policy import CAPABILITIES, Capability
from hostorbit.runtime.timehealth import TimeHealth
from fixtures import ACTOR, WORKER_UID, TestWatch, binding, policy


NS = 10**9


class TimeRig:
    def __init__(self):
        self.wall, self.tick, self.mono = 1_800_000_000 * NS, 10000 * NS, 10000 * NS
        self.boot = "12345678-1234-1234-1234-123456789abc"
        self.watch, self.failure, self.sequence = TestWatch(), None, 0
        self.sync()

    def clock(self):
        return {"wall_ns": self.wall, "tick_ns": self.tick, "mono_ns": self.mono, "boot_id": self.boot}

    def source(self):
        if self.failure:
            raise Denied(self.failure)
        return self.sample.copy()

    def sync(self):
        self.sequence += 1
        self.sample = {"source": "chrony", "last_sync_utc": self.wall / NS, "offset_ms": 1,
                       "max_error_ms": 10, "rate_ppm": 500, "measurement_id": "packet:" + str(self.sequence)}
        self.failure = None

    def advance(self, seconds):
        elapsed = round(seconds * NS)
        self.wall += elapsed
        self.tick += elapsed
        self.mono += elapsed

    def step(self, seconds):
        self.wall += round(seconds * NS)
        self.watch.event = True

    def health(self, directory):
        return TimeHealth.initialize(directory, source=self.source, clock=self.clock, watch=self.watch)


class TimeHealthTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.rig = TimeRig()
        self.health = self.rig.health(self.root / "time")
        self.addCleanup(self.health.close)

    def test_fresh_sample_has_host_fields_and_bounded_offline_holdover(self):
        report = self.health.poll()
        self.assertEqual(report["state"], "FRESH")
        self.assertEqual(report["source"], "chrony")
        self.assertEqual(report["boot_id"], self.rig.boot)
        self.rig.failure = "TIME_SOURCE_UNAVAILABLE"
        self.rig.advance(301)
        holdover = self.health.poll()
        self.assertEqual(holdover["state"], "HOLDOVER")
        self.assertGreater(holdover["max_error_ms"], report["max_error_ms"])
        self.rig.advance(3298)
        self.assertEqual(self.health.poll()["state"], "HOLDOVER")
        self.rig.advance(2)
        self.assertEqual(self.health.poll()["state"], "UNTRUSTED")

    def test_successful_queries_of_the_same_packet_never_reset_freshness(self):
        self.health.poll()
        self.rig.advance(1000)
        first = self.health.poll()
        self.assertEqual(first["state"], "HOLDOVER")
        self.assertGreater(first["sample_age_s"], 999)
        self.rig.advance(2601)
        self.assertEqual(self.health.poll()["state"], "UNTRUSTED")

    def test_holdover_stops_when_projected_uncertainty_exceeds_two_seconds(self):
        self.rig.sample["rate_ppm"] = 10000
        self.health.poll()
        self.rig.advance(201)
        report = self.health.poll()
        self.assertEqual(report["state"], "UNTRUSTED")
        self.assertEqual(report["reason"], "TIME_HOLDOVER_EXPIRED")

    def test_unsynchronized_or_corrupt_source_cannot_fall_back_to_a_good_cached_sample(self):
        for failure in ("TIME_SOURCE_UNSYNCHRONIZED", "TIME_SOURCE_INVALID", "TIME_SOURCE_AMBIGUOUS"):
            with self.subTest(failure=failure):
                self.rig.sync()
                self.assertEqual(self.health.poll(force=True)["state"], "FRESH")
                self.rig.failure = failure
                self.assertEqual(self.health.poll(force=True)["state"], "UNTRUSTED")

    def test_bootstrap_requires_a_recent_independent_measurement(self):
        self.rig.sample["last_sync_utc"] -= 301
        self.assertEqual(self.health.poll()["state"], "UNTRUSTED")
        self.rig.sync()
        self.assertEqual(self.health.poll(force=True)["state"], "FRESH")

    def test_clock_steps_in_either_direction_invalidate_old_anchors(self):
        for seconds in (3, -3):
            with self.subTest(seconds=seconds):
                self.rig.sync()
                self.health.poll(force=True)
                plan = identifier()
                anchor = self.health.anchor(plan, 1)
                self.rig.step(seconds)
                report = self.health.poll(force=True)
                self.assertEqual(report["state"], "UNTRUSTED")
                self.assertTrue(report["clock_step_detected"])
                self.rig.sync()
                self.health.poll(force=True)
                with self.assertRaisesRegex(Denied, "TIME_UNTRUSTED"):
                    self.health.validate(anchor, plan, 1)

    def test_cancel_on_set_signal_rejects_a_net_zero_forward_and_backward_step(self):
        anchor = self.health.anchor(identifier(), 1)
        self.rig.watch.event = True  # Real kernel cancellation is checked in the disposable VM lab.
        report = self.health.poll(force=True)
        self.assertEqual(report["state"], "UNTRUSTED")
        self.assertGreater(report["generation"], anchor["generation"])
        self.assertEqual(report["reason"], "TIME_CLOCK_STEP")

    def test_suspend_boot_change_and_monotonic_regression_invalidate_time(self):
        for change in ("suspend", "boot", "regression"):
            rig = TimeRig()
            health = rig.health(self.root / change)
            self.addCleanup(health.close)
            health.poll()
            if change == "suspend":
                rig.wall += 3 * NS
                rig.tick += 3 * NS
            elif change == "boot":
                rig.boot = "87654321-4321-4321-4321-cba987654321"
            else:
                rig.tick -= NS
                rig.mono -= NS
            self.assertEqual(health.poll(force=True)["state"], "UNTRUSTED")

    def test_watch_failure_invalidates_anchors_durably_even_if_telemetry_recovers(self):
        plan = identifier()
        anchor = self.health.anchor(plan, 1)
        self.rig.watch.failed = True
        failed = self.health.poll()
        self.assertEqual(failed["state"], "UNTRUSTED")
        self.assertGreater(failed["generation"], anchor["generation"])
        self.rig.watch.failed = False
        self.rig.sync()
        self.health.poll(force=True)
        with self.assertRaisesRegex(Denied, "TIME_UNTRUSTED"):
            self.health.validate(anchor, plan, 1)

    def test_recovery_never_reissues_an_old_plan_revision_with_a_new_time_baseline(self):
        plan = identifier()
        before = self.health.anchor(plan, 1)
        self.assertEqual(before, self.health.anchor(plan, 1))
        self.health.recover()
        with self.assertRaisesRegex(Denied, "TIME_UNTRUSTED"):
            self.health.anchor(plan, 1)
        after = self.health.anchor(plan, 2)
        self.assertGreater(after["generation"], before["generation"])

    def test_anchor_age_is_monotonic_and_execution_does_not_renew_its_approval(self):
        plan = identifier()
        anchor = self.health.anchor(plan, 1)
        self.rig.advance(901)
        self.rig.sync()
        self.health.poll(force=True)
        with self.assertRaisesRegex(Denied, "TIME_UNTRUSTED"):
            self.health.validate(anchor, plan, 1)
        self.health.validate(anchor, plan, 1, active=True)
        with self.assertRaisesRegex(Denied, "TIME_UNTRUSTED"):
            self.health.anchor(plan, 1)

    def test_missing_state_never_creates_an_automatic_replacement(self):
        missing = self.root / "missing"
        health = TimeHealth(missing, source=self.rig.source, clock=self.rig.clock, watch=TestWatch())
        self.addCleanup(health.close)
        self.assertEqual(health.poll()["state"], "UNTRUSTED")
        self.assertFalse(missing.exists())

    def test_failed_recovery_cannot_silently_reactivate_old_time_state_after_disk_recovers(self):
        self.health.anchor(identifier(), 1)
        with patch.object(self.health.journal, "write", side_effect=PermissionError("fixture")):
            with self.assertRaises(PermissionError):
                self.health.recover()
        self.assertEqual(self.health.poll()["state"], "UNTRUSTED")
        self.health.recover()
        self.assertEqual(self.health.poll()["state"], "FRESH")

    def authority(self):
        self.enterContext(patch.dict(CAPABILITIES, {"lab.mutation": Capability(True, "vps:restart")}))
        p = policy(capabilities=["host.probe", "lab.mutation"])
        authority = Authority.initialize(self.root / "gate", p, clock=lambda: self.rig.wall / NS, time_health=self.health)
        return authority, p

    def update_request(self, authority):
        plan = identifier()
        return {"kind": "application", "plan_id": plan, "revision": 1, "plan_digest": "a" * 64, "approval_id": ACTOR,
                "time_anchor": authority.time_anchor({"plan_id": plan, "revision": 1})}

    def test_signed_host_report_is_peer_scoped_and_tampering_or_cross_protocol_reuse_fails(self):
        authority, _ = self.authority()
        peer = Peer(12, WORKER_UID, WORKER_UID)
        report = authority.dispatch("worker", peer, "time.health", {})
        key = bytes(authority.key.verify_key)
        self.assertEqual(verify_host_time(report, key)["state"], "FRESH")
        changed = copy.deepcopy(report)
        changed["claims"]["max_error_ms"] = 0
        with self.assertRaisesRegex(Denied, "TIME_PROOF_INVALID"):
            verify_host_time(changed, key)
        with self.assertRaisesRegex(Denied, "TIME_PROOF_INVALID"):
            verify_host_time(report, bytes(SigningKey.generate().verify_key))
        anchor = authority.time_anchor({"plan_id": identifier(), "revision": 1})
        with self.assertRaisesRegex(Denied, "TIME_PROOF_INVALID"):
            verify_host_time(anchor, key)
        for role in ("api", "stranger"):
            with self.assertRaisesRegex(Denied, "RPC_OPERATION_DENIED"):
                authority.dispatch(role, peer, "time.health", {})

    def test_absent_time_blocks_mutations_but_not_readonly_admission(self):
        authority, p = self.authority()
        self.rig.failure = "TIME_SOURCE_UNAVAILABLE"
        with self.assertRaisesRegex(Denied, "TIME_UNTRUSTED"):
            authority.time_anchor({"plan_id": identifier(), "revision": 1})
        permit = authority.admit(binding(p, identifier()))
        self.assertFalse(permit["claims"]["mutating"])
        authority.consume(permit)

    def test_step_between_admission_and_consumption_keeps_mutating_reservation(self):
        authority, p = self.authority()
        request = binding(p, identifier())
        request["capability"] = "lab.mutation"
        request["time_anchor"] = authority.time_anchor({"plan_id": request["plan_id"], "revision": 1})
        permit = authority.admit(request)
        self.rig.step(2)
        with self.assertRaisesRegex(Denied, "TIME_UNTRUSTED"):
            authority.consume(permit)
        self.assertEqual(authority.status(request["job_id"])["state"], "ISSUED")
        authority.consume(authority.admit(binding(p, identifier())))

    def test_failed_time_at_maintenance_transition_commits_recovery_hold(self):
        authority, _ = self.authority()
        ticket = authority.update("update.quiesce", self.update_request(authority))
        self.rig.failure = "TIME_SOURCE_UNSYNCHRONIZED"
        self.health.poll(force=True)
        with self.assertRaisesRegex(Denied, "TIME_UNTRUSTED"):
            authority.update("update.maintenance", ticket)
        with authority.journal.connect() as db:
            gate = db.execute("SELECT state,epoch FROM gate").fetchone()
            self.assertEqual(gate["state"], "RECOVERY_HOLD")
            self.assertGreater(gate["epoch"], ticket["epoch"])

    def test_periodic_host_check_holds_an_update_without_waiting_for_the_updater(self):
        authority, _ = self.authority()
        ticket = authority.update("update.quiesce", self.update_request(authority))
        authority.update("update.maintenance", ticket)
        self.rig.step(3)
        authority.poll_time()
        with authority.journal.connect() as db:
            self.assertEqual(db.execute("SELECT state FROM gate").fetchone()[0], "RECOVERY_HOLD")


class TimeParserTests(unittest.TestCase):
    def test_chrony_csv_uses_current_correction_and_the_full_root_error_bound(self):
        raw = "C0000201,192.0.2.1,2,1800000000.0,0.001,-0.001,0.001,1.0,0.0,0.1,0.002,0.001,16.0,Normal\n"
        sample = chrony_sample(raw)
        self.assertEqual(sample["offset_ms"], 1)
        self.assertEqual(sample["max_error_ms"], 2)
        for changed in (raw.replace("C0000201", "7F7F0101"), raw.replace("Normal", "Not synchronised"),
                        raw.replace(",0.001,-0.001", ",nan,-0.001"), raw + raw, raw.replace(",16.0,", ",-1,")):
            with self.subTest(changed=changed), self.assertRaises(Denied):
                chrony_sample(changed)

    def test_timesyncd_uses_actual_packet_timestamps_not_the_configured_maximum(self):
        origin = 1_800_000_000_000_000
        row = [0, 4, 4, 2, -20, 2000, 1000, [192, 0, 2, 1], origin, origin + 1000,
               origin + 2000, origin + 3000, False, 5, 100]
        raw = lambda r: json.dumps({"type": "(uuuuittayttttbtt)", "data": r}).encode()
        sample = timesyncd_sample(raw(row), 0, True)
        self.assertEqual(sample["offset_ms"], 0)
        self.assertGreaterEqual(sample["max_error_ms"], 3)
        for position, value in ((0, 3), (3, 16), (12, True), (13, 0), (14, -1)):
            changed = row.copy()
            changed[position] = value
            with self.subTest(position=position), self.assertRaises(Denied):
                timesyncd_sample(raw(changed), 0, True)
        with self.assertRaises(Denied):
            timesyncd_sample(raw(row), 0, False)


if __name__ == "__main__":
    unittest.main()
