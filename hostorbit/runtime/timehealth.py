"""Durable host time baselines, bounded holdover and immutable plan anchors."""

import json
import math
from pathlib import Path
import secrets
import sqlite3

from ..errors import Denied
from .clock import NANOSECOND, ClockWatch, HostSources, clocks, number
from .protocol import ULID, canonical, fields, integer, text
from .storage import Journal


_SCHEMA = """
CREATE TABLE state(id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
CREATE TABLE anchors(plan_id TEXT NOT NULL, revision INTEGER NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY(plan_id,revision));
"""
ANCHOR_FIELDS = ("v", "plan_id", "revision", "boot_id", "generation", "issued_at_utc", "tick_ns", "nonce")


class TimeHealth:
    def __init__(self, directory, *, source=None, clock=None, watch=None):
        self.journal = Journal(Path(directory) / "time.sqlite3")
        self.source, self.clock, self.watch = source or HostSources(), clock or clocks, watch or ClockWatch()
        self._next_probe = 0
        self._recovery_failed = True

    @classmethod
    def initialize(cls, directory, **kwargs):
        journal = Journal.initialize(Path(directory) / "time.sqlite3", _SCHEMA)
        with journal.write() as db:
            db.execute("INSERT INTO state VALUES(1,?)", (canonical({"generation": 0, "previous": None, "base": None,
                "reason": "TIME_STARTUP", "clock_step_detected": False, "blocked_measurement": None}).decode(),))
        health = cls(directory, **kwargs)
        health._recovery_failed = False  # A new journal has no prior approvals.
        return health

    @staticmethod
    def _read(db):
        row = db.execute("SELECT value FROM state WHERE id=1").fetchone()
        if row is None:
            raise Denied("TIME_STATE_INVALID")
        return json.loads(row[0])

    @staticmethod
    def _save(db, state):
        db.execute("UPDATE state SET value=? WHERE id=1", (canonical(state).decode(),))

    @staticmethod
    def _invalidate(state, reason, *, step=False):
        if state["base"] is not None:
            state["blocked_measurement"] = state["base"]["measurement_id"]
        if state["base"] is not None or state["reason"] != reason:
            state["generation"] += 1
        state.update(base=None, reason=reason, clock_step_detected=step or state["clock_step_detected"])

    def recover(self):
        """A fresh process/boot cannot reuse a prior process's time approvals."""
        self._recovery_failed = True
        if not self.journal.path.exists():
            return  # Existing installations remain read-only until explicit init.
        with self.journal.write() as db:
            state = self._read(db)
            state.update(generation=state["generation"] + 1, previous=None, base=None,
                         reason="TIME_STARTUP", clock_step_detected=False, blocked_measurement=None)
            self._save(db, state)
        self._next_probe = 0
        self._recovery_failed = False

    def _clock_check(self, state, current):
        previous = state["previous"]
        reason = None
        if self.watch.changed():
            reason = "TIME_CLOCK_STEP"
        if previous is not None:
            elapsed = current["tick_ns"] - previous["tick_ns"]
            if current["boot_id"] != previous["boot_id"]:
                reason = "TIME_BOOT_CHANGED"
            elif elapsed < 0 or current["mono_ns"] < previous["mono_ns"]:
                reason = "TIME_MONOTONIC_CHANGED"
            elif abs((current["wall_ns"] - previous["wall_ns"]) - elapsed) > NANOSECOND:
                reason = "TIME_CLOCK_STEP"
            elif abs((current["mono_ns"] - previous["mono_ns"]) - elapsed) > NANOSECOND:
                reason = "TIME_SUSPEND_DETECTED"
        state["previous"] = current
        if reason:
            self._invalidate(state, reason, step=True)
        return reason

    @staticmethod
    def _sample(value, current):
        fields(value, ("source", "last_sync_utc", "offset_ms", "max_error_ms", "rate_ppm", "measurement_id"))
        if value["source"] not in ("chrony", "timesyncd"):
            raise Denied("TIME_SOURCE_INVALID")
        reference = number(value["last_sync_utc"], low=1, high=2**53)
        offset = number(value["offset_ms"], low=-86400_000, high=86400_000)
        error = number(value["max_error_ms"], low=0, high=86400_000)
        rate = number(value["rate_ppm"], low=500, high=100_000)
        text(value["measurement_id"], r"[A-Za-z0-9:.+-]{1,160}")
        age = current["wall_ns"] / NANOSECOND - reference
        if abs(offset) + error > 2000 or age < -2 or age > 86400:
            raise Denied("TIME_BOUNDS_EXCEEDED")
        # Include source uncertainty in age rather than rounding a boundary down.
        age = max(0.0, age) + (abs(offset) + error) / 1000
        return {**value, "offset_ms": offset, "max_error_ms": error, "rate_ppm": rate,
                "last_sync_utc": reference, "age": age}

    @staticmethod
    def _report(state, current):
        base = state["base"]
        result = {"v": 1, "state": "UNTRUSTED", "reason": state["reason"], "generation": state["generation"],
                  "source": None, "last_sync_utc": None, "offset_ms": None, "max_error_ms": None,
                  "sample_age_s": None, "clock_step_detected": state["clock_step_detected"],
                  "boot_id": current["boot_id"], "observed_at_utc": current["wall_ns"] // NANOSECOND,
                  "tick_ns": current["tick_ns"]}
        if base is None:
            return result
        elapsed = (current["tick_ns"] - base["captured_tick_ns"]) / NANOSECOND
        age = (current["tick_ns"] - base["reference_tick_ns"]) / NANOSECOND
        error = max(base["max_error_ms"] + max(0, elapsed) * base["rate_ppm"] / 1000,
                    base["latest_bound_ms"] - abs(base["offset_ms"]))
        result.update(source=base["source"], last_sync_utc=base["last_sync_utc"], offset_ms=base["offset_ms"],
                      max_error_ms=error, sample_age_s=age)
        if age < 0 or elapsed < 0 or age > 3600 or abs(base["offset_ms"]) + error > 2000:
            result["reason"] = "TIME_HOLDOVER_EXPIRED"
        else:
            result.update(state="FRESH" if age <= 300 else "HOLDOVER", reason="OK")
        return result

    def poll(self, *, force=False):
        try:
            current = self.clock()
        except (OSError, Denied):
            return self._unavailable(None)
        if self._recovery_failed:
            return self._unavailable(current)
        try:
            with self.journal.write() as db:
                state = self._read(db)
                try:
                    event = self._clock_check(state, current)
                except (Denied, OSError):
                    self._invalidate(state, "TIME_WATCH_UNAVAILABLE", step=True)
                    self._save(db, state)
                    return self._report(state, current)
                if force or current["tick_ns"] >= self._next_probe:
                    self._next_probe = current["tick_ns"] + 30 * NANOSECOND
                    try:
                        value = self.source()
                        after = self.clock()
                        event = self._clock_check(state, after) or event
                        current = after
                        sample = self._sample(value, current)
                        if not event and sample["measurement_id"] != state["blocked_measurement"]:
                            base = state["base"]
                            if base is None or base["measurement_id"] != sample["measurement_id"]:
                                if sample["age"] <= 300:
                                    state.update(base={key: val for key, val in sample.items() if key != "age"},
                                                 reason="OK", clock_step_detected=False, blocked_measurement=None)
                                    state["base"].update(captured_tick_ns=current["tick_ns"],
                                        reference_tick_ns=current["tick_ns"] - math.ceil(sample["age"] * NANOSECOND),
                                        latest_bound_ms=abs(sample["offset_ms"]) + sample["max_error_ms"])
                                elif base is None:
                                    state["reason"] = "TIME_SAMPLE_STALE"
                            else:
                                base["latest_bound_ms"] = abs(sample["offset_ms"]) + sample["max_error_ms"]
                                base["rate_ppm"] = max(base["rate_ppm"], sample["rate_ppm"])
                    except Denied as error:
                        if error.code != "TIME_SOURCE_UNAVAILABLE":
                            self._invalidate(state, error.code, step=error.code == "TIME_WATCH_UNAVAILABLE")
                        elif state["base"] is None:
                            state["reason"] = error.code
                    except (OSError, KeyError, ValueError, TypeError):
                        self._invalidate(state, "TIME_SOURCE_INVALID")
                result = self._report(state, current)
                if result["state"] == "UNTRUSTED" and state["base"] is not None:
                    self._invalidate(state, result["reason"])
                    result = self._report(state, current)
                self._save(db, state)
                return result
        except (OSError, RuntimeError, Denied, ValueError, TypeError, KeyError, sqlite3.Error):
            return self._unavailable(current)

    @staticmethod
    def _unavailable(current):
        return {"v": 1, "state": "UNTRUSTED", "reason": "TIME_STATE_OR_WATCH_UNAVAILABLE", "generation": -1,
                "source": None, "last_sync_utc": None, "offset_ms": None, "max_error_ms": None,
                "sample_age_s": None, "clock_step_detected": True, "boot_id": current["boot_id"] if current else None,
                "observed_at_utc": current["wall_ns"] // NANOSECOND if current else None,
                "tick_ns": current["tick_ns"] if current else None}

    def anchor(self, plan_id, revision):
        text(plan_id, ULID)
        integer(revision, 1, 2**31 - 1)
        report = self.poll()
        if report["state"] == "UNTRUSTED":
            raise Denied("TIME_UNTRUSTED")
        with self.journal.write() as db:
            row = db.execute("SELECT value FROM anchors WHERE plan_id=? AND revision=?", (plan_id, revision)).fetchone()
            if row:
                value = json.loads(row[0])
                self._validate(value, report, plan_id, revision)
                return value
            value = {"v": 1, "plan_id": plan_id, "revision": revision, "boot_id": report["boot_id"],
                     "generation": report["generation"], "issued_at_utc": report["observed_at_utc"],
                     "tick_ns": report["tick_ns"], "nonce": secrets.token_hex(32)}
            db.execute("INSERT INTO anchors VALUES(?,?,?)", (plan_id, revision, canonical(value).decode()))
            return value

    @staticmethod
    def _validate(value, report, plan_id, revision, *, active=False):
        fields(value, ANCHOR_FIELDS)
        if (report["state"] == "UNTRUSTED" or value["v"] != 1 or value["plan_id"] != plan_id or value["revision"] != revision
                or value["generation"] != report["generation"] or value["boot_id"] != report["boot_id"]
                or not 0 <= report["tick_ns"] - value["tick_ns"] <= (2**63 - 1 if active else 900 * NANOSECOND)):
            raise Denied("TIME_UNTRUSTED")

    def validate(self, value, plan_id, revision, *, active=False):
        report = self.poll()
        self._validate(value, report, plan_id, revision, active=active)
        with self.journal.connect() as db:
            row = db.execute("SELECT value FROM anchors WHERE plan_id=? AND revision=?", (plan_id, revision)).fetchone()
            if row is None or row[0] != canonical(value).decode():
                raise Denied("TIME_UNTRUSTED")
        return report

    def close(self):
        self.watch.close()
