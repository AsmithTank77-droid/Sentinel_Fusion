"""Tests for detection/winlog_rules.py"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from detection.winlog_rules import WinlogRulesDetector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ev(event_id: int, src_ip: str = "", timestamp: str = "2026-05-09T10:00:00Z",
        timestamp_epoch: float = 1746784800.0, target_user: str = "",
        subject_user: str = "", logon_type: int | None = None,
        group_name: str = "", service_name: str = "", task_name: str = "",
        computer: str = "DC01") -> dict:
    """Build a Sentinel_Fusion enriched winlog event dict."""
    return {
        "source_type": "winlog",
        "src_ip":       src_ip,
        "dst_ip":       computer,
        "timestamp":    timestamp,
        "severity":     5,
        "event_type":   "winlog_event",
        "metadata": {
            "event_id":        event_id,
            "timestamp_epoch": timestamp_epoch,
            "src_ip":          src_ip,
            "target_user":     target_user,
            "subject_user":    subject_user,
            "logon_type":      logon_type,
            "group_name":      group_name,
            "service_name":    service_name,
            "task_name":       task_name,
            "computer":        computer,
        },
    }


def _fail(src_ip: str = "1.2.3.4", target_user: str = "admin",
          epoch: float = 1746784800.0, ts: str = "2026-05-09T10:00:00Z") -> dict:
    return _ev(4625, src_ip=src_ip, target_user=target_user,
               timestamp_epoch=epoch, timestamp=ts)


def _success(src_ip: str = "1.2.3.4", target_user: str = "admin",
             epoch: float = 1746784900.0, ts: str = "2026-05-09T10:01:40Z") -> dict:
    return _ev(4624, src_ip=src_ip, target_user=target_user,
               logon_type=3, timestamp_epoch=epoch, timestamp=ts)


# ---------------------------------------------------------------------------
# WinlogRulesDetector — contract
# ---------------------------------------------------------------------------

class TestDetectorContract:
    def setup_method(self):
        self.detector = WinlogRulesDetector()

    def test_returns_list(self):
        assert isinstance(self.detector.detect([]), list)

    def test_empty_input_returns_empty(self):
        assert self.detector.detect([]) == []

    def test_non_winlog_events_ignored(self):
        nra_event = {"source_type": "nra", "src_ip": "1.2.3.4", "metadata": {}}
        assert self.detector.detect([nra_event]) == []

    def test_alert_has_required_keys(self):
        events = [_fail(epoch=float(i)) for i in range(6)]
        alerts = self.detector.detect(events)
        if alerts:
            required = {"alert_type", "confidence", "mitre_technique",
                        "mitre_tactic", "description", "first_seen",
                        "last_seen", "severity"}
            assert required.issubset(set(alerts[0].keys()))

    def test_confidence_in_range(self):
        events = [_fail(epoch=float(i)) for i in range(6)]
        for alert in self.detector.detect(events):
            assert 0.0 <= alert["confidence"] <= 1.0

    def test_severity_is_int(self):
        events = [_fail(epoch=float(i)) for i in range(6)]
        for alert in self.detector.detect(events):
            assert isinstance(alert["severity"], int)


# ---------------------------------------------------------------------------
# WINLOG-001 — Brute Force
# ---------------------------------------------------------------------------

class TestRuleBruteForce:
    def setup_method(self):
        self.detector = WinlogRulesDetector()

    def _brute_events(self, count: int = 6, src_ip: str = "10.0.0.99") -> list:
        return [_fail(src_ip=src_ip, epoch=float(i * 5)) for i in range(count)]

    def test_fires_on_5_plus_failures(self):
        alerts = self.detector.detect(self._brute_events(6))
        bf = [a for a in alerts if a["alert_type"] == "WINLOG-001"]
        assert len(bf) >= 1

    def test_does_not_fire_on_4_failures(self):
        alerts = self.detector.detect(self._brute_events(4))
        bf = [a for a in alerts if a["alert_type"] == "WINLOG-001"]
        assert len(bf) == 0

    def test_fires_only_on_same_src_ip(self):
        events = (
            [_fail(src_ip="1.1.1.1", epoch=float(i)) for i in range(3)]
            + [_fail(src_ip="2.2.2.2", epoch=float(i)) for i in range(3)]
        )
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-001"]
        assert len(alerts) == 0

    def test_fires_per_distinct_src_ip(self):
        events = (
            [_fail(src_ip="1.1.1.1", epoch=float(i * 5)) for i in range(6)]
            + [_fail(src_ip="2.2.2.2", epoch=float(i * 5)) for i in range(6)]
        )
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-001"]
        src_ips = {a["context"]["src_ip"] for a in alerts}
        assert "1.1.1.1" in src_ips
        assert "2.2.2.2" in src_ips

    def test_mitre_tactic_credential_access(self):
        alerts = self.detector.detect(self._brute_events())
        bf = [a for a in alerts if a["alert_type"] == "WINLOG-001"]
        assert any("Credential Access" in a["mitre_tactic"] for a in bf)

    def test_context_has_src_ip(self):
        alerts = self.detector.detect(self._brute_events(src_ip="5.5.5.5"))
        bf = [a for a in alerts if a["alert_type"] == "WINLOG-001"]
        assert bf[0]["context"]["src_ip"] == "5.5.5.5"

    def test_context_has_failure_count(self):
        alerts = self.detector.detect(self._brute_events(6))
        bf = [a for a in alerts if a["alert_type"] == "WINLOG-001"]
        assert bf[0]["context"]["failure_count"] >= 5

    def test_failures_outside_window_do_not_fire(self):
        events = [_fail(src_ip="9.9.9.9", epoch=float(i * 30)) for i in range(6)]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-001"]
        assert len(alerts) == 0


# ---------------------------------------------------------------------------
# WINLOG-002 — Brute Force Followed by Successful Logon
# ---------------------------------------------------------------------------

class TestRuleBruteForceSuccess:
    def setup_method(self):
        self.detector = WinlogRulesDetector()

    def _bf_then_success(self, src_ip: str = "3.3.3.3", gap: float = 30.0) -> list:
        failures = [_fail(src_ip=src_ip, epoch=float(i * 5)) for i in range(6)]
        last_fail_epoch = float(5 * 5)
        success = _success(src_ip=src_ip, epoch=last_fail_epoch + gap)
        return failures + [success]

    def test_fires_on_brute_force_followed_by_success(self):
        alerts = self.detector.detect(self._bf_then_success())
        assert any(a["alert_type"] == "WINLOG-002" for a in alerts)

    def test_does_not_fire_when_success_too_late(self):
        events = self._bf_then_success(gap=200.0)
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-002"]
        assert len(alerts) == 0

    def test_confidence_is_high(self):
        alerts = self.detector.detect(self._bf_then_success())
        rule2 = [a for a in alerts if a["alert_type"] == "WINLOG-002"]
        if rule2:
            assert rule2[0]["confidence"] >= 0.90

    def test_severity_is_10(self):
        alerts = self.detector.detect(self._bf_then_success())
        rule2 = [a for a in alerts if a["alert_type"] == "WINLOG-002"]
        if rule2:
            assert rule2[0]["severity"] == 10

    def test_context_has_compromised_user(self):
        alerts = self.detector.detect(self._bf_then_success())
        rule2 = [a for a in alerts if a["alert_type"] == "WINLOG-002"]
        if rule2:
            assert "compromised_user" in rule2[0]["context"]


# ---------------------------------------------------------------------------
# WINLOG-003 — New Account Added to Security Group
# ---------------------------------------------------------------------------

class TestRuleAccountBackdoor:
    def setup_method(self):
        self.detector = WinlogRulesDetector()

    def test_fires_on_account_created_then_group_add(self):
        events = [
            _ev(4720, target_user="newuser", subject_user="admin",
                timestamp_epoch=1000.0, timestamp="2026-05-09T10:00:00Z"),
            _ev(4732, group_name="Administrators", timestamp_epoch=1050.0,
                timestamp="2026-05-09T10:00:50Z"),
        ]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-003"]
        assert len(alerts) >= 1

    def test_does_not_fire_when_gap_too_large(self):
        events = [
            _ev(4720, target_user="newuser", timestamp_epoch=1000.0,
                timestamp="2026-05-09T10:00:00Z"),
            _ev(4732, group_name="Admins", timestamp_epoch=2000.0,
                timestamp="2026-05-09T10:16:40Z"),
        ]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-003"]
        assert len(alerts) == 0

    def test_context_has_new_user(self):
        events = [
            _ev(4720, target_user="backdoor_user", timestamp_epoch=1000.0,
                timestamp="2026-05-09T10:00:00Z"),
            _ev(4732, group_name="Administrators", timestamp_epoch=1100.0,
                timestamp="2026-05-09T10:01:40Z"),
        ]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-003"]
        if alerts:
            assert "new_user" in alerts[0]["context"]


# ---------------------------------------------------------------------------
# WINLOG-004 — Lateral Movement
# ---------------------------------------------------------------------------

class TestRuleLateralMovement:
    def setup_method(self):
        self.detector = WinlogRulesDetector()

    def test_fires_on_explicit_cred_then_net_logon(self):
        events = [
            _ev(4648, subject_user="jdoe", timestamp_epoch=1000.0,
                timestamp="2026-05-09T10:00:00Z"),
            _ev(4624, subject_user="jdoe", logon_type=3, timestamp_epoch=1060.0,
                timestamp="2026-05-09T10:01:00Z"),
        ]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-004"]
        assert len(alerts) >= 1

    def test_does_not_fire_for_system_accounts(self):
        events = [
            _ev(4648, subject_user="system", timestamp_epoch=1000.0,
                timestamp="2026-05-09T10:00:00Z"),
            _ev(4624, subject_user="system", logon_type=3, timestamp_epoch=1060.0,
                timestamp="2026-05-09T10:01:00Z"),
        ]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-004"]
        assert len(alerts) == 0

    def test_mitre_tactic_lateral_movement(self):
        events = [
            _ev(4648, subject_user="hacker", timestamp_epoch=1000.0,
                timestamp="2026-05-09T10:00:00Z"),
            _ev(4624, subject_user="hacker", logon_type=3, timestamp_epoch=1050.0,
                timestamp="2026-05-09T10:00:50Z"),
        ]
        alerts = self.detector.detect(events)
        lm = [a for a in alerts if a["alert_type"] == "WINLOG-004"]
        if lm:
            assert "Lateral Movement" in lm[0]["mitre_tactic"]


# ---------------------------------------------------------------------------
# WINLOG-006 — Audit Log Cleared
# ---------------------------------------------------------------------------

class TestRuleLogCleared:
    def setup_method(self):
        self.detector = WinlogRulesDetector()

    def test_fires_on_1102(self):
        events = [_ev(1102, subject_user="admin", timestamp_epoch=1000.0,
                      timestamp="2026-05-09T10:00:00Z")]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-006"]
        assert len(alerts) == 1

    def test_confidence_near_1(self):
        events = [_ev(1102, subject_user="admin", timestamp_epoch=1000.0,
                      timestamp="2026-05-09T10:00:00Z")]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-006"]
        assert alerts[0]["confidence"] >= 0.95

    def test_severity_is_10(self):
        events = [_ev(1102, timestamp_epoch=1000.0, timestamp="2026-05-09T10:00:00Z")]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-006"]
        assert alerts[0]["severity"] == 10

    def test_does_not_fire_on_other_event_ids(self):
        events = [_ev(4624, timestamp_epoch=1000.0, timestamp="2026-05-09T10:00:00Z")]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-006"]
        assert len(alerts) == 0

    def test_multiple_clears_produce_multiple_alerts(self):
        events = [
            _ev(1102, timestamp_epoch=1000.0, timestamp="2026-05-09T10:00:00Z"),
            _ev(1102, timestamp_epoch=2000.0, timestamp="2026-05-09T10:16:40Z"),
        ]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-006"]
        assert len(alerts) == 2

    def test_mitre_defense_evasion(self):
        events = [_ev(1102, timestamp_epoch=1000.0, timestamp="2026-05-09T10:00:00Z")]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-006"]
        assert "Defense Evasion" in alerts[0]["mitre_tactic"]


# ---------------------------------------------------------------------------
# WINLOG-007 — Audit Policy Changed
# ---------------------------------------------------------------------------

class TestRuleAuditPolicyChanged:
    def setup_method(self):
        self.detector = WinlogRulesDetector()

    def test_fires_on_4719(self):
        events = [_ev(4719, subject_user="admin", timestamp_epoch=1000.0,
                      timestamp="2026-05-09T10:00:00Z")]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-007"]
        assert len(alerts) == 1

    def test_severity_is_8(self):
        events = [_ev(4719, timestamp_epoch=1000.0, timestamp="2026-05-09T10:00:00Z")]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-007"]
        assert alerts[0]["severity"] == 8


# ---------------------------------------------------------------------------
# WINLOG-008 — New Service Installed
# ---------------------------------------------------------------------------

class TestRuleNewService:
    def setup_method(self):
        self.detector = WinlogRulesDetector()

    def test_fires_on_7045(self):
        events = [_ev(7045, service_name="evilsvc", subject_user="admin",
                      timestamp_epoch=1000.0, timestamp="2026-05-09T10:00:00Z")]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-008"]
        assert len(alerts) == 1

    def test_context_has_service_name(self):
        events = [_ev(7045, service_name="backdoor", timestamp_epoch=1000.0,
                      timestamp="2026-05-09T10:00:00Z")]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-008"]
        assert alerts[0]["context"]["service_name"] == "backdoor"

    def test_mitre_persistence(self):
        events = [_ev(7045, timestamp_epoch=1000.0, timestamp="2026-05-09T10:00:00Z")]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-008"]
        assert "Persistence" in alerts[0]["mitre_tactic"]


# ---------------------------------------------------------------------------
# WINLOG-009 — Scheduled Task Persistence
# ---------------------------------------------------------------------------

class TestRuleScheduledTask:
    def setup_method(self):
        self.detector = WinlogRulesDetector()

    def test_fires_on_4698_created(self):
        events = [_ev(4698, task_name="\\evil_task", subject_user="admin",
                      timestamp_epoch=1000.0, timestamp="2026-05-09T10:00:00Z")]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-009"]
        assert len(alerts) == 1
        assert "Created" in alerts[0]["title"]

    def test_fires_on_4702_modified(self):
        events = [_ev(4702, task_name="\\evil_task", subject_user="admin",
                      timestamp_epoch=1000.0, timestamp="2026-05-09T10:00:00Z")]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-009"]
        assert len(alerts) == 1
        assert "Modified" in alerts[0]["title"]

    def test_context_has_task_name(self):
        events = [_ev(4698, task_name="\\persist", timestamp_epoch=1000.0,
                      timestamp="2026-05-09T10:00:00Z")]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-009"]
        assert alerts[0]["context"]["task_name"] == "\\persist"


# ---------------------------------------------------------------------------
# Mixed event streams
# ---------------------------------------------------------------------------

class TestMixedEventStream:
    def setup_method(self):
        self.detector = WinlogRulesDetector()

    def test_multiple_rules_fire_independently(self):
        events = (
            [_fail(src_ip="1.1.1.1", epoch=float(i * 5)) for i in range(6)]
            + [_ev(1102, timestamp_epoch=1000.0, timestamp="2026-05-09T10:00:00Z")]
            + [_ev(7045, service_name="backdoor", timestamp_epoch=2000.0,
                   timestamp="2026-05-09T10:33:20Z")]
        )
        alerts = self.detector.detect(events)
        rule_ids = {a["alert_type"] for a in alerts}
        assert "WINLOG-001" in rule_ids
        assert "WINLOG-006" in rule_ids
        assert "WINLOG-008" in rule_ids

    def test_source_field_is_winlog_rules(self):
        events = [_ev(1102, timestamp_epoch=1000.0, timestamp="2026-05-09T10:00:00Z")]
        alerts = self.detector.detect(events)
        assert all(a.get("source") == "winlog_rules" for a in alerts)

    def test_nra_events_in_mixed_stream_ignored(self):
        events = [
            {"source_type": "nra", "metadata": {"event_id": 1102}},
            _ev(1102, timestamp_epoch=1000.0, timestamp="2026-05-09T10:00:00Z"),
        ]
        alerts = [a for a in self.detector.detect(events) if a["alert_type"] == "WINLOG-006"]
        assert len(alerts) == 1
