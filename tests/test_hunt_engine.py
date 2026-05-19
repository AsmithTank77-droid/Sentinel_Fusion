"""Tests for hunting/hunt_engine.py"""

import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hunting.hunt_engine import (
    HuntEngine,
    _hunt_low_and_slow_brute_force,
    _hunt_alert_cluster,
    _hunt_beacon,
    _hunt_persistent_threat_actor,
    _REQUIRED_KEYS,
    _SLOW_BF_MIN_RUNS,
    _CLUSTER_MIN_ALERTS,
    _BEACON_MIN_RUNS,
    _PERSISTENT_MIN_RUNS,
)


# ---------------------------------------------------------------------------
# Minimal store/model stubs
# ---------------------------------------------------------------------------

class _Ev:
    def __init__(self, src_ip, dst_ip, event_type, run_id):
        self.src_ip     = src_ip
        self.dst_ip     = dst_ip
        self.event_type = event_type
        self.run_id     = run_id


class _Al:
    def __init__(self, src_ip, dst_ip, alert_type, confidence, run_id, status="open"):
        self.src_ip     = src_ip
        self.dst_ip     = dst_ip
        self.alert_type = alert_type
        self.confidence = confidence
        self.run_id     = run_id
        self.status     = status


class _Events:
    def __init__(self, events=None):
        self._events = events or []

    def get_by_event_type(self, event_type, limit=2000):
        return [e for e in self._events if e.event_type == event_type][:limit]

    def get_recent(self, limit=5000):
        return self._events[:limit]


class _Alerts:
    def __init__(self, alerts=None):
        self._alerts = alerts or []

    def get_open(self, min_confidence=0.0):
        return [a for a in self._alerts if a.confidence >= min_confidence]

    def get_by_src_ip(self, src_ip):
        return [a for a in self._alerts if a.src_ip == src_ip]


class _Store:
    def __init__(self, events=None, alerts=None):
        self.events = _Events(events)
        self.alerts = _Alerts(alerts)


def _make_auth_failures(src_ip, run_ids, count_per_run=2):
    return [
        _Ev(src_ip, "10.0.0.1", "auth_failure", run_id)
        for run_id in run_ids
        for _ in range(count_per_run)
    ]


# ---------------------------------------------------------------------------
# TestHuntEngineContract
# ---------------------------------------------------------------------------

class TestHuntEngineContract:
    def test_none_store_returns_empty(self):
        assert HuntEngine().hunt(None) == []

    def test_empty_store_returns_empty(self):
        store = _Store()
        assert HuntEngine().hunt(store) == []

    def test_returns_list(self):
        store = _Store()
        result = HuntEngine().hunt(store)
        assert isinstance(result, list)

    def test_finding_has_required_keys(self):
        # Build enough auth_failure events to trigger low_and_slow
        run_ids = [f"run-{i}" for i in range(_SLOW_BF_MIN_RUNS)]
        evs = _make_auth_failures("1.2.3.4", run_ids, count_per_run=2)
        store = _Store(events=evs)
        findings = HuntEngine().hunt(store)
        assert len(findings) > 0
        for f in findings:
            assert _REQUIRED_KEYS.issubset(set(f.keys()))

    def test_findings_sorted_by_confidence_desc(self):
        run_ids = [f"run-{i}" for i in range(8)]
        evs = _make_auth_failures("1.2.3.4", run_ids, count_per_run=2)
        store = _Store(events=evs)
        findings = HuntEngine().hunt(store)
        confidences = [f["confidence"] for f in findings]
        assert confidences == sorted(confidences, reverse=True)

    def test_source_field_is_hunt_engine(self):
        run_ids = [f"run-{i}" for i in range(_SLOW_BF_MIN_RUNS)]
        evs = _make_auth_failures("1.2.3.4", run_ids)
        store = _Store(events=evs)
        findings = HuntEngine().hunt(store)
        for f in findings:
            assert f["source"] == "hunt_engine"

    def test_confidence_in_range(self):
        run_ids = [f"run-{i}" for i in range(_SLOW_BF_MIN_RUNS)]
        evs = _make_auth_failures("1.2.3.4", run_ids)
        store = _Store(events=evs)
        for f in HuntEngine().hunt(store):
            assert 0.0 <= f["confidence"] <= 1.0

    def test_severity_is_valid_string(self):
        run_ids = [f"run-{i}" for i in range(_SLOW_BF_MIN_RUNS)]
        evs = _make_auth_failures("1.2.3.4", run_ids)
        store = _Store(events=evs)
        for f in HuntEngine().hunt(store):
            assert f["severity"] in ("low", "medium", "high", "critical")


# ---------------------------------------------------------------------------
# TestLowAndSlowBruteForce
# ---------------------------------------------------------------------------

class TestLowAndSlowBruteForce:
    def test_fires_at_threshold(self):
        run_ids = [f"run-{i}" for i in range(_SLOW_BF_MIN_RUNS)]
        evs = _make_auth_failures("9.9.9.9", run_ids, count_per_run=2)
        store = _Store(events=evs)
        findings = _hunt_low_and_slow_brute_force(store)
        assert any(f["hunt_type"] == "low_and_slow_brute_force" for f in findings)

    def test_does_not_fire_below_threshold(self):
        run_ids = [f"run-{i}" for i in range(_SLOW_BF_MIN_RUNS - 1)]
        evs = _make_auth_failures("9.9.9.9", run_ids, count_per_run=2)
        store = _Store(events=evs)
        findings = _hunt_low_and_slow_brute_force(store)
        assert findings == []

    def test_ignores_runs_above_per_run_limit(self):
        # One run with 5+ failures (above sub-threshold) — should not count
        run_ids_ok  = [f"run-{i}" for i in range(_SLOW_BF_MIN_RUNS - 1)]
        run_ids_hot = ["run-hot"]
        evs = (
            _make_auth_failures("9.9.9.9", run_ids_ok,  count_per_run=2) +
            _make_auth_failures("9.9.9.9", run_ids_hot, count_per_run=10)
        )
        store = _Store(events=evs)
        findings = _hunt_low_and_slow_brute_force(store)
        assert findings == []

    def test_src_ip_in_finding(self):
        run_ids = [f"run-{i}" for i in range(_SLOW_BF_MIN_RUNS)]
        evs = _make_auth_failures("5.5.5.5", run_ids)
        store = _Store(events=evs)
        findings = _hunt_low_and_slow_brute_force(store)
        assert findings[0]["src_ip"] == "5.5.5.5"

    def test_mitre_tactic_credential_access(self):
        run_ids = [f"run-{i}" for i in range(_SLOW_BF_MIN_RUNS)]
        evs = _make_auth_failures("5.5.5.5", run_ids)
        store = _Store(events=evs)
        findings = _hunt_low_and_slow_brute_force(store)
        assert "TA0006" in findings[0]["mitre_tactic"]

    def test_evidence_has_run_breakdown(self):
        run_ids = [f"run-{i}" for i in range(_SLOW_BF_MIN_RUNS)]
        evs = _make_auth_failures("5.5.5.5", run_ids)
        store = _Store(events=evs)
        findings = _hunt_low_and_slow_brute_force(store)
        assert "run_breakdown" in findings[0]["evidence"]

    def test_run_count_correct(self):
        run_ids = [f"run-{i}" for i in range(_SLOW_BF_MIN_RUNS + 1)]
        evs = _make_auth_failures("5.5.5.5", run_ids)
        store = _Store(events=evs)
        findings = _hunt_low_and_slow_brute_force(store)
        assert findings[0]["run_count"] == _SLOW_BF_MIN_RUNS + 1

    def test_severity_high_at_six_runs(self):
        run_ids = [f"run-{i}" for i in range(6)]
        evs = _make_auth_failures("5.5.5.5", run_ids)
        store = _Store(events=evs)
        findings = _hunt_low_and_slow_brute_force(store)
        assert findings[0]["severity"] == "high"

    def test_empty_events_returns_empty(self):
        store = _Store(events=[])
        assert _hunt_low_and_slow_brute_force(store) == []

    def test_multiple_ips_detected_independently(self):
        run_ids = [f"run-{i}" for i in range(_SLOW_BF_MIN_RUNS)]
        evs = (
            _make_auth_failures("1.1.1.1", run_ids) +
            _make_auth_failures("2.2.2.2", run_ids)
        )
        store = _Store(events=evs)
        findings = _hunt_low_and_slow_brute_force(store)
        src_ips = {f["src_ip"] for f in findings}
        assert "1.1.1.1" in src_ips
        assert "2.2.2.2" in src_ips


# ---------------------------------------------------------------------------
# TestAlertCluster
# ---------------------------------------------------------------------------

class TestAlertCluster:
    def _make_alerts(self, src_ip, count, run_ids=None):
        run_ids = run_ids or ["run-0"] * count
        return [
            _Al(src_ip, "10.0.0.1", f"alert_type_{i}", 0.4, run_ids[i % len(run_ids)])
            for i in range(count)
        ]

    def test_fires_at_threshold(self):
        alerts = self._make_alerts("3.3.3.3", _CLUSTER_MIN_ALERTS)
        store = _Store(alerts=alerts)
        findings = _hunt_alert_cluster(store)
        assert any(f["hunt_type"] == "alert_cluster" for f in findings)

    def test_does_not_fire_below_threshold(self):
        alerts = self._make_alerts("3.3.3.3", _CLUSTER_MIN_ALERTS - 1)
        store = _Store(alerts=alerts)
        findings = _hunt_alert_cluster(store)
        assert findings == []

    def test_src_ip_in_finding(self):
        alerts = self._make_alerts("3.3.3.3", _CLUSTER_MIN_ALERTS)
        store = _Store(alerts=alerts)
        findings = _hunt_alert_cluster(store)
        assert findings[0]["src_ip"] == "3.3.3.3"

    def test_evidence_has_alert_count(self):
        alerts = self._make_alerts("3.3.3.3", _CLUSTER_MIN_ALERTS)
        store = _Store(alerts=alerts)
        findings = _hunt_alert_cluster(store)
        assert findings[0]["evidence"]["alert_count"] == _CLUSTER_MIN_ALERTS

    def test_mitre_tactic_reconnaissance(self):
        alerts = self._make_alerts("3.3.3.3", _CLUSTER_MIN_ALERTS)
        store = _Store(alerts=alerts)
        findings = _hunt_alert_cluster(store)
        assert "TA0043" in findings[0]["mitre_tactic"]

    def test_no_alerts_returns_empty(self):
        store = _Store(alerts=[])
        assert _hunt_alert_cluster(store) == []

    def test_alerts_with_no_src_ip_ignored(self):
        alerts = [_Al("", "10.0.0.1", "scan", 0.4, "run-0") for _ in range(_CLUSTER_MIN_ALERTS)]
        store = _Store(alerts=alerts)
        assert _hunt_alert_cluster(store) == []


# ---------------------------------------------------------------------------
# TestBeacon
# ---------------------------------------------------------------------------

class TestBeacon:
    def _make_beacon_events(self, src_ip, dst_ip, run_count):
        return [
            _Ev(src_ip, dst_ip, "port_scan", f"run-{i}")
            for i in range(run_count)
        ]

    def test_fires_at_threshold(self):
        evs = self._make_beacon_events("7.7.7.7", "10.0.0.5", _BEACON_MIN_RUNS)
        store = _Store(events=evs)
        findings = _hunt_beacon(store)
        assert any(f["hunt_type"] == "beacon" for f in findings)

    def test_does_not_fire_below_threshold(self):
        evs = self._make_beacon_events("7.7.7.7", "10.0.0.5", _BEACON_MIN_RUNS - 1)
        store = _Store(events=evs)
        findings = _hunt_beacon(store)
        assert findings == []

    def test_src_dst_in_finding(self):
        evs = self._make_beacon_events("7.7.7.7", "10.0.0.5", _BEACON_MIN_RUNS)
        store = _Store(events=evs)
        findings = _hunt_beacon(store)
        assert findings[0]["src_ip"] == "7.7.7.7"
        assert findings[0]["dst_ip"] == "10.0.0.5"

    def test_mitre_tactic_c2(self):
        evs = self._make_beacon_events("7.7.7.7", "10.0.0.5", _BEACON_MIN_RUNS)
        store = _Store(events=evs)
        findings = _hunt_beacon(store)
        assert "TA0011" in findings[0]["mitre_tactic"]

    def test_run_count_in_evidence(self):
        evs = self._make_beacon_events("7.7.7.7", "10.0.0.5", _BEACON_MIN_RUNS + 2)
        store = _Store(events=evs)
        findings = _hunt_beacon(store)
        assert findings[0]["run_count"] == _BEACON_MIN_RUNS + 2

    def test_events_with_missing_dst_ignored(self):
        evs = [_Ev("7.7.7.7", "", "port_scan", f"run-{i}") for i in range(_BEACON_MIN_RUNS)]
        store = _Store(events=evs)
        findings = _hunt_beacon(store)
        assert findings == []

    def test_empty_events_returns_empty(self):
        assert _hunt_beacon(_Store(events=[])) == []


# ---------------------------------------------------------------------------
# TestPersistentThreatActor
# ---------------------------------------------------------------------------

class TestPersistentThreatActor:
    def _make_events(self, src_ip, run_count):
        return [
            _Ev(src_ip, "10.0.0.1", "port_scan", f"run-{i}")
            for i in range(run_count)
        ]

    def test_fires_at_threshold(self):
        evs = self._make_events("8.8.4.4", _PERSISTENT_MIN_RUNS)
        store = _Store(events=evs)
        findings = _hunt_persistent_threat_actor(store)
        assert any(f["hunt_type"] == "persistent_threat_actor" for f in findings)

    def test_does_not_fire_below_threshold(self):
        evs = self._make_events("8.8.4.4", _PERSISTENT_MIN_RUNS - 1)
        store = _Store(events=evs)
        findings = _hunt_persistent_threat_actor(store)
        assert findings == []

    def test_private_ips_excluded(self):
        for private in ("10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"):
            evs = self._make_events(private, _PERSISTENT_MIN_RUNS)
            store = _Store(events=evs)
            findings = _hunt_persistent_threat_actor(store)
            assert findings == [], f"Private IP {private} should not trigger finding"

    def test_src_ip_in_finding(self):
        evs = self._make_events("8.8.4.4", _PERSISTENT_MIN_RUNS)
        store = _Store(events=evs)
        findings = _hunt_persistent_threat_actor(store)
        assert findings[0]["src_ip"] == "8.8.4.4"

    def test_evidence_includes_run_ids(self):
        evs = self._make_events("8.8.4.4", _PERSISTENT_MIN_RUNS)
        store = _Store(events=evs)
        findings = _hunt_persistent_threat_actor(store)
        assert "run_ids" in findings[0]["evidence"]
        assert len(findings[0]["evidence"]["run_ids"]) == _PERSISTENT_MIN_RUNS

    def test_alert_count_included_in_evidence(self):
        evs = self._make_events("8.8.4.4", _PERSISTENT_MIN_RUNS)
        alerts = [_Al("8.8.4.4", "10.0.0.1", "scan", 0.5, "run-0")]
        store = _Store(events=evs, alerts=alerts)
        findings = _hunt_persistent_threat_actor(store)
        assert findings[0]["evidence"]["alert_count"] == 1

    def test_empty_events_returns_empty(self):
        assert _hunt_persistent_threat_actor(_Store(events=[])) == []


# ---------------------------------------------------------------------------
# TestHuntEngineIntegration
# ---------------------------------------------------------------------------

class TestHuntEngineIntegration:
    def test_all_four_types_can_fire_simultaneously(self):
        """Populate store with triggers for all four strategies."""
        # Low-and-slow BF
        bf_ip = "1.1.1.1"
        bf_events = [
            _Ev(bf_ip, "10.0.0.1", "auth_failure", f"run-{i}")
            for i in range(_SLOW_BF_MIN_RUNS)
            for _ in range(2)
        ]
        # Beacon
        beacon_events = [
            _Ev("2.2.2.2", "10.0.0.5", "port_scan", f"run-{i}")
            for i in range(_BEACON_MIN_RUNS)
        ]
        # Persistent
        persistent_events = [
            _Ev("3.3.3.3", "10.0.0.1", "port_scan", f"run-{i}")
            for i in range(_PERSISTENT_MIN_RUNS)
        ]
        # Alert cluster
        cluster_alerts = [
            _Al("4.4.4.4", "10.0.0.1", f"type_{i}", 0.4, "run-0")
            for i in range(_CLUSTER_MIN_ALERTS)
        ]

        store = _Store(
            events=bf_events + beacon_events + persistent_events,
            alerts=cluster_alerts,
        )
        findings = HuntEngine().hunt(store)
        hunt_types = {f["hunt_type"] for f in findings}

        assert "low_and_slow_brute_force" in hunt_types
        assert "alert_cluster" in hunt_types
        assert "beacon" in hunt_types
        assert "persistent_threat_actor" in hunt_types

    def test_hunt_id_unique_per_finding(self):
        run_ids = [f"run-{i}" for i in range(_SLOW_BF_MIN_RUNS)]
        evs = [
            _Ev(f"{i}.{i}.{i}.{i}", "10.0.0.1", "auth_failure", run_id)
            for i in range(1, 4)
            for run_id in run_ids
            for _ in range(2)
        ]
        store = _Store(events=evs)
        findings = HuntEngine().hunt(store)
        ids = [f["hunt_id"] for f in findings]
        assert len(ids) == len(set(ids))
