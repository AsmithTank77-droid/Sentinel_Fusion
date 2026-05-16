"""Tests for core/pipeline/normalize.py — Stage 2: Normalization."""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pipeline.normalize import Normalizer, NormalizedEvent


# ---------------------------------------------------------------------------
# NormalizedEvent
# ---------------------------------------------------------------------------

class TestNormalizedEvent:
    def test_valid_construction(self):
        ev = NormalizedEvent(
            timestamp="2026-05-09T02:14:00Z",
            source_type="nra",
            src_ip="1.2.3.4",
            dst_ip="10.0.0.5",
            event_type="port_scan",
            severity=8,
            metadata={},
        )
        assert ev.source_type == "nra"
        assert ev.severity == 8

    def test_invalid_source_type_raises(self):
        with pytest.raises(ValueError, match="source_type"):
            NormalizedEvent("ts", "syslog", "", "", "x", 1, {})

    def test_severity_out_of_range_raises(self):
        with pytest.raises(TypeError, match="severity"):
            NormalizedEvent("ts", "nra", "", "", "x", 11, {})

    def test_severity_negative_raises(self):
        with pytest.raises(TypeError):
            NormalizedEvent("ts", "nra", "", "", "x", -1, {})

    def test_metadata_must_be_dict(self):
        with pytest.raises(TypeError, match="metadata"):
            NormalizedEvent("ts", "nra", "", "", "x", 1, "not-a-dict")

    def test_to_dict_round_trip(self):
        ev = NormalizedEvent(
            timestamp="2026-05-09T02:14:00Z",
            source_type="mock",
            src_ip="185.220.101.45",
            dst_ip="10.0.0.5",
            event_type="lateral_movement",
            severity=8,
            metadata={"key": "val"},
        )
        d = ev.to_dict()
        assert d["timestamp"] == "2026-05-09T02:14:00Z"
        assert d["src_ip"] == "185.220.101.45"
        assert d["metadata"]["key"] == "val"

    def test_to_dict_deep_copies_metadata(self):
        meta = {"nested": {"a": 1}}
        ev = NormalizedEvent("ts", "nra", "", "", "x", 1, meta)
        d = ev.to_dict()
        d["metadata"]["nested"]["a"] = 99
        assert meta["nested"]["a"] == 1  # original unchanged


# ---------------------------------------------------------------------------
# Normalizer._parse_timestamp
# ---------------------------------------------------------------------------

class TestParseTimestamp:
    def setup_method(self):
        self.n = Normalizer()

    def _parse(self, v):
        return self.n._parse_timestamp(v)

    def test_iso_z(self):
        assert self._parse("2026-05-09T02:14:00Z") == "2026-05-09T02:14:00Z"

    def test_iso_no_z(self):
        assert self._parse("2026-05-09T02:14:00") == "2026-05-09T02:14:00Z"

    def test_unix_epoch(self):
        # 2025-05-09T02:14:00Z = 1746756840
        assert self._parse(1746756840) == "2025-05-09T02:14:00Z"

    def test_none_raises(self):
        with pytest.raises(ValueError, match="required"):
            self._parse(None)

    def test_bool_raises(self):
        with pytest.raises(ValueError):
            self._parse(True)

    def test_unparseable_string_raises(self):
        with pytest.raises(ValueError, match="no supported format"):
            self._parse("not-a-date")


# ---------------------------------------------------------------------------
# Normalizer._map_severity
# ---------------------------------------------------------------------------

class TestMapSeverity:
    def setup_method(self):
        self.n = Normalizer()

    def test_string_low(self):
        assert self.n._map_severity("low") == 2

    def test_string_medium(self):
        assert self.n._map_severity("medium") == 5

    def test_string_high(self):
        assert self.n._map_severity("high") == 8

    def test_string_critical(self):
        assert self.n._map_severity("critical") == 10

    def test_string_information(self):
        assert self.n._map_severity("information") == 2

    def test_string_warning(self):
        assert self.n._map_severity("warning") == 5

    def test_string_error(self):
        assert self.n._map_severity("error") == 8

    def test_int_passthrough(self):
        assert self.n._map_severity(7) == 7

    def test_int_clamped_high(self):
        assert self.n._map_severity(15) == 10

    def test_int_clamped_low(self):
        assert self.n._map_severity(-3) == 0

    def test_float_rounded(self):
        assert self.n._map_severity(7.6) == 8

    def test_zero_int_not_inflated(self):
        assert self.n._map_severity(0) == 0

    def test_unknown_string_defaults_to_one(self):
        assert self.n._map_severity("unknown_label") == 1


# ---------------------------------------------------------------------------
# normalize_nra
# ---------------------------------------------------------------------------

class TestNormalizeNra:
    def setup_method(self):
        self.n = Normalizer()

    def _nra(self, **kw):
        return self.n.normalize_nra(kw)

    def test_basic(self):
        ev = self._nra(
            scanner_ip="185.220.101.45",
            host="10.0.0.5",
            scan_time="2026-05-09T02:14:00Z",
            risk_level="high",
        )
        assert isinstance(ev, NormalizedEvent)
        assert ev.source_type == "nra"
        assert ev.src_ip == "185.220.101.45"
        assert ev.dst_ip == "10.0.0.5"
        assert ev.severity == 8
        assert ev.event_type == "port_scan"

    def test_defaults_event_type_to_port_scan(self):
        ev = self._nra(host="10.0.0.1", scan_time="2026-05-09T02:14:00Z")
        assert ev.event_type == "port_scan"

    def test_ip_alias_address(self):
        ev = self._nra(address="10.0.0.1", scan_time="2026-05-09T02:14:00Z")
        assert ev.dst_ip == "10.0.0.1"

    def test_missing_timestamp_raises(self):
        with pytest.raises(ValueError):
            self._nra(host="10.0.0.1")

    def test_severity_zero_not_inflated(self):
        ev = self._nra(host="10.0.0.1", scan_time="2026-05-09T02:14:00Z", severity=0)
        assert ev.severity == 0


# ---------------------------------------------------------------------------
# normalize_winlog
# ---------------------------------------------------------------------------

class TestNormalizeWinlog:
    def setup_method(self):
        self.n = Normalizer()

    def _winlog(self, **kw):
        return self.n.normalize_winlog(kw)

    def test_4625_maps_to_auth_failure(self):
        ev = self._winlog(
            EventID=4625,
            TimeCreated="2026-05-09T02:15:00Z",
            IpAddress="185.220.101.45",
            dst_ip="10.0.0.5",
        )
        assert ev.event_type == "authentication_failure"
        assert ev.severity == 5
        assert ev.src_ip == "185.220.101.45"

    def test_4624_maps_to_auth_success(self):
        ev = self._winlog(
            EventID=4624,
            TimeCreated="2026-05-09T02:20:00Z",
            IpAddress="185.220.101.45",
        )
        assert ev.event_type == "authentication_success"
        assert ev.severity == 2

    def test_event_data_ip_fallback(self):
        ev = self._winlog(
            EventID=4625,
            TimeCreated="2026-05-09T02:15:00Z",
            EventData={"IpAddress": "1.2.3.4", "TargetIpAddress": "10.0.0.5"},
        )
        assert ev.src_ip == "1.2.3.4"
        assert ev.dst_ip == "10.0.0.5"

    def test_non_dict_event_data_ignored(self):
        ev = self._winlog(
            EventID=4624,
            TimeCreated="2026-05-09T02:20:00Z",
            EventData="SYSTEM",
        )
        assert ev.src_ip == ""  # no crash

    def test_unknown_event_id(self):
        ev = self._winlog(EventID=9999, TimeCreated="2026-05-09T02:20:00Z")
        assert ev.event_type == "winlog_event_9999"

    def test_missing_timestamp_raises(self):
        with pytest.raises(ValueError):
            self._winlog(EventID=4624)


# ---------------------------------------------------------------------------
# normalize_mock
# ---------------------------------------------------------------------------

class TestNormalizeMock:
    def setup_method(self):
        self.n = Normalizer()

    def _mock(self, **kw):
        return self.n.normalize_mock(kw)

    def test_basic(self):
        ev = self._mock(
            timestamp="2026-05-09T02:22:00Z",
            src_ip="10.0.0.5",
            dst_ip="10.0.0.10",
            event_type="lateral_movement",
            severity="high",
        )
        assert ev.source_type == "mock"
        assert ev.src_ip == "10.0.0.5"
        assert ev.dst_ip == "10.0.0.10"
        assert ev.event_type == "lateral_movement"
        assert ev.severity == 8

    def test_src_alias(self):
        ev = self._mock(timestamp="2026-05-09T02:22:00Z", src="1.2.3.4", dst="5.6.7.8")
        assert ev.src_ip == "1.2.3.4"
        assert ev.dst_ip == "5.6.7.8"

    def test_type_alias(self):
        ev = self._mock(timestamp="2026-05-09T02:22:00Z", type="simulated")
        assert ev.event_type == "simulated"

    def test_missing_timestamp_raises(self):
        with pytest.raises(ValueError):
            self._mock(src_ip="1.2.3.4")
