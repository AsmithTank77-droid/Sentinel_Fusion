"""Tests for core/pipeline/winlog_parser.py"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import textwrap
import xml.etree.ElementTree as ET

from core.pipeline.winlog_parser import (
    _parse_record,
    _parse_timestamp,
    _extract_event_data,
    _safe_int,
    _text,
    _attr,
    parse_evtx,
    _EVTX_AVAILABLE,
)


# ---------------------------------------------------------------------------
# _parse_timestamp
# ---------------------------------------------------------------------------

class TestParseTimestamp:
    def test_standard_format(self):
        ts, epoch = _parse_timestamp("2026-05-09T10:30:00.123456Z")
        assert "2026-05-09" in ts
        assert epoch > 0

    def test_fractional_seconds_truncated_correctly(self):
        ts, epoch = _parse_timestamp("2026-05-09T10:30:00.1Z")
        assert epoch > 0

    def test_unrecognised_format_returns_raw(self):
        ts, epoch = _parse_timestamp("not-a-timestamp")
        assert ts == "not-a-timestamp"
        assert epoch == 0.0

    def test_empty_string_returns_empty(self):
        ts, epoch = _parse_timestamp("")
        assert ts == ""
        assert epoch == 0.0

    def test_epoch_is_float(self):
        _, epoch = _parse_timestamp("2026-05-09T10:30:00.000000Z")
        assert isinstance(epoch, float)

    def test_iso_format_output(self):
        ts, _ = _parse_timestamp("2026-05-09T10:30:00.000000Z")
        assert "T" in ts


# ---------------------------------------------------------------------------
# _safe_int
# ---------------------------------------------------------------------------

class TestSafeInt:
    def test_string_digit(self):
        assert _safe_int("3") == 3

    def test_integer_passthrough(self):
        assert _safe_int(5) == 5

    def test_none_returns_none(self):
        assert _safe_int(None) is None

    def test_non_numeric_string_returns_none(self):
        assert _safe_int("abc") is None

    def test_float_string_returns_none(self):
        assert _safe_int("3.5") is None


# ---------------------------------------------------------------------------
# _parse_record — using synthetic XML
# ---------------------------------------------------------------------------

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _make_event_xml(event_id: int = 4625,
                    time: str = "2026-05-09T10:00:00.000000Z",
                    computer: str = "DC01",
                    provider: str = "Microsoft-Windows-Security-Auditing",
                    channel: str = "Security",
                    extra_data: dict | None = None) -> str:
    data_items = ""
    for k, v in (extra_data or {}).items():
        data_items += f'<Data Name="{k}">{v}</Data>\n'
    return textwrap.dedent(f"""\
        <Event xmlns="{_NS}">
          <System>
            <Provider Name="{provider}"/>
            <EventID>{event_id}</EventID>
            <TimeCreated SystemTime="{time}"/>
            <Computer>{computer}</Computer>
            <Channel>{channel}</Channel>
          </System>
          <EventData>
            {data_items}
          </EventData>
        </Event>
    """)


class TestParseRecord:
    def test_basic_event_returns_dict(self):
        result = _parse_record(_make_event_xml())
        assert isinstance(result, dict)

    def test_event_id_extracted(self):
        result = _parse_record(_make_event_xml(event_id=4625))
        assert result["event_id"] == 4625

    def test_computer_extracted(self):
        result = _parse_record(_make_event_xml(computer="WORKSTATION01"))
        assert result["computer"] == "WORKSTATION01"

    def test_provider_extracted(self):
        result = _parse_record(_make_event_xml(provider="Microsoft-Windows-Security-Auditing"))
        assert result["provider"] == "Microsoft-Windows-Security-Auditing"

    def test_channel_extracted(self):
        result = _parse_record(_make_event_xml(channel="Security"))
        assert result["channel"] == "Security"

    def test_timestamp_is_string(self):
        result = _parse_record(_make_event_xml())
        assert isinstance(result["timestamp"], str)

    def test_timestamp_epoch_is_float(self):
        result = _parse_record(_make_event_xml())
        assert isinstance(result["timestamp_epoch"], float)

    def test_src_ip_from_event_data(self):
        result = _parse_record(_make_event_xml(extra_data={"IpAddress": "192.168.1.100"}))
        assert result["src_ip"] == "192.168.1.100"

    def test_target_user_from_event_data(self):
        result = _parse_record(_make_event_xml(extra_data={"TargetUserName": "jdoe"}))
        assert result["target_user"] == "jdoe"

    def test_logon_type_from_event_data(self):
        result = _parse_record(_make_event_xml(extra_data={"LogonType": "3"}))
        assert result["logon_type"] == 3

    def test_logon_type_none_when_absent(self):
        result = _parse_record(_make_event_xml())
        assert result["logon_type"] is None

    def test_required_keys_always_present(self):
        result = _parse_record(_make_event_xml())
        required = {
            "event_id", "timestamp", "timestamp_epoch", "computer",
            "provider", "channel", "subject_user", "target_user",
            "target_domain", "src_ip", "source_port", "logon_type",
            "process_name", "command_line", "service_name", "task_name",
            "group_name", "raw_data",
        }
        assert required.issubset(set(result.keys()))

    def test_raw_data_is_dict(self):
        result = _parse_record(_make_event_xml(extra_data={"IpAddress": "10.0.0.1"}))
        assert isinstance(result["raw_data"], dict)

    def test_malformed_xml_returns_none(self):
        assert _parse_record("<unclosed>") is None

    def test_missing_system_element_returns_none(self):
        xml = f'<Event xmlns="{_NS}"><EventData/></Event>'
        assert _parse_record(xml) is None

    def test_service_name_from_event_data(self):
        result = _parse_record(_make_event_xml(extra_data={"ServiceName": "evilsvc"}))
        assert result["service_name"] == "evilsvc"

    def test_task_name_from_event_data(self):
        result = _parse_record(_make_event_xml(extra_data={"TaskName": "\\evil_task"}))
        assert result["task_name"] == "\\evil_task"

    def test_subject_user_from_event_data(self):
        result = _parse_record(_make_event_xml(extra_data={"SubjectUserName": "administrator"}))
        assert result["subject_user"] == "administrator"


# ---------------------------------------------------------------------------
# parse_evtx — error handling (python-evtx not installed in test env)
# ---------------------------------------------------------------------------

class TestParseEvtxErrors:
    def test_non_evtx_extension_raises_value_error(self, tmp_path):
        f = tmp_path / "events.log"
        f.write_text("dummy")
        with pytest.raises(ValueError, match=".evtx"):
            parse_evtx(str(f))

    def test_missing_file_raises_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_evtx("/tmp/does_not_exist_xyzzy.evtx")

    def test_evtx_without_library_raises_import_error(self, tmp_path):
        if _EVTX_AVAILABLE:
            pytest.skip("python-evtx is installed; skipping ImportError test")
        f = tmp_path / "test.evtx"
        f.write_bytes(b"\x00" * 8)
        with pytest.raises(ImportError, match="python-evtx"):
            parse_evtx(str(f))
