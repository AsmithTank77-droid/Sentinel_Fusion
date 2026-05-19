"""Tests for detection/sigma_field_mapper.py."""

import copy
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from detection.sigma_field_mapper import SIGMA_FIELD_MAP, map_event

# All ten Sigma fields the mapper must expose.
EXPECTED_SIGMA_FIELDS = {
    "EventID",
    "CommandLine",
    "Image",
    "DestinationIp",
    "SourceIp",
    "LogonType",
    "SubjectUserName",
    "TargetUserName",
    "ParentImage",
    "DestinationPort",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def winlog_auth_event():
    """Typical authentication_failure event from the winlog normalizer."""
    return {
        "timestamp": "2026-01-15T10:00:00Z",
        "source_type": "winlog",
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.5",
        "event_type": "authentication_failure",
        "severity": 5,
        "metadata": {
            "event_id": 4625,
            "logon_type": "3",
            "target_user": "administrator",
            "subject_user": "SYSTEM",
        },
    }


@pytest.fixture
def process_creation_event():
    """process_creation event (EventID 4688) with full process fields."""
    return {
        "timestamp": "2026-01-15T10:05:00Z",
        "source_type": "winlog",
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.5",
        "event_type": "process_creation",
        "severity": 2,
        "metadata": {
            "event_id": 4688,
            "command_line": "cmd.exe /c whoami",
            "image": "C:\\Windows\\System32\\cmd.exe",
            "parent_image": "C:\\Windows\\explorer.exe",
            "subject_user": "jdoe",
            "target_user": None,
            "logon_type": None,
            "dst_port": None,
        },
    }


@pytest.fixture
def nra_event():
    """NRA port-scan event with a destination port in metadata."""
    return {
        "timestamp": "2026-01-15T09:00:00Z",
        "source_type": "nra",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.20",
        "event_type": "port_scan",
        "severity": 5,
        "metadata": {
            "dst_port": 22,
            "ports": [{"port": 22, "service": "ssh", "state": "open"}],
        },
    }


@pytest.fixture
def minimal_event():
    """Minimal event with an empty metadata dict — no winlog-specific fields."""
    return {
        "timestamp": "2026-01-15T09:00:00Z",
        "source_type": "mock",
        "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8",
        "event_type": "simulated_event",
        "severity": 1,
        "metadata": {},
    }


# ---------------------------------------------------------------------------
# Mapping dict completeness
# ---------------------------------------------------------------------------

class TestSigmaFieldMapCompleteness:
    def test_all_expected_fields_present(self):
        assert set(SIGMA_FIELD_MAP.keys()) == EXPECTED_SIGMA_FIELDS

    def test_field_count(self):
        assert len(SIGMA_FIELD_MAP) == 10

    def test_all_paths_are_non_empty_strings(self):
        for sigma_name, path in SIGMA_FIELD_MAP.items():
            assert isinstance(path, str) and path, (
                f"Path for {sigma_name!r} must be a non-empty string"
            )

    def test_no_duplicate_paths(self):
        paths = list(SIGMA_FIELD_MAP.values())
        assert len(paths) == len(set(paths)), "Each Sigma field must map to a distinct path"

    def test_top_level_fields_have_no_dot(self):
        assert "." not in SIGMA_FIELD_MAP["SourceIp"]
        assert "." not in SIGMA_FIELD_MAP["DestinationIp"]

    def test_metadata_fields_use_dot_notation(self):
        metadata_fields = [k for k, v in SIGMA_FIELD_MAP.items() if v.startswith("metadata.")]
        assert len(metadata_fields) == 8

    def test_source_ip_maps_to_src_ip(self):
        assert SIGMA_FIELD_MAP["SourceIp"] == "src_ip"

    def test_destination_ip_maps_to_dst_ip(self):
        assert SIGMA_FIELD_MAP["DestinationIp"] == "dst_ip"

    def test_event_id_maps_to_metadata_event_id(self):
        assert SIGMA_FIELD_MAP["EventID"] == "metadata.event_id"

    def test_logon_type_maps_to_metadata_logon_type(self):
        assert SIGMA_FIELD_MAP["LogonType"] == "metadata.logon_type"


# ---------------------------------------------------------------------------
# map_event: output structure
# ---------------------------------------------------------------------------

class TestMapEventStructure:
    def test_all_sigma_fields_present_in_output(self, winlog_auth_event):
        result = map_event(winlog_auth_event)
        for sigma_name in SIGMA_FIELD_MAP:
            assert sigma_name in result, f"Sigma field {sigma_name!r} missing from output"

    def test_original_top_level_fields_preserved(self, winlog_auth_event):
        result = map_event(winlog_auth_event)
        for key in ("timestamp", "source_type", "src_ip", "dst_ip", "event_type", "severity", "metadata"):
            assert key in result

    def test_returns_deep_copy_not_reference(self, winlog_auth_event):
        result = map_event(winlog_auth_event)
        result["metadata"]["event_id"] = 9999
        assert winlog_auth_event["metadata"]["event_id"] == 4625

    def test_does_not_mutate_input(self, winlog_auth_event):
        original = copy.deepcopy(winlog_auth_event)
        map_event(winlog_auth_event)
        assert winlog_auth_event == original

    def test_sigma_fields_are_top_level_not_nested(self, winlog_auth_event):
        result = map_event(winlog_auth_event)
        metadata = result.get("metadata", {})
        for sigma_name in SIGMA_FIELD_MAP:
            assert sigma_name in result, f"{sigma_name!r} must be a top-level key"
            assert sigma_name not in metadata, f"{sigma_name!r} must not be injected into metadata"


# ---------------------------------------------------------------------------
# map_event: known inputs and expected outputs
# ---------------------------------------------------------------------------

class TestMapEventKnownOutputs:
    def test_source_ip(self, winlog_auth_event):
        assert map_event(winlog_auth_event)["SourceIp"] == "192.168.1.10"

    def test_destination_ip(self, winlog_auth_event):
        assert map_event(winlog_auth_event)["DestinationIp"] == "10.0.0.5"

    def test_event_id_from_metadata(self, winlog_auth_event):
        assert map_event(winlog_auth_event)["EventID"] == 4625

    def test_logon_type(self, winlog_auth_event):
        assert map_event(winlog_auth_event)["LogonType"] == "3"

    def test_target_user_name(self, winlog_auth_event):
        assert map_event(winlog_auth_event)["TargetUserName"] == "administrator"

    def test_subject_user_name(self, winlog_auth_event):
        assert map_event(winlog_auth_event)["SubjectUserName"] == "SYSTEM"

    def test_command_line(self, process_creation_event):
        assert map_event(process_creation_event)["CommandLine"] == "cmd.exe /c whoami"

    def test_image(self, process_creation_event):
        assert map_event(process_creation_event)["Image"] == "C:\\Windows\\System32\\cmd.exe"

    def test_parent_image(self, process_creation_event):
        assert map_event(process_creation_event)["ParentImage"] == "C:\\Windows\\explorer.exe"

    def test_destination_port_from_metadata(self, nra_event):
        assert map_event(nra_event)["DestinationPort"] == 22

    def test_nra_event_null_winlog_fields(self, nra_event):
        result = map_event(nra_event)
        assert result["EventID"] is None
        assert result["CommandLine"] is None
        assert result["LogonType"] is None
        assert result["SubjectUserName"] is None
        assert result["TargetUserName"] is None

    def test_process_event_src_and_dst_ip(self, process_creation_event):
        result = map_event(process_creation_event)
        assert result["SourceIp"] == "192.168.1.10"
        assert result["DestinationIp"] == "10.0.0.5"
        assert result["EventID"] == 4688


# ---------------------------------------------------------------------------
# Edge cases: missing or null fields
# ---------------------------------------------------------------------------

class TestMapEventEdgeCases:
    def test_all_metadata_fields_missing_return_none(self, minimal_event):
        result = map_event(minimal_event)
        for sigma_name, path in SIGMA_FIELD_MAP.items():
            if path.startswith("metadata."):
                assert result[sigma_name] is None, (
                    f"{sigma_name!r} should be None when metadata key is absent"
                )

    def test_null_metadata_value_returns_none(self, process_creation_event):
        result = map_event(process_creation_event)
        assert result["LogonType"] is None
        assert result["TargetUserName"] is None
        assert result["DestinationPort"] is None

    def test_metadata_key_absent_entirely(self):
        event = {
            "timestamp": "2026-01-15T09:00:00Z",
            "source_type": "mock",
            "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8",
            "event_type": "simulated_event",
            "severity": 1,
        }
        result = map_event(event)
        assert result["EventID"] is None
        assert result["SourceIp"] == "1.2.3.4"
        assert result["DestinationIp"] == "5.6.7.8"

    def test_non_dict_metadata_returns_none_for_nested_fields(self):
        event = {
            "timestamp": "2026-01-15T09:00:00Z",
            "source_type": "mock",
            "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8",
            "event_type": "simulated_event",
            "severity": 1,
            "metadata": "malformed-string",
        }
        result = map_event(event)
        assert result["EventID"] is None
        assert result["CommandLine"] is None
        assert result["LogonType"] is None

    def test_empty_string_ip_preserved(self):
        event = {
            "timestamp": "2026-01-15T09:00:00Z",
            "source_type": "mock",
            "src_ip": "",
            "dst_ip": "",
            "event_type": "simulated_event",
            "severity": 1,
            "metadata": {},
        }
        result = map_event(event)
        assert result["SourceIp"] == ""
        assert result["DestinationIp"] == ""

    def test_zero_event_id_preserved(self):
        event = {
            "timestamp": "2026-01-15T09:00:00Z",
            "source_type": "winlog",
            "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8",
            "event_type": "winlog_event_0",
            "severity": 1,
            "metadata": {"event_id": 0},
        }
        assert map_event(event)["EventID"] == 0

    def test_zero_destination_port_preserved(self):
        event = {
            "timestamp": "2026-01-15T09:00:00Z",
            "source_type": "nra",
            "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8",
            "event_type": "port_scan",
            "severity": 1,
            "metadata": {"dst_port": 0},
        }
        assert map_event(event)["DestinationPort"] == 0

    def test_multiple_calls_are_independent(self, winlog_auth_event, nra_event):
        r1 = map_event(winlog_auth_event)
        r2 = map_event(nra_event)
        assert r1["EventID"] == 4625
        assert r2["EventID"] is None
        assert r1["SourceIp"] != r2["SourceIp"]
