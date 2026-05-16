"""Tests for intelligence/event_intelligence.py"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.event_intelligence import (
    EVENT_KNOWLEDGE,
    SEVERITY_ORDER,
    CATEGORIES,
    get_event,
    is_known,
)


# ---------------------------------------------------------------------------
# get_event — known event IDs
# ---------------------------------------------------------------------------

class TestGetEventKnown:
    def test_4624_successful_logon(self):
        result = get_event(4624)
        assert result["name"] == "Successful Logon"
        assert result["category"] == "authentication"
        assert result["mitre_technique"] == "T1078"

    def test_4625_failed_logon(self):
        result = get_event(4625)
        assert result["name"] == "Failed Logon"
        assert result["category"] == "authentication"
        assert result["mitre_technique"] == "T1110"

    def test_1102_audit_log_cleared(self):
        result = get_event(1102)
        assert result["severity"] == "critical"
        assert result["category"] == "defense_evasion"
        assert "T1070" in result["mitre_technique"]

    def test_4672_special_privileges(self):
        result = get_event(4672)
        assert result["category"] == "privilege_escalation"

    def test_4720_account_created(self):
        result = get_event(4720)
        assert result["category"] == "persistence"
        assert "T1136" in result["mitre_technique"]

    def test_4698_scheduled_task_created(self):
        result = get_event(4698)
        assert result["category"] == "persistence"
        assert result["severity"] == "high"

    def test_7045_new_service(self):
        result = get_event(7045)
        assert result["category"] == "persistence"
        assert "T1543" in result["mitre_technique"]

    def test_4719_audit_policy_changed(self):
        result = get_event(4719)
        assert result["severity"] == "high"
        assert result["category"] == "defense_evasion"

    def test_4688_process_created(self):
        result = get_event(4688)
        assert result["category"] == "execution"

    def test_4104_powershell_logging(self):
        result = get_event(4104)
        assert result["severity"] == "high"
        assert "T1059.001" in result["mitre_technique"]

    def test_wmi_subscription_binding_is_critical(self):
        result = get_event(21)
        assert result["severity"] == "critical"

    def test_analyst_note_present(self):
        result = get_event(4625)
        assert isinstance(result["analyst_note"], str)
        assert len(result["analyst_note"]) > 0

    def test_description_present(self):
        for event_id in (4624, 4625, 4672, 1102):
            result = get_event(event_id)
            assert isinstance(result["description"], str)
            assert len(result["description"]) > 0


# ---------------------------------------------------------------------------
# get_event — unknown event IDs
# ---------------------------------------------------------------------------

class TestGetEventUnknown:
    def test_unknown_id_returns_dict(self):
        result = get_event(99999)
        assert isinstance(result, dict)

    def test_unknown_id_name_contains_id(self):
        result = get_event(99999)
        assert "99999" in result["name"]

    def test_unknown_id_category_is_unknown(self):
        assert get_event(99999)["category"] == "unknown"

    def test_unknown_id_mitre_is_na(self):
        assert get_event(99999)["mitre_technique"] == "N/A"

    def test_unknown_id_severity_is_info(self):
        assert get_event(99999)["severity"] == "info"

    def test_zero_event_id_returns_dict(self):
        assert isinstance(get_event(0), dict)

    def test_required_keys_always_present(self):
        required = {"name", "category", "severity", "mitre_technique",
                    "mitre_name", "description", "analyst_note"}
        for eid in (4624, 4625, 9999, 0):
            assert required.issubset(set(get_event(eid).keys()))


# ---------------------------------------------------------------------------
# is_known
# ---------------------------------------------------------------------------

class TestIsKnown:
    def test_4624_is_known(self):
        assert is_known(4624) is True

    def test_4625_is_known(self):
        assert is_known(4625) is True

    def test_1102_is_known(self):
        assert is_known(1102) is True

    def test_7045_is_known(self):
        assert is_known(7045) is True

    def test_unknown_id_not_known(self):
        assert is_known(99999) is False

    def test_zero_not_known(self):
        assert is_known(0) is False


# ---------------------------------------------------------------------------
# EVENT_KNOWLEDGE — structural integrity
# ---------------------------------------------------------------------------

class TestEventKnowledgeIntegrity:
    _REQUIRED_KEYS = {"name", "category", "severity", "mitre_technique",
                      "mitre_name", "description", "analyst_note"}

    def test_all_entries_have_required_keys(self):
        for eid, record in EVENT_KNOWLEDGE.items():
            missing = self._REQUIRED_KEYS - set(record.keys())
            assert not missing, f"Event {eid} missing keys: {missing}"

    def test_all_severities_are_valid(self):
        valid = {"critical", "high", "medium", "low", "info"}
        for eid, record in EVENT_KNOWLEDGE.items():
            assert record["severity"] in valid, f"Event {eid} has invalid severity"

    def test_all_categories_are_valid(self):
        valid = CATEGORIES | {"unknown"}
        for eid, record in EVENT_KNOWLEDGE.items():
            assert record["category"] in valid, f"Event {eid} category {record['category']!r} not in CATEGORIES"

    def test_all_event_ids_are_integers(self):
        for eid in EVENT_KNOWLEDGE:
            assert isinstance(eid, int)

    def test_mitre_techniques_non_empty(self):
        for eid, record in EVENT_KNOWLEDGE.items():
            assert record["mitre_technique"], f"Event {eid} has empty mitre_technique"

    def test_at_least_30_events_defined(self):
        assert len(EVENT_KNOWLEDGE) >= 30

    def test_critical_events_include_1102(self):
        critical = [eid for eid, r in EVENT_KNOWLEDGE.items() if r["severity"] == "critical"]
        assert 1102 in critical

    def test_persistence_events_include_4720(self):
        persistence = [eid for eid, r in EVENT_KNOWLEDGE.items() if r["category"] == "persistence"]
        assert 4720 in persistence


# ---------------------------------------------------------------------------
# SEVERITY_ORDER
# ---------------------------------------------------------------------------

class TestSeverityOrder:
    def test_critical_highest(self):
        assert SEVERITY_ORDER["critical"] > SEVERITY_ORDER["high"]

    def test_high_above_medium(self):
        assert SEVERITY_ORDER["high"] > SEVERITY_ORDER["medium"]

    def test_medium_above_low(self):
        assert SEVERITY_ORDER["medium"] > SEVERITY_ORDER["low"]

    def test_low_above_info(self):
        assert SEVERITY_ORDER["low"] > SEVERITY_ORDER["info"]

    def test_info_is_zero(self):
        assert SEVERITY_ORDER["info"] == 0
