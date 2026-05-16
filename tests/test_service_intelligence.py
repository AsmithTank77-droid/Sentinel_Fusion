"""Tests for intelligence/service_intelligence.py"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.service_intelligence import (
    SERVICE_RISK,
    HIGH_RISK_PORTS,
    DANGEROUS_COMBOS,
    DANGEROUS_SERVICES,
    THREAT_MAP,
    ATTACK_PHASES,
    get_service_risk,
    get_threat,
    get_attack_phases,
    is_high_risk_port,
    check_dangerous_combos,
    enrich_service,
)


# ---------------------------------------------------------------------------
# SERVICE_RISK
# ---------------------------------------------------------------------------

class TestServiceRisk:
    def test_rdp_is_highest_risk(self):
        assert get_service_risk("rdp") == 9

    def test_telnet_is_highest_risk(self):
        assert get_service_risk("telnet") == 9

    def test_smb_is_high_risk(self):
        assert get_service_risk("smb") >= 7

    def test_https_lower_than_http(self):
        assert get_service_risk("https") <= get_service_risk("http")

    def test_ntp_is_low(self):
        assert get_service_risk("ntp") <= 3

    def test_unknown_service_returns_default(self):
        assert get_service_risk("totally_unknown_svc_xyz") == SERVICE_RISK["unknown"]

    def test_case_insensitive(self):
        assert get_service_risk("SSH") == get_service_risk("ssh")

    def test_all_scores_in_range(self):
        for svc, score in SERVICE_RISK.items():
            assert 0 <= score <= 10, f"{svc}: {score} out of range"

    def test_database_services_are_high_risk(self):
        for svc in ("mysql", "postgresql", "mssql", "redis", "mongodb"):
            assert get_service_risk(svc) >= 7, f"{svc} should be high risk"

    def test_remote_access_services_are_high_risk(self):
        for svc in ("rdp", "telnet", "vnc"):
            assert get_service_risk(svc) >= 7


# ---------------------------------------------------------------------------
# HIGH_RISK_PORTS
# ---------------------------------------------------------------------------

class TestHighRiskPorts:
    def test_rdp_port_3389_is_high_risk(self):
        assert is_high_risk_port(3389)

    def test_smb_port_445_is_high_risk(self):
        assert is_high_risk_port(445)

    def test_telnet_port_23_is_high_risk(self):
        assert is_high_risk_port(23)

    def test_mssql_port_1433_is_high_risk(self):
        assert is_high_risk_port(1433)

    def test_mysql_port_3306_is_high_risk(self):
        assert is_high_risk_port(3306)

    def test_redis_port_6379_is_high_risk(self):
        assert is_high_risk_port(6379)

    def test_http_port_80_not_high_risk(self):
        assert not is_high_risk_port(80)

    def test_https_port_443_not_high_risk(self):
        assert not is_high_risk_port(443)

    def test_random_port_not_high_risk(self):
        assert not is_high_risk_port(54321)

    def test_high_risk_ports_dict_non_empty(self):
        assert len(HIGH_RISK_PORTS) >= 10


# ---------------------------------------------------------------------------
# DANGEROUS_COMBOS / check_dangerous_combos
# ---------------------------------------------------------------------------

class TestDangerousCombos:
    def test_smb_rdp_is_dangerous(self):
        result = check_dangerous_combos({"smb", "rdp"})
        assert len(result) >= 1
        assert any("SMB" in r and "RDP" in r for r in result)

    def test_ssh_ftp_is_dangerous(self):
        result = check_dangerous_combos({"ssh", "ftp"})
        assert len(result) >= 1

    def test_http_mysql_is_dangerous(self):
        result = check_dangerous_combos({"http", "mysql"})
        assert len(result) >= 1

    def test_safe_services_return_no_combos(self):
        assert check_dangerous_combos({"ntp", "domain"}) == []

    def test_single_service_no_combo(self):
        assert check_dangerous_combos({"rdp"}) == []

    def test_empty_set_no_combo(self):
        assert check_dangerous_combos(set()) == []

    def test_all_dangerous_services_triggers_multiple_combos(self):
        all_svcs = {"smb", "rdp", "ssh", "ftp", "mysql", "http", "mssql", "vnc", "telnet"}
        result = check_dangerous_combos(all_svcs)
        assert len(result) >= 3

    def test_returns_list_of_strings(self):
        result = check_dangerous_combos({"smb", "rdp"})
        assert all(isinstance(r, str) for r in result)

    def test_dangerous_combos_list_non_empty(self):
        assert len(DANGEROUS_COMBOS) >= 5

    def test_each_combo_entry_has_frozenset_and_string(self):
        for combo, label in DANGEROUS_COMBOS:
            assert isinstance(combo, frozenset)
            assert isinstance(label, str)
            assert len(label) > 0


# ---------------------------------------------------------------------------
# THREAT_MAP / get_threat
# ---------------------------------------------------------------------------

class TestThreatMap:
    def test_ssh_has_threat_description(self):
        result = get_threat("ssh")
        assert result is not None
        assert len(result) > 0

    def test_rdp_has_threat_description(self):
        result = get_threat("rdp")
        assert result is not None
        assert "ransomware" in result.lower() or "credential" in result.lower()

    def test_smb_mentions_cve(self):
        result = get_threat("smb")
        assert result is not None
        assert "CVE" in result

    def test_mysql_has_threat(self):
        assert get_threat("mysql") is not None

    def test_unknown_service_returns_none(self):
        assert get_threat("totally_unknown_xyz") is None

    def test_case_insensitive(self):
        assert get_threat("SSH") == get_threat("ssh")

    def test_all_threat_map_values_are_strings(self):
        for svc, threat in THREAT_MAP.items():
            assert isinstance(threat, str), f"{svc} threat is not a string"
            assert len(threat) > 10, f"{svc} threat description too short"

    def test_at_least_15_services_have_threats(self):
        assert len(THREAT_MAP) >= 15


# ---------------------------------------------------------------------------
# get_attack_phases
# ---------------------------------------------------------------------------

class TestAttackPhases:
    def test_ssh_has_attack_phases(self):
        phases = get_attack_phases("ssh")
        assert isinstance(phases, list)
        assert len(phases) > 0

    def test_smb_includes_lateral_movement(self):
        phases = get_attack_phases("smb")
        assert any("Lateral" in p for p in phases)

    def test_unknown_service_returns_empty_list(self):
        assert get_attack_phases("totally_unknown_xyz") == []

    def test_rdp_includes_initial_access(self):
        phases = get_attack_phases("rdp")
        assert any("Initial Access" in p for p in phases)

    def test_returns_list(self):
        assert isinstance(get_attack_phases("http"), list)


# ---------------------------------------------------------------------------
# enrich_service
# ---------------------------------------------------------------------------

class TestEnrichService:
    def test_returns_dict(self):
        result = enrich_service("ssh", 22)
        assert isinstance(result, dict)

    def test_required_keys_present(self):
        result = enrich_service("rdp", 3389)
        required = {"service", "port", "risk_score", "is_high_risk_port", "threat", "attack_phases"}
        assert required.issubset(set(result.keys()))

    def test_service_name_lowercased(self):
        result = enrich_service("RDP", 3389)
        assert result["service"] == "rdp"

    def test_port_echoed(self):
        result = enrich_service("ssh", 22)
        assert result["port"] == 22

    def test_risk_score_in_range(self):
        for svc, port in [("ssh", 22), ("rdp", 3389), ("http", 80), ("unknown_svc", 9999)]:
            result = enrich_service(svc, port)
            assert 0 <= result["risk_score"] <= 10

    def test_high_risk_port_flagged(self):
        result = enrich_service("rdp", 3389)
        assert result["is_high_risk_port"] is True

    def test_non_high_risk_port_not_flagged(self):
        result = enrich_service("http", 80)
        assert result["is_high_risk_port"] is False

    def test_known_service_has_threat(self):
        result = enrich_service("smb", 445)
        assert result["threat"] is not None

    def test_unknown_service_threat_is_none(self):
        result = enrich_service("totally_unknown_xyz", 9999)
        assert result["threat"] is None

    def test_attack_phases_is_list(self):
        result = enrich_service("ssh", 22)
        assert isinstance(result["attack_phases"], list)
