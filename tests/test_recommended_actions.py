"""Tests for reporting/recommended_actions.py"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from reporting.recommended_actions import generate_recommendations

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _host(ip="10.0.0.1", risk_level="High", ports=None):
    return {"ip": ip, "risk_level": risk_level, "ports": ports or []}


def _port(port=80, protocol="tcp", service="http", risk="Medium", state="open", flags=None):
    p = {"port": port, "protocol": protocol, "service": service, "risk": risk, "state": state}
    if flags:
        p["flags"] = flags
    return p


_REQUIRED_HOST_KEYS   = {"ip", "overall_risk_level", "overall_host_summary", "recommendations"}
_REQUIRED_REC_KEYS    = {
    "port", "protocol", "service", "category", "subcategory",
    "risk_level", "priority", "service_context", "risk_rationale",
    "action_taken", "enumeration_steps", "hardening_checks", "notable_cves", "flags",
}


# ---------------------------------------------------------------------------
# Empty / edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_empty_input_returns_empty_list(self):
        assert generate_recommendations([]) == []

    def test_no_port_host_returns_summary_with_no_port_data(self):
        result = generate_recommendations([_host(ports=[])])
        assert len(result) == 1
        host = result[0]
        assert host["recommendations"] == []
        assert "no port data" in host["overall_host_summary"].lower()

    def test_no_port_host_preserves_ip_and_risk_level(self):
        result = generate_recommendations([_host(ip="192.168.1.1", risk_level="Low", ports=[])])
        assert result[0]["ip"] == "192.168.1.1"
        assert result[0]["overall_risk_level"] == "Low"


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------

class TestOutputSchema:

    def test_host_output_has_required_keys(self):
        result = generate_recommendations([_host(ports=[_port()])])
        assert _REQUIRED_HOST_KEYS.issubset(result[0].keys())

    def test_recommendation_has_required_keys(self):
        result = generate_recommendations([_host(ports=[_port(service="rdp", risk="Critical")])])
        rec = result[0]["recommendations"][0]
        assert _REQUIRED_REC_KEYS.issubset(rec.keys())

    def test_enumeration_steps_is_list(self):
        result = generate_recommendations([_host(ports=[_port()])])
        assert isinstance(result[0]["recommendations"][0]["enumeration_steps"], list)

    def test_hardening_checks_is_list(self):
        result = generate_recommendations([_host(ports=[_port()])])
        assert isinstance(result[0]["recommendations"][0]["hardening_checks"], list)


# ---------------------------------------------------------------------------
# Priority and risk label mapping
# ---------------------------------------------------------------------------

class TestPriorityMapping:

    @pytest.mark.parametrize("risk_level,expected_priority", [
        ("Critical",      1),
        ("High",          2),
        ("Medium",        3),
        ("Low",           4),
        ("Informational", 5),
    ])
    def test_priority_matches_risk_level(self, risk_level, expected_priority):
        result = generate_recommendations([
            _host(ports=[_port(service="ssh", risk=risk_level)])
        ])
        assert result[0]["recommendations"][0]["priority"] == expected_priority

    def test_critical_rdp_has_priority_1(self):
        result = generate_recommendations([
            _host(ports=[_port(port=3389, service="rdp", risk="Critical")])
        ])
        assert result[0]["recommendations"][0]["priority"] == 1


# ---------------------------------------------------------------------------
# Sort order
# ---------------------------------------------------------------------------

class TestSortOrder:

    def test_sorted_by_priority_ascending(self):
        ports = [
            _port(port=80,   service="http",  risk="Low"),
            _port(port=3389, service="rdp",   risk="Critical"),
            _port(port=22,   service="ssh",   risk="High"),
        ]
        result = generate_recommendations([_host(ports=ports)])
        priorities = [r["priority"] for r in result[0]["recommendations"]]
        assert priorities == sorted(priorities)

    def test_port_number_is_tiebreaker(self):
        ports = [
            _port(port=445, service="smb", risk="High"),
            _port(port=21,  service="ftp", risk="High"),
        ]
        result = generate_recommendations([_host(ports=ports)])
        port_nums = [r["port"] for r in result[0]["recommendations"]]
        assert port_nums == [21, 445]


# ---------------------------------------------------------------------------
# Service context and SOC content
# ---------------------------------------------------------------------------

class TestServiceContext:

    def test_known_service_rdp_has_service_context(self):
        result = generate_recommendations([
            _host(ports=[_port(port=3389, service="rdp", risk="Critical")])
        ])
        ctx = result[0]["recommendations"][0]["service_context"]
        assert isinstance(ctx, str) and len(ctx) > 20

    def test_rdp_service_context_mentions_ransomware(self):
        result = generate_recommendations([
            _host(ports=[_port(port=3389, service="rdp", risk="Critical")])
        ])
        ctx = result[0]["recommendations"][0]["service_context"].lower()
        assert "ransomware" in ctx

    def test_unknown_service_falls_back_to_unknown_context(self):
        result = generate_recommendations([
            _host(ports=[_port(port=9999, service="xyzunknownproto", risk="Medium")])
        ])
        rec = result[0]["recommendations"][0]
        assert rec["service"] == "xyzunknownproto" or rec["service"] == "unknown"
        assert "identified" in rec["service_context"].lower() or "unclassified" in rec["service_context"].lower()

    def test_action_taken_differs_by_risk_level(self):
        low_result = generate_recommendations([
            _host(ports=[_port(service="ssh", risk="Low")])
        ])
        crit_result = generate_recommendations([
            _host(ports=[_port(service="ssh", risk="Critical")])
        ])
        low_action  = low_result[0]["recommendations"][0]["action_taken"]
        crit_action = crit_result[0]["recommendations"][0]["action_taken"]
        assert low_action != crit_action


# ---------------------------------------------------------------------------
# Alias resolution
# ---------------------------------------------------------------------------

class TestAliasResolution:

    def test_microsoft_ds_resolves_to_smb(self):
        result = generate_recommendations([
            _host(ports=[_port(port=445, service="microsoft-ds", risk="High")])
        ])
        assert result[0]["recommendations"][0]["service"] == "smb"

    def test_ms_wbt_server_resolves_to_rdp(self):
        result = generate_recommendations([
            _host(ports=[_port(port=3389, service="ms-wbt-server", risk="High")])
        ])
        assert result[0]["recommendations"][0]["service"] == "rdp"

    def test_alias_resolution_preserves_cves(self):
        result = generate_recommendations([
            _host(ports=[_port(port=445, service="microsoft-ds", risk="Critical")])
        ])
        cves = result[0]["recommendations"][0]["notable_cves"]
        assert "CVE-2017-0144" in cves


# ---------------------------------------------------------------------------
# CVEs and cleartext flags
# ---------------------------------------------------------------------------

class TestCVEsAndFlags:

    def test_rdp_notable_cves_populated(self):
        result = generate_recommendations([
            _host(ports=[_port(port=3389, service="rdp", risk="Critical")])
        ])
        cves = result[0]["recommendations"][0]["notable_cves"]
        assert "CVE-2019-0708" in cves

    def test_cleartext_service_mentioned_in_host_summary(self):
        result = generate_recommendations([
            _host(ports=[_port(port=23, service="telnet", risk="High")])
        ])
        summary = result[0]["overall_host_summary"].lower()
        assert "cleartext" in summary

    def test_anonymous_risk_service_mentioned_in_host_summary(self):
        result = generate_recommendations([
            _host(ports=[_port(port=6379, service="redis", risk="Critical")])
        ])
        summary = result[0]["overall_host_summary"].lower()
        assert "anonymous" in summary or "unauthenticated" in summary

    def test_risk_rationale_includes_mitre_phases_for_known_service(self):
        result = generate_recommendations([
            _host(ports=[_port(port=22, service="ssh", risk="High")])
        ])
        rationale = result[0]["recommendations"][0]["risk_rationale"]
        assert "MITRE" in rationale or "ATT&CK" in rationale

    def test_flags_field_preserved_from_input(self):
        p = _port(service="smb", risk="High", flags=["smb_v1_detected"])
        result = generate_recommendations([_host(ports=[p])])
        assert "smb_v1_detected" in result[0]["recommendations"][0]["flags"]


# ---------------------------------------------------------------------------
# Multi-host
# ---------------------------------------------------------------------------

class TestMultiHost:

    def test_multi_host_returns_one_entry_per_host(self):
        result = generate_recommendations([
            _host(ip="10.0.0.1", ports=[_port(service="rdp",  risk="Critical")]),
            _host(ip="10.0.0.2", ports=[_port(service="http", risk="Medium")]),
        ])
        assert len(result) == 2
        ips = {h["ip"] for h in result}
        assert ips == {"10.0.0.1", "10.0.0.2"}

    def test_multi_host_order_matches_input(self):
        result = generate_recommendations([
            _host(ip="10.0.0.3", ports=[_port()]),
            _host(ip="10.0.0.1", ports=[_port()]),
            _host(ip="10.0.0.2", ports=[_port()]),
        ])
        assert [h["ip"] for h in result] == ["10.0.0.3", "10.0.0.1", "10.0.0.2"]
