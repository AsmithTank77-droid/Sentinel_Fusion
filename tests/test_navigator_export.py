"""Tests for reporting/navigator_export.py."""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reporting.navigator_export import (
    NavigatorExport,
    _parse_technique_id,
    _parse_tactic_slug,
    _confidence_to_color,
)


# ---------------------------------------------------------------------------
# Helper parsers
# ---------------------------------------------------------------------------

def test_parse_technique_id_with_description():
    assert _parse_technique_id("T1218 - Signed Binary Proxy Execution") == "T1218"


def test_parse_technique_id_bare():
    assert _parse_technique_id("T1110") == "T1110"


def test_parse_technique_id_subtechnique():
    assert _parse_technique_id("T1059.001 - PowerShell") == "T1059.001"


def test_parse_technique_id_none_on_empty():
    assert _parse_technique_id("") is None


def test_parse_technique_id_none_on_no_match():
    assert _parse_technique_id("TA0006 - Credential Access") is None


def test_parse_tactic_slug_known():
    assert _parse_tactic_slug("TA0006 - Credential Access") == "credential-access"


def test_parse_tactic_slug_all_known_tactics():
    cases = {
        "TA0001": "initial-access",
        "TA0002": "execution",
        "TA0003": "persistence",
        "TA0004": "privilege-escalation",
        "TA0005": "defense-evasion",
        "TA0006": "credential-access",
        "TA0007": "discovery",
        "TA0008": "lateral-movement",
        "TA0009": "collection",
        "TA0010": "exfiltration",
        "TA0011": "command-and-control",
        "TA0040": "impact",
        "TA0043": "reconnaissance",
    }
    for tactic_id, expected_slug in cases.items():
        assert _parse_tactic_slug(f"{tactic_id} - Some Name") == expected_slug


def test_parse_tactic_slug_none_on_empty():
    assert _parse_tactic_slug("") is None


def test_parse_tactic_slug_none_on_unknown_id():
    assert _parse_tactic_slug("TA9999 - Unknown") is None


def test_confidence_to_color_high():
    assert _confidence_to_color(0.9) == "#ff6666"
    assert _confidence_to_color(0.7) == "#ff6666"


def test_confidence_to_color_medium():
    assert _confidence_to_color(0.5) == "#ffa366"
    assert _confidence_to_color(0.4) == "#ffa366"


def test_confidence_to_color_low():
    assert _confidence_to_color(0.3) == "#ffe766"
    assert _confidence_to_color(0.0) == "#ffe766"


# ---------------------------------------------------------------------------
# build() — layer structure
# ---------------------------------------------------------------------------

def _alert(alert_type="brute_force", confidence=0.9,
           technique="T1110 - Brute Force", tactic="TA0006 - Credential Access"):
    return {
        "alert_type":      alert_type,
        "confidence":      confidence,
        "mitre_technique": technique,
        "mitre_tactic":    tactic,
    }


def test_build_returns_valid_navigator_structure():
    layer = NavigatorExport().build([_alert()])
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["navigator"] == "4.9"
    assert layer["versions"]["attack"] == "14"
    assert layer["versions"]["layer"] == "4.5"
    assert isinstance(layer["techniques"], list)
    assert isinstance(layer["legendItems"], list)


def test_build_includes_run_id_in_name():
    layer = NavigatorExport().build([_alert()], run_id="abc123")
    assert "abc123" in layer["name"]


def test_build_single_alert_produces_one_technique():
    layer = NavigatorExport().build([_alert(technique="T1110", tactic="TA0006 - Credential Access")])
    assert len(layer["techniques"]) == 1
    t = layer["techniques"][0]
    assert t["techniqueID"] == "T1110"
    assert t["tactic"] == "credential-access"
    assert t["score"] == 90
    assert t["color"] == "#ff6666"


def test_build_score_is_confidence_times_100():
    layer = NavigatorExport().build([_alert(confidence=0.72)])
    assert layer["techniques"][0]["score"] == 72


def test_build_deduplicates_same_technique_keeps_highest_confidence():
    alerts = [
        _alert(alert_type="brute_force",    confidence=0.6, technique="T1110"),
        _alert(alert_type="winlog_rule",     confidence=0.9, technique="T1110"),
        _alert(alert_type="another_detector", confidence=0.4, technique="T1110"),
    ]
    layer = NavigatorExport().build(alerts)
    techs = [t for t in layer["techniques"] if t["techniqueID"] == "T1110"]
    assert len(techs) == 1
    assert techs[0]["score"] == 90


def test_build_multiple_different_techniques():
    alerts = [
        _alert(technique="T1110", tactic="TA0006 - Credential Access"),
        _alert(technique="T1021", tactic="TA0008 - Lateral Movement"),
        _alert(technique="T1059.001", tactic="TA0002 - Execution"),
    ]
    layer = NavigatorExport().build(alerts)
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert ids == {"T1110", "T1021", "T1059.001"}


def test_build_skips_alerts_without_technique():
    alerts = [
        {"alert_type": "correlation_chain", "confidence": 0.8, "mitre_tactics": ["TA0006"], "mitre_technique": ""},
        _alert(technique="T1110"),
    ]
    layer = NavigatorExport().build(alerts)
    assert len(layer["techniques"]) == 1
    assert layer["techniques"][0]["techniqueID"] == "T1110"


def test_build_empty_alerts_returns_empty_techniques():
    layer = NavigatorExport().build([])
    assert layer["techniques"] == []


def test_build_subtechnique_treated_independently():
    alerts = [
        _alert(technique="T1059"),
        _alert(technique="T1059.001"),
    ]
    layer = NavigatorExport().build(alerts)
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert "T1059" in ids
    assert "T1059.001" in ids


def test_build_comment_contains_alert_type_and_technique():
    layer = NavigatorExport().build([_alert(alert_type="brute_force", technique="T1110 - Brute Force")])
    comment = layer["techniques"][0]["comment"]
    assert "brute_force" in comment
    assert "T1110" in comment


def test_build_technique_missing_tactic_still_included():
    alert = {"alert_type": "test", "confidence": 0.8, "mitre_technique": "T1110", "mitre_tactic": ""}
    layer = NavigatorExport().build([alert])
    assert len(layer["techniques"]) == 1
    assert "tactic" not in layer["techniques"][0]


def test_build_description_contains_technique_and_alert_counts():
    alerts = [_alert(), _alert(technique="T1021", tactic="TA0008 - Lateral Movement")]
    layer = NavigatorExport().build(alerts)
    assert "2" in layer["description"]
