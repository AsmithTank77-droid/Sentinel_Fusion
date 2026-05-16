"""Tests for core/pipeline/ingest.py — Stage 1: Ingestion."""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pipeline.ingest import Ingester, _ext, _xml_element_to_dict
import xml.etree.ElementTree as ET


# ---------------------------------------------------------------------------
# _ext helper
# ---------------------------------------------------------------------------

def test_ext_json():
    assert _ext("events/scan.json") == ".json"

def test_ext_xml():
    assert _ext("nmap.XML") == ".xml"

def test_ext_no_extension():
    assert _ext("no_extension") == ""

def test_ext_evtx():
    assert _ext("log.evtx") == ".evtx"


# ---------------------------------------------------------------------------
# _xml_element_to_dict helper
# ---------------------------------------------------------------------------

def test_xml_element_attributes():
    el = ET.fromstring('<Host addr="1.2.3.4" addrtype="ipv4"/>')
    result = _xml_element_to_dict(el)
    assert result == {"addr": "1.2.3.4", "addrtype": "ipv4"}

def test_xml_element_text_content():
    el = ET.fromstring("<Name>DC01</Name>")
    result = _xml_element_to_dict(el)
    assert result["_text"] == "DC01"

def test_xml_element_nested_children():
    el = ET.fromstring("<Host><Status state='up'/></Host>")
    result = _xml_element_to_dict(el)
    assert "Status" in result
    assert result["Status"]["state"] == "up"

def test_xml_element_repeated_tags_become_list():
    el = ET.fromstring(
        "<Host><Port portid='22'/><Port portid='80'/></Host>"
    )
    result = _xml_element_to_dict(el)
    assert isinstance(result["Port"], list)
    assert len(result["Port"]) == 2

def test_xml_element_no_extra_keys_for_empty_text():
    el = ET.fromstring("<EventID>4624</EventID>")
    result = _xml_element_to_dict(el)
    assert set(result.keys()) == {"_text"}


# ---------------------------------------------------------------------------
# Ingester.ingest dispatch
# ---------------------------------------------------------------------------

class TestIngesterDispatch:
    def setup_method(self):
        self.ingester = Ingester()

    def test_valid_source_nra(self):
        raw = {"host": "10.0.0.1", "scan_time": "2026-05-09T02:14:00Z"}
        result = self.ingester.ingest("nra", raw)
        assert result == raw

    def test_valid_source_winlog(self):
        raw = {"EventID": 4624, "TimeCreated": "2026-05-09T02:20:00Z"}
        result = self.ingester.ingest("winlog", raw)
        assert result == raw

    def test_valid_source_mock(self):
        raw = {"timestamp": "2026-05-09T02:22:00Z", "src_ip": "10.0.0.5"}
        result = self.ingester.ingest("mock", raw)
        assert result == raw

    def test_unknown_source_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown source_type"):
            self.ingester.ingest("syslog", {"ts": "x"})

    def test_empty_dict_raises_value_error(self):
        with pytest.raises(ValueError):
            self.ingester.ingest("nra", {})

    def test_non_dict_non_str_raises_type_error(self):
        with pytest.raises(TypeError):
            self.ingester.ingest("nra", 42)


# ---------------------------------------------------------------------------
# ingest_nra
# ---------------------------------------------------------------------------

class TestIngestNra:
    def setup_method(self):
        self.ingester = Ingester()

    def test_dict_passthrough(self):
        raw = {"scanner_ip": "1.2.3.4", "host": "5.6.7.8"}
        assert self.ingester.ingest_nra(raw) == raw

    def test_unsupported_extension_raises(self):
        with pytest.raises(ValueError, match="unsupported file extension"):
            self.ingester.ingest_nra("scan.csv")

    def test_wrong_type_raises(self):
        with pytest.raises(TypeError):
            self.ingester.ingest_nra(["list", "not", "valid"])


# ---------------------------------------------------------------------------
# ingest_winlog
# ---------------------------------------------------------------------------

class TestIngestWinlog:
    def setup_method(self):
        self.ingester = Ingester()

    def test_dict_passthrough(self):
        raw = {"EventID": 4625, "TimeCreated": "2026-05-09T02:15:00Z"}
        assert self.ingester.ingest_winlog(raw) == raw

    def test_evtx_attempts_parse(self):
        # .evtx is now supported via winlog_parser; without python-evtx installed
        # it raises ImportError, and without a real file it raises FileNotFoundError.
        # Either is acceptable — NotImplementedError is no longer raised.
        with pytest.raises((ImportError, FileNotFoundError, ValueError)):
            self.ingester.ingest_winlog("security.evtx")

    def test_unsupported_extension_raises(self):
        with pytest.raises(ValueError, match="unsupported file extension"):
            self.ingester.ingest_winlog("log.csv")


# ---------------------------------------------------------------------------
# ingest_mock
# ---------------------------------------------------------------------------

class TestIngestMock:
    def setup_method(self):
        self.ingester = Ingester()

    def test_dict_passthrough(self):
        raw = {"timestamp": "2026-05-09T02:22:00Z", "src_ip": "10.0.0.5",
               "dst_ip": "10.0.0.10", "event_type": "lateral_movement"}
        assert self.ingester.ingest_mock(raw) == raw

    def test_unsupported_extension_raises(self):
        with pytest.raises(ValueError, match="unsupported file extension"):
            self.ingester.ingest_mock("data.xml")

    def test_wrong_type_raises(self):
        with pytest.raises(TypeError):
            self.ingester.ingest_mock(None)
