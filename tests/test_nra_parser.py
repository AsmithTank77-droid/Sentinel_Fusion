"""Tests for core/pipeline/nra_parser.py"""

import sys
import os
import textwrap
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from core.pipeline.nra_parser import parse_scan, _get_ip, _parse_ports

import xml.etree.ElementTree as ET


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_xml(content: str) -> str:
    """Write XML content to a temp file and return the path."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(content)
        return f.name


MINIMAL_NMAP = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun start="1746748800">
      <host>
        <address addr="192.168.1.10" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http"/>
          </port>
        </ports>
      </host>
    </nmaprun>
""")

MULTI_HOST_NMAP = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun start="1746748800">
      <host>
        <address addr="10.0.0.1" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="3389">
            <state state="open"/>
            <service name="rdp"/>
          </port>
        </ports>
      </host>
      <host>
        <address addr="10.0.0.2" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="445">
            <state state="open"/>
            <service name="smb"/>
          </port>
          <port protocol="tcp" portid="22">
            <state state="filtered"/>
            <service name="ssh"/>
          </port>
        </ports>
      </host>
    </nmaprun>
""")

NO_IP_NMAP = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun start="1746748800">
      <host>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http"/>
          </port>
        </ports>
      </host>
    </nmaprun>
""")

NO_START_NMAP = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="1.2.3.4" addrtype="ipv4"/>
        <ports/>
      </host>
    </nmaprun>
""")


# ---------------------------------------------------------------------------
# parse_scan — file errors
# ---------------------------------------------------------------------------

class TestParseScanErrors:
    def test_missing_file_returns_empty(self):
        assert parse_scan("/tmp/does_not_exist_xyzzy.xml") == []

    def test_malformed_xml_returns_empty(self, tmp_path):
        bad = tmp_path / "bad.xml"
        bad.write_text("<unclosed>")
        assert parse_scan(str(bad)) == []


# ---------------------------------------------------------------------------
# parse_scan — host extraction
# ---------------------------------------------------------------------------

class TestParseScanHosts:
    def setup_method(self):
        self.path = _write_xml(MINIMAL_NMAP)

    def teardown_method(self):
        os.unlink(self.path)

    def test_returns_list(self):
        result = parse_scan(self.path)
        assert isinstance(result, list)

    def test_single_host_found(self):
        result = parse_scan(self.path)
        assert len(result) == 1

    def test_host_has_required_keys(self):
        host = parse_scan(self.path)[0]
        assert "ip" in host
        assert "ports" in host
        assert "scan_time" in host

    def test_ip_extracted_correctly(self):
        host = parse_scan(self.path)[0]
        assert host["ip"] == "192.168.1.10"

    def test_scan_time_is_iso_string(self):
        host = parse_scan(self.path)[0]
        assert "T" in host["scan_time"]
        assert host["scan_time"].endswith("Z")

    def test_scan_time_from_epoch(self):
        # start="1746748800" → 2025-05-09T04:00:00Z
        host = parse_scan(self.path)[0]
        assert host["scan_time"].startswith("2025-")

    def test_ports_is_list(self):
        host = parse_scan(self.path)[0]
        assert isinstance(host["ports"], list)

    def test_port_count(self):
        host = parse_scan(self.path)[0]
        assert len(host["ports"]) == 2

    def test_port_fields(self):
        ports = parse_scan(self.path)[0]["ports"]
        for p in ports:
            assert "port" in p
            assert "protocol" in p
            assert "service" in p
            assert "state" in p

    def test_ssh_port_parsed(self):
        ports = parse_scan(self.path)[0]["ports"]
        ssh = next(p for p in ports if p["port"] == 22)
        assert ssh["service"] == "ssh"
        assert ssh["protocol"] == "tcp"
        assert ssh["state"] == "open"

    def test_http_port_parsed(self):
        ports = parse_scan(self.path)[0]["ports"]
        http = next(p for p in ports if p["port"] == 80)
        assert http["service"] == "http"
        assert http["state"] == "open"


# ---------------------------------------------------------------------------
# parse_scan — multi-host
# ---------------------------------------------------------------------------

class TestParseScanMultiHost:
    def setup_method(self):
        self.path = _write_xml(MULTI_HOST_NMAP)

    def teardown_method(self):
        os.unlink(self.path)

    def test_two_hosts_returned(self):
        assert len(parse_scan(self.path)) == 2

    def test_first_host_ip(self):
        hosts = parse_scan(self.path)
        ips = {h["ip"] for h in hosts}
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips

    def test_rdp_host_has_one_port(self):
        hosts = {h["ip"]: h for h in parse_scan(self.path)}
        assert len(hosts["10.0.0.1"]["ports"]) == 1
        assert hosts["10.0.0.1"]["ports"][0]["service"] == "rdp"

    def test_filtered_state_preserved(self):
        hosts = {h["ip"]: h for h in parse_scan(self.path)}
        ports = hosts["10.0.0.2"]["ports"]
        ssh = next(p for p in ports if p["port"] == 22)
        assert ssh["state"] == "filtered"

    def test_all_hosts_share_same_scan_time(self):
        hosts = parse_scan(self.path)
        times = {h["scan_time"] for h in hosts}
        assert len(times) == 1


# ---------------------------------------------------------------------------
# parse_scan — edge cases
# ---------------------------------------------------------------------------

class TestParseScanEdgeCases:
    def test_host_without_ip_skipped(self, tmp_path):
        path = tmp_path / "no_ip.xml"
        path.write_text(NO_IP_NMAP)
        assert parse_scan(str(path)) == []

    def test_no_start_attribute_uses_fallback_time(self, tmp_path):
        path = tmp_path / "no_start.xml"
        path.write_text(NO_START_NMAP)
        result = parse_scan(str(path))
        assert len(result) == 1
        assert "T" in result[0]["scan_time"]

    def test_host_with_no_ports(self, tmp_path):
        xml = textwrap.dedent("""\
            <?xml version="1.0"?>
            <nmaprun start="1746748800">
              <host>
                <address addr="1.2.3.4" addrtype="ipv4"/>
                <ports/>
              </host>
            </nmaprun>
        """)
        path = tmp_path / "no_ports.xml"
        path.write_text(xml)
        result = parse_scan(str(path))
        assert len(result) == 1
        assert result[0]["ports"] == []

    def test_ipv6_address_accepted(self, tmp_path):
        xml = textwrap.dedent("""\
            <?xml version="1.0"?>
            <nmaprun start="1746748800">
              <host>
                <address addr="::1" addrtype="ipv6"/>
                <ports/>
              </host>
            </nmaprun>
        """)
        path = tmp_path / "ipv6.xml"
        path.write_text(xml)
        result = parse_scan(str(path))
        assert len(result) == 1
        assert result[0]["ip"] == "::1"

    def test_ipv4_preferred_over_ipv6(self, tmp_path):
        xml = textwrap.dedent("""\
            <?xml version="1.0"?>
            <nmaprun start="1746748800">
              <host>
                <address addr="192.168.1.1" addrtype="ipv4"/>
                <address addr="::1" addrtype="ipv6"/>
                <ports/>
              </host>
            </nmaprun>
        """)
        path = tmp_path / "dual.xml"
        path.write_text(xml)
        result = parse_scan(str(path))
        assert result[0]["ip"] == "192.168.1.1"

    def test_empty_nmaprun_returns_empty_list(self, tmp_path):
        path = tmp_path / "empty.xml"
        path.write_text('<?xml version="1.0"?><nmaprun/>')
        assert parse_scan(str(path)) == []

    def test_port_without_service_defaults_to_unknown(self, tmp_path):
        xml = textwrap.dedent("""\
            <?xml version="1.0"?>
            <nmaprun start="1746748800">
              <host>
                <address addr="1.2.3.4" addrtype="ipv4"/>
                <ports>
                  <port protocol="tcp" portid="9999">
                    <state state="open"/>
                  </port>
                </ports>
              </host>
            </nmaprun>
        """)
        path = tmp_path / "no_svc.xml"
        path.write_text(xml)
        ports = parse_scan(str(path))[0]["ports"]
        assert ports[0]["service"] == "unknown"

    def test_dangerous_combo_ports_all_captured(self, tmp_path):
        xml = textwrap.dedent("""\
            <?xml version="1.0"?>
            <nmaprun start="1746748800">
              <host>
                <address addr="10.0.0.5" addrtype="ipv4"/>
                <ports>
                  <port protocol="tcp" portid="445">
                    <state state="open"/>
                    <service name="smb"/>
                  </port>
                  <port protocol="tcp" portid="3389">
                    <state state="open"/>
                    <service name="rdp"/>
                  </port>
                </ports>
              </host>
            </nmaprun>
        """)
        path = tmp_path / "combo.xml"
        path.write_text(xml)
        ports = parse_scan(str(path))[0]["ports"]
        services = {p["service"] for p in ports}
        assert "smb" in services
        assert "rdp" in services
