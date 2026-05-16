"""
nra_parser.py — Nmap XML scan file parser for Stage 1 ingestion.
Adapted from nmap-recon-analyzer/scan_xml.py.
"""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _get_ip(host_elem: ET.Element) -> str | None:
    for addrtype in ("ipv4", "ipv6"):
        elem = host_elem.find(f"address[@addrtype='{addrtype}']")
        if elem is not None:
            return elem.get("addr")
    return None


def _parse_ports(host_elem: ET.Element) -> list[dict]:
    ports = []
    for port_elem in host_elem.findall(".//port"):
        port_num   = int(port_elem.get("portid", 0))
        protocol   = port_elem.get("protocol", "tcp")
        svc_elem   = port_elem.find("service")
        service    = svc_elem.get("name", "unknown") if svc_elem is not None else "unknown"
        state_elem = port_elem.find("state")
        state      = state_elem.get("state", "open") if state_elem is not None else "open"
        ports.append({"port": port_num, "protocol": protocol, "service": service, "state": state})
    return ports


def parse_scan(file_path: str) -> list[dict]:
    """
    Parse an Nmap XML file and return one dict per scanned host.

    Each dict:
        {
            "ip":        str,
            "ports":     list[{"port": int, "protocol": str, "service": str, "state": str}],
            "scan_time": str  (ISO 8601 UTC),
        }

    Returns an empty list if the file is missing or malformed.
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        logger.error("Failed to parse Nmap XML: %s", exc)
        return []
    except FileNotFoundError:
        logger.error("Scan file not found: %s", file_path)
        return []

    start_epoch = root.get("start")
    if start_epoch:
        try:
            dt = datetime.fromtimestamp(int(start_epoch), tz=timezone.utc)
            scan_time = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, OSError):
            scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    hosts = []
    for host_elem in root.findall("host"):
        ip = _get_ip(host_elem)
        if ip is None:
            continue
        hosts.append({
            "ip":        ip,
            "ports":     _parse_ports(host_elem),
            "scan_time": scan_time,
        })

    logger.debug("parse_scan: %d host(s) parsed from %s", len(hosts), file_path)
    return hosts
