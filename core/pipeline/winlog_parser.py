"""
winlog_parser.py — Windows Event Log (.evtx) binary file parser for Stage 1 ingestion.
Adapted from winlog-soc-analyzer/log_parser.py.

Requires: pip install python-evtx
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

try:
    import Evtx.Evtx as _evtx_lib
    _EVTX_AVAILABLE = True
except ImportError:
    _evtx_lib = None
    _EVTX_AVAILABLE = False

_NS     = "http://schemas.microsoft.com/win/2004/08/events/event"
_NS_MAP = {"evt": _NS}
_TS_RE  = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d+)Z?")


def parse_evtx(filepath: str) -> list[dict]:
    """
    Parse a Windows .evtx binary file into a list of event dicts.

    Each dict contains fields compatible with normalize_winlog():
        event_id, timestamp, timestamp_epoch, computer, provider, channel,
        subject_user, target_user, target_domain, src_ip, source_port,
        logon_type, process_name, command_line, service_name, task_name,
        group_name, raw_data

    Events are returned sorted by timestamp_epoch ascending.

    Raises:
        ImportError:       if python-evtx is not installed
        FileNotFoundError: if the file does not exist
        ValueError:        if the path is not a .evtx file
    """
    path = Path(filepath)
    if path.suffix.lower() != ".evtx":
        raise ValueError(f"Expected a .evtx file, got: {path.suffix}")
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {filepath}")
    if not _EVTX_AVAILABLE:
        raise ImportError(
            "python-evtx is not installed — run: pip install python-evtx"
        )

    events: list[dict] = []
    with _evtx_lib.Evtx(str(path)) as log:
        for record in log.records():
            try:
                event = _parse_record(record.xml())
                if event:
                    events.append(event)
            except Exception:
                continue

    events.sort(key=lambda e: e["timestamp_epoch"])
    return events


def _parse_record(xml_str: str) -> dict | None:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    system = root.find("evt:System", _NS_MAP)
    if system is None:
        return None

    event_id = _text(system, "evt:EventID")
    if event_id is None:
        return None

    timestamp_raw              = _attr(system, "evt:TimeCreated", "SystemTime") or ""
    timestamp, timestamp_epoch = _parse_timestamp(timestamp_raw)
    raw_data                   = _extract_event_data(root)

    return {
        "event_id":        int(event_id),
        "timestamp":       timestamp,
        "timestamp_epoch": timestamp_epoch,
        "computer":        _text(system, "evt:Computer") or "",
        "provider":        _attr(system, "evt:Provider", "Name") or "",
        "channel":         _text(system, "evt:Channel") or "",
        "subject_user":    raw_data.get("SubjectUserName") or raw_data.get("SubjectUser") or "",
        "target_user":     raw_data.get("TargetUserName") or raw_data.get("TargetUser") or "",
        "target_domain":   raw_data.get("TargetDomainName") or "",
        "src_ip":          raw_data.get("IpAddress") or raw_data.get("SourceAddress") or "",
        "source_port":     raw_data.get("IpPort") or raw_data.get("SourcePort") or "",
        "logon_type":      _safe_int(raw_data.get("LogonType")),
        "process_name":    raw_data.get("NewProcessName") or raw_data.get("ProcessName") or "",
        "command_line":    raw_data.get("CommandLine") or "",
        "service_name":    raw_data.get("ServiceName") or "",
        "task_name":       raw_data.get("TaskName") or "",
        "group_name":      raw_data.get("GroupName") or raw_data.get("TargetUserName") or "",
        "raw_data":        raw_data,
    }


def _extract_event_data(root: ET.Element) -> dict:
    data: dict = {}
    for section in ("evt:EventData", "evt:UserData"):
        node = root.find(section, _NS_MAP)
        if node is None:
            continue
        for child in node.iter():
            name = child.get("Name")
            if name and child.text:
                data[name] = child.text.strip()
    return data


def _parse_timestamp(ts_str: str) -> tuple[str, float]:
    match = _TS_RE.match(ts_str)
    if match:
        base, frac = match.groups()
        frac = frac[:6].ljust(6, "0")
        try:
            dt = datetime.strptime(f"{base}.{frac}", "%Y-%m-%dT%H:%M:%S.%f")
            dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat(), dt.timestamp()
        except ValueError:
            pass
    return ts_str, 0.0


def _text(parent: ET.Element, tag: str) -> str | None:
    el = parent.find(tag, _NS_MAP)
    return el.text.strip() if el is not None and el.text else None


def _attr(parent: ET.Element, tag: str, attr: str) -> str | None:
    el = parent.find(tag, _NS_MAP)
    return el.get(attr) if el is not None else None


def _safe_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
