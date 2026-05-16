"""
normalize.py — Stage 2: Normalization
Pipeline: ingest.py → normalize.py → correlation_engine.py

Converts raw NRA, Winlog, and Mock inputs into a unified NormalizedEvent schema.
No raw source data passes beyond this module.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone


class NormalizedEvent:
    """Unified event schema for all data traversing the Sentinel_Fusion pipeline."""

    __slots__ = (
        "timestamp",
        "source_type",
        "src_ip",
        "dst_ip",
        "event_type",
        "severity",
        "metadata",
    )

    VALID_SOURCE_TYPES: frozenset[str] = frozenset({"nra", "winlog", "mock"})

    def __init__(
        self,
        timestamp: str,
        source_type: str,
        src_ip: str,
        dst_ip: str,
        event_type: str,
        severity: int,
        metadata: dict,
    ) -> None:
        if source_type not in self.VALID_SOURCE_TYPES:
            raise ValueError(
                f"source_type must be one of {sorted(self.VALID_SOURCE_TYPES)!r}, "
                f"got {source_type!r}"
            )
        if not isinstance(severity, int) or not (0 <= severity <= 10):
            raise TypeError(
                f"severity must be an int in [0, 10], got {severity!r}"
            )
        if not isinstance(metadata, dict):
            raise TypeError(f"metadata must be a dict, got {type(metadata).__name__!r}")

        self.timestamp: str = timestamp
        self.source_type: str = source_type
        self.src_ip: str = src_ip
        self.dst_ip: str = dst_ip
        self.event_type: str = event_type
        self.severity: int = severity
        self.metadata: dict = metadata

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "source_type": self.source_type,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "event_type": self.event_type,
            "severity": self.severity,
            "metadata": copy.deepcopy(self.metadata),
        }

    def __repr__(self) -> str:
        return (
            f"NormalizedEvent("
            f"source_type={self.source_type!r}, "
            f"event_type={self.event_type!r}, "
            f"severity={self.severity}, "
            f"src_ip={self.src_ip!r}, "
            f"dst_ip={self.dst_ip!r}, "
            f"timestamp={self.timestamp!r})"
        )


class Normalizer:
    """
    Stateless normalizer for the Sentinel_Fusion pipeline.

    Each public method accepts a raw dict from a specific source system and returns
    a NormalizedEvent. No instance state is maintained between calls.
    """

    _SEVERITY_MAP: dict[str, int] = {
        "low": 2,
        "medium": 5,
        "high": 8,
        "critical": 10,
        # Windows Level / LevelDisplayName values
        "verbose": 1,
        "information": 2,
        "warning": 5,
        "error": 8,
    }

    # Windows Security EventID → (event_type, default_severity_label)
    _WINLOG_EVENT_TYPES: dict[int, tuple[str, str]] = {
        4624: ("authentication_success",          "low"),
        4625: ("authentication_failure",          "medium"),
        4648: ("explicit_credential_logon",       "medium"),
        4672: ("privileged_logon",                "medium"),
        4688: ("process_creation",                "low"),
        4697: ("service_installed",               "high"),
        4698: ("scheduled_task_created",          "high"),
        4720: ("account_created",                 "medium"),
        4728: ("domain_group_member_added",       "medium"),
        4732: ("local_group_member_added",        "medium"),
        4756: ("universal_group_member_added",    "medium"),
        4768: ("kerberos_tgt_request",            "low"),
        4769: ("kerberos_service_ticket_request", "low"),
        4771: ("kerberos_preauth_failure",        "medium"),
        4776: ("ntlm_credential_validation",      "low"),
        7045: ("new_service_installed",           "high"),
    }

    @staticmethod
    def _parse_timestamp(value: object) -> str:
        """
        Coerce diverse timestamp representations into ISO 8601 UTC string.
        Raises ValueError if value is present but cannot be parsed — never fabricates.
        Callers must supply a non-None value or handle the exception.
        """
        if value is None:
            raise ValueError("timestamp is required but was not present in the raw event")
        if isinstance(value, bool):
            raise ValueError(f"Cannot parse timestamp from boolean {value!r}")
        if isinstance(value, (int, float)):
            try:
                dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except (OSError, OverflowError, ValueError) as exc:
                raise ValueError(f"Cannot parse UNIX epoch timestamp {value!r}: {exc}") from exc
        if isinstance(value, datetime):
            dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        for fmt in (
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y/%m/%d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(str(value).strip(), fmt).replace(tzinfo=timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                continue
        raise ValueError(f"Cannot parse timestamp {value!r} — no supported format matched")

    def _map_severity(self, level: object) -> int:
        """Map severity label to integer. low=2, medium=5, high=8, critical=10, default=1.
        Accepts int, float (CVSS scores rounded and clamped), or string label."""
        if isinstance(level, bool):
            return int(level)
        if isinstance(level, (int, float)):
            return max(0, min(10, round(level)))
        return self._SEVERITY_MAP.get(str(level).lower().strip(), 1)

    def normalize_nra(self, raw: dict) -> NormalizedEvent:
        """
        Normalize an NRA (Nmap Recon Analyzer) record.

        Preferred input format (from nra_parser.parse_scan()):
            {"ip": str, "ports": list[dict], "scan_time": str}

        Also accepts legacy/manual fields:
            scanner_ip / src_ip  — host running the scan
            host / target / ip   — scanned target
            scan_time / timestamp — when the scan executed
            risk_level / severity — optional override; defaults to 'low' (scored later)
        """
        src_ip     = str(raw.get("scanner_ip") or raw.get("src_ip") or raw.get("source") or "")
        dst_ip     = str(raw.get("ip") or raw.get("host") or raw.get("target") or raw.get("dst_ip") or raw.get("address") or "")
        timestamp  = self._parse_timestamp(raw.get("scan_time") or raw.get("timestamp") or raw.get("time") or raw.get("start"))
        event_type = str(raw.get("event_type") or "port_scan")

        # Derive severity from open port risk when not explicitly provided
        if "risk_level" in raw or "severity" in raw:
            severity = self._map_severity(
                next((raw[k] for k in ("risk_level", "severity") if k in raw), "low")
            )
        else:
            # Estimate from ports: any open high-risk port → high
            ports = raw.get("ports") or []
            from intelligence.service_intelligence import SERVICE_RISK, HIGH_RISK_PORTS
            open_services = [
                p.get("service", "unknown")
                for p in ports
                if str(p.get("state", "open")).lower() == "open"
            ]
            if any(SERVICE_RISK.get(s, 4) >= 8 for s in open_services):
                severity = 8
            elif any(SERVICE_RISK.get(s, 4) >= 5 for s in open_services):
                severity = 5
            elif open_services:
                severity = 2
            else:
                severity = 1

        meta = copy.deepcopy(raw)
        # Annotate metadata with service-level enrichment hints
        if raw.get("ports"):
            from intelligence.service_intelligence import enrich_service
            meta["service_enrichment"] = [
                enrich_service(p.get("service", "unknown"), p.get("port", 0))
                for p in raw["ports"]
                if str(p.get("state", "open")).lower() == "open"
            ]

        return NormalizedEvent(
            timestamp=timestamp,
            source_type="nra",
            src_ip=src_ip,
            dst_ip=dst_ip,
            event_type=event_type,
            severity=severity,
            metadata=meta,
        )

    def normalize_winlog(self, raw: dict) -> NormalizedEvent:
        """
        Normalize a Windows event log record.

        Preferred input format (from winlog_parser.parse_evtx()):
            event_id, timestamp, timestamp_epoch, computer, src_ip, logon_type,
            target_user, subject_user, group_name, service_name, task_name, raw_data

        Also accepts Winlogbeat / manual export fields:
            EventID / event_id, TimeCreated / timestamp, IpAddress / src_ip,
            Computer / dst_ip, EventData (nested dict), severity / risk_level
        """
        from intelligence.event_intelligence import get_event

        event_id_raw = raw.get("event_id") or raw.get("EventID") or 0
        try:
            event_id = int(event_id_raw)
        except (TypeError, ValueError):
            event_id = 0

        # _WINLOG_EVENT_TYPES is the primary source for event_type and severity
        # (preserves pipeline-tuned values); event_intelligence adds MITRE/analyst context
        intel = get_event(event_id)
        default_event_type, default_severity_label = self._WINLOG_EVENT_TYPES.get(
            event_id, (f"winlog_event_{event_id}", "low")
        )
        event_type = str(raw.get("event_type") or default_event_type)

        # Severity: explicit override → _WINLOG_EVENT_TYPES label → raw severity field
        if any(k in raw for k in ("severity", "risk_level", "Level", "LevelDisplayName")):
            raw_sev  = next(raw[k] for k in ("severity", "risk_level", "Level", "LevelDisplayName") if k in raw)
            severity = self._map_severity(raw_sev)
        else:
            severity = self._map_severity(default_severity_label)

        timestamp = self._parse_timestamp(
            raw.get("timestamp") or raw.get("TimeCreated") or raw.get("time") or raw.get("@timestamp")
        )

        _ed = raw.get("EventData")
        event_data: dict = _ed if isinstance(_ed, dict) else {}

        src_ip = str(
            raw.get("src_ip")
            or raw.get("IpAddress")
            or raw.get("SourceAddress")
            or event_data.get("IpAddress")
            or event_data.get("Ipv4Address")
            or ""
        )
        dst_ip = str(
            event_data.get("TargetIpAddress")
            or raw.get("dst_ip")
            or raw.get("TargetHost")
            or raw.get("computer")
            or raw.get("Computer")
            or ""
        )

        meta = copy.deepcopy(raw)
        # Attach event intelligence into metadata for downstream stages
        meta["event_intel"] = {
            "event_id":        event_id,
            "event_name":      intel["name"],
            "category":        intel["category"],
            "mitre_technique": intel["mitre_technique"],
            "mitre_name":      intel["mitre_name"],
            "description":     intel["description"],
            "analyst_note":    intel["analyst_note"],
            "known":           event_id in (intel if isinstance(intel, dict) else {}),
        }

        return NormalizedEvent(
            timestamp=timestamp,
            source_type="winlog",
            src_ip=src_ip,
            dst_ip=dst_ip,
            event_type=event_type,
            severity=severity,
            metadata=meta,
        )

    def normalize_mock(self, raw: dict) -> NormalizedEvent:
        """
        Normalize mock/simulated attack data.

        Accepted raw keys mirror the NormalizedEvent schema directly:
            timestamp, src_ip, dst_ip, event_type, severity
        """
        timestamp  = self._parse_timestamp(raw.get("timestamp"))
        src_ip     = str(raw.get("src_ip") or raw.get("src") or "")
        dst_ip     = str(raw.get("dst_ip") or raw.get("dst") or "")
        event_type = str(raw.get("event_type") or raw.get("type") or "simulated_event")
        severity   = self._map_severity(raw["severity"] if "severity" in raw else "low")

        return NormalizedEvent(
            timestamp=timestamp,
            source_type="mock",
            src_ip=src_ip,
            dst_ip=dst_ip,
            event_type=event_type,
            severity=severity,
            metadata=copy.deepcopy(raw),
        )
