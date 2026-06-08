"""
detection/sigma_field_mapper.py — Stage 4 pre-processing: Sigma field translation.
Pipeline: enrich.py (Stage 3) → [Stage 4: sigma_engine] → correlation_engine.py (Stage 5)

Translates normalized event dicts into Sigma-compatible field names so that
Sigma rules can match against standard field names without awareness of the
internal schema layout.
"""

from __future__ import annotations

import copy

# Maps Sigma standard field names to their location in a normalized event dict.
# Dot notation: "metadata.event_id" traverses event["metadata"]["event_id"].
# Single key (no dot): resolved directly from the top-level event dict.
SIGMA_FIELD_MAP: dict[str, str] = {
    "EventID":         "metadata.event_id",
    "CommandLine":     "metadata.command_line",
    "Image":           "metadata.image",
    "DestinationIp":   "dst_ip",
    "SourceIp":        "src_ip",
    "LogonType":       "metadata.logon_type",
    "SubjectUserName": "metadata.subject_user",
    "TargetUserName":  "metadata.target_user",
    "ParentImage":     "metadata.parent_image",
    "DestinationPort": "metadata.dst_port",
}


def _resolve(event: dict, path: str) -> object:
    """Walk a dot-notated path into event. Returns None if any key is absent or
    if an intermediate value is not a dict."""
    key, _, remainder = path.partition(".")
    value = event.get(key)
    if not remainder:
        return value
    if not isinstance(value, dict):
        return None
    return _resolve(value, remainder)


def map_event(event: dict) -> dict:
    """
    Return a deep copy of event with Sigma-compatible field names added at the
    top level. Original fields are preserved unchanged. Sigma fields whose source
    path is absent or null resolve to None.

    Args:
        event: normalized event dict (output of NormalizedEvent.to_dict()).

    Returns:
        Copy of event with all SIGMA_FIELD_MAP keys present at the top level.
    """
    mapped = copy.deepcopy(event)
    for sigma_name, path in SIGMA_FIELD_MAP.items():
        mapped[sigma_name] = _resolve(event, path)
    return mapped
