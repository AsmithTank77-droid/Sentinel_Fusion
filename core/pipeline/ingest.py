"""
ingest.py — Stage 1: Ingestion
Pipeline: ingest.py → normalize.py → enrich.py → ...

Reads raw structured input from three source types and returns plain Python
dicts ready for normalization. No field renaming, value calculation, schema
mapping, enrichment, or detection logic is performed here.

Expected source locations:
    NRA:    .xml (Nmap XML) or .json (pre-parsed host dicts)
    Winlog: .evtx (binary Windows Event Log) or .json export
    Mock:   data/samples/ (.json simulated attack data)

When called via the orchestrator, raw events arrive as pre-parsed dicts.
When called directly (CLI, demo), file paths are also accepted.

Module-level helpers for native file expansion:
    load_nra_file(path)    → list[dict]   one dict per host
    load_winlog_file(path) → list[dict]   one dict per event
"""

from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET


# ---------------------------------------------------------------------------
# File-level helpers — expand native source files before pipeline ingestion
# ---------------------------------------------------------------------------

def load_nra_file(path: str) -> list[dict]:
    """
    Parse an Nmap XML file and return one host dict per scanned host.
    Delegates to core.pipeline.nra_parser.parse_scan().
    Raises OSError or ValueError on parse failure.
    """
    from core.pipeline.nra_parser import parse_scan
    hosts = parse_scan(path)
    if not hosts:
        raise ValueError(f"load_nra_file: no hosts found in {path!r}")
    return hosts


def load_winlog_file(path: str) -> list[dict]:
    """
    Parse a .evtx binary file and return one event dict per Windows event record.
    Delegates to core.pipeline.winlog_parser.parse_evtx().
    Raises ImportError if python-evtx is not installed.
    Raises FileNotFoundError or ValueError for bad paths.
    """
    from core.pipeline.winlog_parser import parse_evtx
    return parse_evtx(path)


# ---------------------------------------------------------------------------
# Internal helpers — not part of the public API
# ---------------------------------------------------------------------------

def _ext(path: str) -> str:
    """Return the lowercase file extension including the dot, or '' if absent."""
    return os.path.splitext(path)[1].lower()


def _read_json(path: str) -> dict:
    """
    Read and parse a JSON file. The top-level value must be a JSON object (dict).
    Raises OSError on file access failure, ValueError on malformed JSON,
    TypeError if the top-level value is not a dict.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise OSError(f"Cannot read {path!r}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed JSON in {path!r}: {exc}") from exc
    if not isinstance(data, dict):
        raise TypeError(
            f"Expected a JSON object in {path!r}, "
            f"got {type(data).__name__!r}. "
            f"If the file contains a list of events, split it before ingestion."
        )
    return data


def _xml_element_to_dict(element: ET.Element) -> dict:
    """
    Recursively convert an ElementTree Element to a plain dict.

    Rules:
        - XML attributes become top-level keys.
        - Child elements are nested by tag name.
        - Repeated child tags become a list.
        - Non-empty text content is stored under the '_text' key.
    """
    node: dict = dict(element.attrib)
    for child in element:
        child_data = _xml_element_to_dict(child)
        tag = child.tag
        if tag in node:
            if not isinstance(node[tag], list):
                node[tag] = [node[tag]]
            node[tag].append(child_data)
        else:
            node[tag] = child_data
    text = (element.text or "").strip()
    if text:
        node["_text"] = text
    return node


def _read_xml(path: str) -> dict:
    """
    Parse an XML file and return the root element as a dict.
    The root tag is stored under the '_tag' key for traceability.
    Raises OSError on file access failure, ValueError on malformed XML.
    """
    try:
        tree = ET.parse(path)
    except OSError as exc:
        raise OSError(f"Cannot read {path!r}: {exc}") from exc
    except ET.ParseError as exc:
        raise ValueError(f"Malformed XML in {path!r}: {exc}") from exc
    root = tree.getroot()
    result = _xml_element_to_dict(root)
    result["_tag"] = root.tag
    return result


def _validate_dict(data: object, context: str) -> dict:
    """
    Assert that data is a non-empty dict.
    Raises TypeError or ValueError with a message identifying the call site.
    """
    if not isinstance(data, dict):
        raise TypeError(
            f"{context}: expected dict, got {type(data).__name__!r}"
        )
    if not data:
        raise ValueError(f"{context}: raw event dict must not be empty")
    return data


# ---------------------------------------------------------------------------
# Ingester
# ---------------------------------------------------------------------------

class Ingester:
    """
    Stage 1 ingester. Converts raw source inputs into plain Python dicts.
    Stateless: no state is maintained between calls.

    The orchestrator calls ingest(source_type, raw) once per event, where raw
    is a pre-parsed dict. The per-source methods (ingest_nra, ingest_winlog,
    ingest_mock) also accept file path strings for direct or CLI use.

    No field transformation is performed. All schema mapping is deferred to
    normalize.py per CLAUDE.md §2 pipeline order.
    """

    _VALID_SOURCES: frozenset[str] = frozenset({"nra", "winlog", "mock"})

    _DISPATCH: dict[str, str] = {
        "nra":    "ingest_nra",
        "winlog": "ingest_winlog",
        "mock":   "ingest_mock",
    }

    def ingest(self, source_type: str, raw: object) -> dict:
        """
        Orchestrator entry point. Dispatches to the source-specific method.

        Args:
            source_type: "nra", "winlog", or "mock"
            raw:         pre-parsed dict (from orchestrator) or file path str

        Returns:
            Raw event dict, unmodified beyond file-to-dict conversion.

        Raises:
            ValueError:          unknown source_type or empty result dict
            TypeError:           raw is neither dict nor str
            OSError:             file cannot be read
            NotImplementedError: unsupported binary format (e.g. .evtx)
        """
        if source_type not in self._VALID_SOURCES:
            raise ValueError(
                f"Unknown source_type {source_type!r}. "
                f"Must be one of {sorted(self._VALID_SOURCES)!r}."
            )
        method = getattr(self, self._DISPATCH[source_type])
        return method(raw)

    def ingest_nra(self, raw: object) -> dict:
        """
        Ingest a single NRA (Nmap Recon Analyzer) event.

        Accepted inputs:
            dict — pre-parsed Nmap event dict (primary path via orchestrator)
            str  — file path to a .xml or .json Nmap output file

        Supported file formats:
            .xml  — standard Nmap XML output, parsed with stdlib xml.etree
            .json — Nmap JSON export

        Returns:
            Raw NRA dict. No field renaming or value mapping is applied.
        """
        if isinstance(raw, dict):
            return _validate_dict(raw, "ingest_nra")

        if isinstance(raw, str):
            ext = _ext(raw)
            if ext == ".xml":
                from core.pipeline.nra_parser import parse_scan
                hosts = parse_scan(raw)
                if not hosts:
                    raise ValueError(f"ingest_nra: no hosts found in {raw!r}")
                return _validate_dict(hosts[0], "ingest_nra[xml]")
            if ext == ".json":
                return _validate_dict(_read_json(raw), "ingest_nra[json]")
            raise ValueError(
                f"ingest_nra: unsupported file extension {ext!r} ({raw!r}). "
                f"Supported: .xml, .json"
            )

        raise TypeError(
            f"ingest_nra: expected dict or file path str, "
            f"got {type(raw).__name__!r}"
        )

    def ingest_winlog(self, raw: object) -> dict:
        """
        Ingest a single Windows event log record.

        Accepted inputs:
            dict — pre-parsed event dict (e.g. from Winlogbeat JSON pipeline)
            str  — file path to a .json or .xml Windows log export

        Supported file formats:
            .json — Winlogbeat or evtxexport JSON output
            .xml  — Windows Event Log XML export (single-event XML fragment)
            .evtx — NOT supported without an external library.
                    Pre-convert using winlogbeat, python-evtx, or evtxexport.

        Returns:
            Raw Winlog dict. No field renaming or value mapping is applied.
        """
        if isinstance(raw, dict):
            return _validate_dict(raw, "ingest_winlog")

        if isinstance(raw, str):
            ext = _ext(raw)
            if ext == ".json":
                return _validate_dict(_read_json(raw), "ingest_winlog[json]")
            if ext == ".xml":
                return _validate_dict(_read_xml(raw), "ingest_winlog[xml]")
            if ext == ".evtx":
                from core.pipeline.winlog_parser import parse_evtx
                events = parse_evtx(raw)
                if not events:
                    raise ValueError(f"ingest_winlog: no events found in {raw!r}")
                return _validate_dict(events[0], "ingest_winlog[evtx]")
            raise ValueError(
                f"ingest_winlog: unsupported file extension {ext!r} ({raw!r}). "
                f"Supported: .evtx, .json, .xml"
            )

        raise TypeError(
            f"ingest_winlog: expected dict or file path str, "
            f"got {type(raw).__name__!r}"
        )

    def ingest_mock(self, raw: object) -> dict:
        """
        Ingest a single mock/simulated attack event.

        Accepted inputs:
            dict — pre-constructed mock event dict
            str  — file path to a .json mock data file (data/samples/)

        Supported file formats:
            .json — simulated attack JSON (data/samples/simulated_attack.json)

        Returns:
            Raw mock event dict. No field renaming or value mapping is applied.
        """
        if isinstance(raw, dict):
            return _validate_dict(raw, "ingest_mock")

        if isinstance(raw, str):
            ext = _ext(raw)
            if ext == ".json":
                return _validate_dict(_read_json(raw), "ingest_mock[json]")
            raise ValueError(
                f"ingest_mock: unsupported file extension {ext!r} ({raw!r}). "
                f"Supported: .json"
            )

        raise TypeError(
            f"ingest_mock: expected dict or file path str, "
            f"got {type(raw).__name__!r}"
        )
