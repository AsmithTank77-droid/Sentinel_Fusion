# Sentinel_Fusion — System Architecture Design

**Version:** 1.0  
**Date:** 2026-05-11  
**Status:** Authoritative

---

## Table of Contents

1. [System Purpose](#1-system-purpose)
2. [Design Philosophy](#2-design-philosophy)
3. [High-Level Architecture](#3-high-level-architecture)
4. [Data Flow](#4-data-flow)
5. [Pipeline Stages](#5-pipeline-stages)
   - [Stage 1 — Ingest](#stage-1--ingest)
   - [Stage 2 — Normalize](#stage-2--normalize)
   - [Stage 3 — Enrich](#stage-3--enrich)
   - [Stage 4 — Correlate](#stage-4--correlate)
   - [Stage 5 — Detect](#stage-5--detect)
   - [Stage 6 — Score](#stage-6--score)
   - [Stage 7 — Timeline](#stage-7--timeline)
   - [Stage 8 — Report](#stage-8--report)
6. [Telemetry Sources](#6-telemetry-sources)
   - [Network Telemetry (NRA)](#network-telemetry-nra)
   - [Host Telemetry (Windows Event Logs)](#host-telemetry-windows-event-logs)
7. [Detection Engineering](#7-detection-engineering)
   - [Correlation Engine](#correlation-engine)
   - [Stateless Detectors](#stateless-detectors)
   - [WINLOG Behavioral Rules](#winlog-behavioral-rules)
8. [Risk Scoring Model](#8-risk-scoring-model)
9. [Intelligence Layer](#9-intelligence-layer)
10. [Narrative Engine](#10-narrative-engine)
11. [Reporting Layer](#11-reporting-layer)
12. [Storage Layer](#12-storage-layer)
13. [REST API](#13-rest-api)
14. [SOC Workflow Integration](#14-soc-workflow-integration)
15. [Module Dependency Map](#15-module-dependency-map)
16. [Constraints and Invariants](#16-constraints-and-invariants)

---

## 1. System Purpose

Sentinel_Fusion is a SOC detection and correlation engine. It ingests heterogeneous security telemetry, runs it through a strict 8-stage processing pipeline, and produces structured outputs that give SOC analysts a complete, explainable picture of observed activity — including host risk scores, attack chains, MITRE ATT&CK mappings, Windows behavioral alerts, and per-service triage recommendations.

The system was built by fusing two existing analyzers:

| Analyzer | Origin | What it contributes |
|----------|--------|---------------------|
| `nmap-recon-analyzer` | Network scanning | Nmap XML parsing, service risk scoring, CVE mapping, SOC triage recommendations |
| `winlog-soc-analyzer` | Host telemetry | Windows Event Log parsing, 9 behavioral correlation rules |

Fusion means a single pipeline processes both sources simultaneously, correlating network exposure with host-level behavioral indicators to produce a unified threat picture.

---

## 2. Design Philosophy

Three principles govern every design decision in this system:

**Determinism over randomness** — Given identical input, the system produces identical output. No random sampling, no probabilistic approximations, no non-deterministic data structures in hot paths.

**Traceability over abstraction** — Every detection, score, and recommendation can be traced back to the specific event(s) that caused it. No black-box inference.

**Explainability over complexity** — Analysts must be able to read any output and understand why it was produced without reading source code. MITRE mappings, CVE references, rule IDs, confidence scores, and action rationale are first-class output fields.

---

## 3. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        TELEMETRY SOURCES                            │
│                                                                     │
│  ┌──────────────┐   ┌──────────────────┐   ┌───────────────────┐   │
│  │  Nmap XML    │   │  Windows .evtx / │   │  Simulated Attack  │   │
│  │  (.xml)      │   │  JSON event log  │   │  JSON             │   │
│  └──────┬───────┘   └────────┬─────────┘   └────────┬──────────┘   │
│         └──────────────────┬─┘                      │               │
│                             └──────────────────────┬─┘              │
└─────────────────────────────────────────────────────┼───────────────┘
                                                       │
                                          ┌────────────▼─────────────┐
                                          │     CORE PIPELINE        │
                                          │                          │
                                          │  1. Ingest               │
                                          │  2. Normalize            │
                                          │  3. Enrich               │
                                          │  4. Correlate            │
                                          │  5. Detect               │
                                          │  6. Score                │
                                          │  7. Timeline             │
                                          │  8. Report               │
                                          └────────────┬─────────────┘
                            ┌─────────────────────────┬┘
                            │                         │
              ┌─────────────▼──────────┐  ┌──────────▼────────────┐
              │    STORAGE LAYER       │  │    OUTPUT              │
              │  SQLite via            │  │  JSON report           │
              │  StorageLayer.         │  │  Markdown report       │
              │  persist_run()         │  │  REST API responses    │
              └────────────────────────┘  └───────────────────────┘
                            │
              ┌─────────────▼──────────┐
              │    REST API / CLI      │
              │  FastAPI /api/v1/*     │
              │  Click CLI (sentinel)  │
              └────────────────────────┘
```

---

## 4. Data Flow

Data moves through the pipeline in a single, forward-only pass. No stage reads from a later stage. No stage writes back to an earlier stage.

```
Raw files
    │
    ▼
[Ingest] ──────────────────────────────────────── raw dicts (list[dict])
    │
    ▼
[Normalize] ────────────────────────────────────── NormalizedEvent objects
    │                                              (timestamp, source_type,
    │                                               src_ip, dst_ip,
    │                                               event_type, severity,
    │                                               metadata)
    ▼
[Enrich] ───────────────────────────────────────── NormalizedEvent objects
    │                                              (metadata["enrichment"]
    │                                               added; all other fields
    │                                               immutable from here)
    ▼
[Correlate] ────────────────────────────────────── chain alert dicts
    │
    ▼
[Detect] ───────────────────────────────────────── detection alert dicts
    │                                              (confidence-scored,
    │                                               MITRE-mapped)
    ▼
[Score] ────────────────────────────────────────── scores dict
    │                                              {host_risk, asset_risk,
    │                                               attack_surface}
    ▼
[Timeline] ──────────────────────────────────────── timeline list[dict]
    │                                               + SOC narrative string
    ▼
[Report] ────────────────────────────────────────── {"json": dict,
                                                      "markdown": str}
```

The orchestrator (`core/pipeline/orchestrator.py`) drives this sequence. It is the only module that calls stage modules directly and the only caller of `StorageLayer.persist_run()`.

---

## 5. Pipeline Stages

### Stage 1 — Ingest

**Module:** `core/pipeline/ingest.py`  
**Input:** File paths (str or Path)  
**Output:** `list[dict]` — raw source records, one dict per host or event

Responsibilities:
- Dispatch to the appropriate parser based on file type
- `nra_parser.py` — parses Nmap XML; produces one dict per `<host>` element with a `ports` list
- `winlog_parser.py` — parses `.evtx` binary format (requires `python-evtx`) or `.json` event arrays
- No transformation, classification, or field renaming occurs here

Invariant: Raw data from ingest is never passed beyond normalization. If a file is unreadable, ingest raises immediately rather than producing partial output.

---

### Stage 2 — Normalize

**Module:** `core/pipeline/normalize.py`  
**Input:** `list[dict]` from ingest  
**Output:** `list[NormalizedEvent]`

The `NormalizedEvent` class defines the unified event schema:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | str | ISO-8601 UTC |
| `source_type` | str | `"nra"` / `"winlog"` / `"mock"` |
| `src_ip` | str | Attacker or scanner IP |
| `dst_ip` | str | Target host IP |
| `event_type` | str | Normalized event type label |
| `severity` | int | 0–10 severity scale |
| `metadata` | dict | Source-specific fields |

`NormalizedEvent` enforces:
- `source_type` must be one of the three valid values (raises `ValueError` otherwise)
- `severity` must be `int` in `[0, 10]` (raises `TypeError` otherwise)
- `metadata` must be `dict` (raises `TypeError` otherwise)

No raw source structure passes beyond this stage. Every downstream module works against `NormalizedEvent` or its serialized form (`NormalizedEvent.to_dict()`).

For NRA events: `src_ip` = scanner IP (often empty), `dst_ip` = scanned host IP, ports live in `metadata["ports"]`.  
For Winlog events: `src_ip` = originating IP, `dst_ip` = target computer, event fields live in `metadata`.

---

### Stage 3 — Enrich

**Module:** `core/pipeline/enrich.py`  
**Input:** `list[NormalizedEvent]`  
**Output:** `list[NormalizedEvent]` (same objects, `metadata["enrichment"]` populated)

Enrichment writes exclusively to `event.metadata["enrichment"]`. All other event fields are immutable after normalization. This ensures the original event data is always preserved separately from derived intelligence.

Enrichment providers called per event:

| Provider | Module | What it adds |
|----------|--------|--------------|
| IP Reputation | `intelligence/ip_reputation.py` | `is_malicious`, `confidence`, `tags` |
| Geo Enrichment | `intelligence/geo_enrichment.py` | `country`, `city`, `asn`, `org` |
| Threat Feeds | `intelligence/threat_feeds.py` | `in_blocklist`, `tor_exit_node`, `feed_sources` |
| Context Builder | `core/pipeline/context_builder.py` | Host/asset context, observed service inventory |

Rules for enrichment modules:
- Stateless — no state between calls
- No detection, scoring, or reporting logic
- Accept `NormalizedEvent` only
- Call intelligence modules only

---

### Stage 4 — Correlate

**Module:** `detection/correlation_engine.py`  
**Input:** `list[dict]` (enriched events serialized via `to_dict()`)  
**Output:** `list[dict]` — correlated chain alert dicts

The `CorrelationEngine` groups events by `src_ip` into multi-stage attack chains. A chain requires at least 2 events from the same source. Chains are scored by the progression of observed event types through a severity-weighted stage ladder:

```
port_scan (1) → authentication_failure (2) → authentication_success (3)
             → lateral_movement (4) → privilege_escalation (5)
```

Chain confidence increases with stage depth and event count. Each chain alert includes:
- Ordered event types observed
- All targeted `dst_ip` values
- First and last timestamp
- Max severity across all chain events
- MITRE tactics observed
- Enrichment summary (Tor flags, malicious IPs, geo data)

---

### Stage 5 — Detect

**Modules:** `detection/brute_force_detection.py`, `detection/lateral_movement_detection.py`, `detection/anomaly_detection.py`, `detection/winlog_rules.py`  
**Input:** Enriched event dicts + correlated chain alerts from Stage 4  
**Output:** `list[dict]` — detection alerts, each with a confidence score (0–1)

All detectors are stateless. Each receives the full event set and produces zero or more alerts. Alerts include:

- `alert_type` — unique identifier (e.g., `WINLOG-002`, `brute_force`, `lateral_movement`)
- `confidence` — float in `[0, 1]`
- `mitre_tactic` / `mitre_technique` — ATT&CK mapping
- `src_ip`, `dst_ip` — who attacked whom
- `reason` — human-readable description of what triggered the alert

Detectors are described in detail in [§7 Detection Engineering](#7-detection-engineering).

---

### Stage 6 — Score

**Modules:** `scoring/host_risk.py`, `scoring/asset_risk.py`, `scoring/attack_surface.py`  
**Input:** Enriched events, detection alerts  
**Output:** `dict` with keys `host_risk`, `asset_risk`, `attack_surface`

Scoring is described in detail in [§8 Risk Scoring Model](#8-risk-scoring-model).

---

### Stage 7 — Timeline

**Module:** `narrative/timeline_builder.py`  
**Input:** Enriched events, detection alerts, scores  
**Output:** `list[dict]` — chronological timeline entries + embedded SOC narrative

The `TimelineBuilder` merges events and alerts into a unified chronological sequence. Each entry captures what happened, when, between which hosts, at what severity, and which MITRE tactic it maps to. After assembly, it calls `AttackStoryEngine.narrate()` to generate a human-readable Markdown narrative and embeds it as a special `entry_type="narrative"` entry at the end of the timeline.

The `AttackStoryEngine` is called exclusively from `TimelineBuilder` — never from detection or scoring modules.

---

### Stage 8 — Report

**Module:** `reporting/report_generator.py`  
**Input:** Timeline, scores, alerts, normalized events  
**Output:** `{"json": dict, "markdown": str}`

The report generator produces two output formats simultaneously:

- **JSON** — machine-readable, complete structured data for downstream SIEM/SOAR integration
- **Markdown** — human-readable SOC analyst report with executive summary, host risk tables, detection alerts, attack timeline, SOC narrative, and NRA triage recommendations

The `normalized_events` parameter is required to reconstruct NRA port data for the recommended actions engine, because `timeline_builder` strips `source_type` from timeline entries.

Internal call sequence within Stage 8:
```
report_generator.generate()
    ├── _build_nra_scan_data(normalized_events, host_risk)
    ├── generate_recommendations(scan_data)          # reporting/recommended_actions.py
    ├── ExecutiveSummary().generate(...)              # reporting/executive_summary.py
    └── _build_markdown(...)
```

---

## 6. Telemetry Sources

### Network Telemetry (NRA)

Sentinel_Fusion ingests Nmap scan results to build a picture of network-level exposure.

**Source format:** Nmap XML (`.xml`) parsed by `nra_parser.py`; JSON array of host dicts as fallback.

**What is captured per host:**
- All open/filtered/closed ports with service identification
- Protocol (tcp/udp)
- Nmap service version strings (mapped to canonical service names)

**How it flows through the pipeline:**
- Ingest: one dict per `<host>` element, with `ports` list in metadata
- Normalize: `source_type="nra"`, `dst_ip=<host IP>`, `src_ip=""` (scanner), `event_type="port_scan"`
- Enrich: IP reputation and geo data added to each host's enrichment block
- Score: `host_risk.py` applies 4-component NRA scoring (see §8)
- Report: `reporting/recommended_actions.py` generates per-port SOC triage recommendations

**Service intelligence:** `intelligence/service_intelligence.py` provides risk scores (0–10 scale) for 30+ protocols, CVE associations, MITRE attack phases, cleartext protocol flags, and anonymous-access risk flags.

---

### Host Telemetry (Windows Event Logs)

Sentinel_Fusion ingests Windows Security Event Logs to detect behavioral indicators of attack.

**Source format:** `.evtx` binary (parsed via `python-evtx`) or JSON array of event dicts.

**Key Event IDs monitored:**

| Event ID | Name | Significance |
|----------|------|--------------|
| 4624 | Successful Logon | Authentication baseline; Logon Type 3 = network |
| 4625 | Failed Logon | Brute-force indicator |
| 4648 | Explicit Credential Logon | Lateral movement via credential reuse |
| 4672 | Special Privileges Assigned | Privilege escalation signal |
| 4697 | Service Installed | Persistence via new service |
| 4698 | Scheduled Task Created | Persistence via task scheduler |
| 4719 | Audit Policy Changed | Defense evasion |
| 4728/4732/4756 | Group Membership Change | Backdoor account creation |
| 7045 | New Service Installed (System log) | Alternate persistence indicator |
| 1102 | Audit Log Cleared | Evidence tampering |

**Event intelligence:** `intelligence/event_intelligence.py` maps every Event ID to name, category, severity, MITRE technique, MITRE tactic, and analyst notes.

---

## 7. Detection Engineering

### Correlation Engine

The correlation engine (Stage 4) is the first detection layer. It operates on the full event set and identifies multi-source, multi-stage attack chains before any individual detector runs.

**Chain construction:**
1. Group all events by `src_ip`
2. For each source with ≥ 2 events, build a chain
3. Score chain confidence using the stage weight ladder
4. Emit a `correlated_attack_chain` alert per qualifying source

Chain confidence formula:
```
base_confidence = max_stage_weight / 5.0
boost = min(len(events) / 10.0, 0.3)
confidence = min(base_confidence + boost, 1.0)
```

---

### Stateless Detectors

All detectors in Stage 5 operate independently on the same event set. They cannot share state and cannot call each other.

| Detector | Module | Detection method |
|----------|--------|-----------------|
| `BruteForceDetector` | `brute_force_detection.py` | Counts `authentication_failure` events per `src_ip` within a sliding time window; fires when threshold exceeded |
| `LateralMovementDetector` | `lateral_movement_detection.py` | Detects `authentication_success` following `authentication_failure` to a different host than the initial target |
| `AnomalyDetector` | `anomaly_detection.py` | Flags statistically unusual patterns in event timing and frequency |
| `WinlogRulesDetector` | `winlog_rules.py` | 9 behavioral rules (see below) |

---

### WINLOG Behavioral Rules

The nine WINLOG rules implement behavioral correlation over Windows event sequences. Each rule is stateless and operates on the full Winlog event set.

| Rule | Event IDs | Window | What it detects | MITRE |
|------|-----------|--------|-----------------|-------|
| WINLOG-001 | 4625 | 60s | Brute-force burst (≥5 failures from same source) | T1110 Brute Force |
| WINLOG-002 | 4625 + 4624 | 120s | Brute-force success — credential compromise | T1110 Brute Force |
| WINLOG-003 | 4728/4732/4756 | 300s | Backdoor account added to security group | T1098 Account Manipulation |
| WINLOG-004 | 4648 + 4624 type 3 | 120s | Lateral movement via explicit credentials | T1078 Valid Accounts |
| WINLOG-005 | 4624 type 3 + 4672 | 30s | Privilege escalation after remote logon | T1134 Token Impersonation |
| WINLOG-006 | 1102 | — | Audit log cleared — evidence tampering | T1070.001 Clear Windows Event Logs |
| WINLOG-007 | 4719 | — | Audit policy changed | T1562.002 Impair Defenses |
| WINLOG-008 | 4697/7045 | — | New service installed — persistence | T1543.003 Windows Service |
| WINLOG-009 | 4698 | — | Scheduled task created — persistence | T1053.005 Scheduled Task |

**Time-windowed rules** (WINLOG-001 through WINLOG-005) use a sliding window approach: events are sorted by timestamp, and for each candidate event, the window looks backward across all events from the same source within the configured interval.

**Instant rules** (WINLOG-006 through WINLOG-009) fire on a single event — no windowing required.

---

## 8. Risk Scoring Model

Three complementary scoring dimensions produce the complete risk picture.

### Host Risk (`scoring/host_risk.py`)

Per-host risk score on a 0–10 scale. For NRA hosts (scanned by Nmap), a 4-component composite score drives the result:

| Component | Max Points | What it measures |
|-----------|-----------|-----------------|
| Service Risk | 40 | Weighted average of service risk scores for all open ports |
| Exposure Risk | 25 | Non-standard ports, dangerous service combinations (SMB+RDP, SSH+MySQL) |
| Attack Surface | 20 | Total open port count, dangerous individual services |
| Threat Context | 15 | Malicious IP flags, Tor exit node, blocklist presence |

The 100-point composite is mapped to a 0–10 output score and labeled:

| Score | Label |
|-------|-------|
| 75–100 → 7.5–10 | Critical |
| 55–74 → 5.5–7.4 | High |
| 35–54 → 3.5–5.4 | Medium |
| 15–34 → 1.5–3.4 | Low |
| 0–14 → 0–1.4 | Low |

For Winlog and mock events, host risk is calculated from alert count, max alert severity, and enrichment signals.

**Dangerous service combinations** that trigger exposure risk bonuses:
- SMB + RDP → ransomware staging environment
- SSH + MySQL → lateral movement and data exfiltration path
- Telnet + FTP → cleartext credential exposure across multiple services

### Asset Exposure (`scoring/asset_risk.py`)

Per-asset (host or service endpoint) exposure score on 0–10 scale. Factors:
- Alert count and max severity for that asset
- Whether the asset is a confirmed lateral movement target
- Enrichment signals on events targeting the asset

### Attack Surface Expansion (`scoring/attack_surface.py`)

Batch-level metric describing the breadth of observed attacker activity:

| Metric | What it measures |
|--------|-----------------|
| `unique_external_sources` | Distinct attacker IPs observed |
| `unique_internal_targets` | Distinct internal hosts reached |
| `unique_attack_techniques` | Distinct event types observed |
| `lateral_movement_hops` | Number of confirmed pivot hops |
| `mitre_tactics_observed` | Distinct ATT&CK tactics seen |
| `expansion_score` | 0–10 composite of the above |
| `expansion_label` | `minimal` / `moderate` / `significant` / `critical` |

---

## 9. Intelligence Layer

The intelligence layer provides static and semi-static knowledge bases consumed by the enrichment and scoring stages. All modules are read-only — they never write to the database or modify pipeline state.

| Module | Purpose |
|--------|---------|
| `intelligence/service_intelligence.py` | Network service risk scores, CVEs, MITRE attack phases, cleartext flags, dangerous combos |
| `intelligence/event_intelligence.py` | Windows Event ID → name, category, severity, MITRE technique, analyst notes |
| `intelligence/ip_reputation.py` | IP classification: malicious, suspicious, Tor exit, scanner |
| `intelligence/geo_enrichment.py` | IP → country, city, ASN, org |
| `intelligence/threat_feeds.py` | Blocklist membership, feed source tracking |

`service_intelligence.py` also exposes `analyze(service, port, risk_label)` which returns a structured intel dict used by the recommended actions engine.

---

## 10. Narrative Engine

**Modules:** `narrative/timeline_builder.py`, `narrative/attack_story_engine.py`

The narrative engine converts machine-readable detections into a human-readable SOC story. It is the only layer that synthesizes across all prior pipeline stages into natural language.

**Timeline construction** (`TimelineBuilder`):
- Merges enriched events and alerts into a unified chronological sequence
- Each entry records: timestamp, entry type, event type, src/dst IPs, severity, confidence, MITRE tactic, risk context snippet
- Timeline is sorted by timestamp; entries without timestamps sort to the end

**SOC narrative** (`AttackStoryEngine`):
- Receives the assembled timeline and alert list
- Produces a multi-paragraph Markdown narrative organized around observed attack phases
- Describes: initial access method, affected hosts, behavioral indicators, attacker progression, persistence mechanisms, evidence tampering

The `AttackStoryEngine` is called exclusively from `TimelineBuilder`. Detection, scoring, and reporting modules must not call it directly.

---

## 11. Reporting Layer

**Modules:** `reporting/report_generator.py`, `reporting/executive_summary.py`, `reporting/recommended_actions.py`

### Report Generator

Produces the final dual-format output. Takes all prior stage outputs as input. Internally:
1. Reconstructs NRA port data from `normalized_events` (not from timeline — timeline strips `source_type`)
2. Calls `generate_recommendations()` to produce per-port SOC triage
3. Calls `ExecutiveSummary().generate()` to produce the CISO-facing summary
4. Serializes everything into JSON and Markdown

### Executive Summary

CISO-facing verdict with supporting evidence. Verdict determination:

```
Critical  ← any host with risk_label == "critical"
High      ← any host with risk_label == "high" OR lateral movement detected
Medium    ← any host with risk_label == "medium" OR any alerts present
Low       ← any host with risk_label == "low"
Clean     ← no risk indicators observed
```

Output fields: `verdict`, `key_findings` (list), `immediate_actions` (list), `risk_surface` (metrics dict), `markdown`.

WINLOG rules WINLOG-002, WINLOG-003, WINLOG-006, and WINLOG-009 automatically inject pre-defined immediate actions when fired, as these indicate credential compromise, backdoor accounts, evidence tampering, and persistence respectively.

### Recommended Actions Engine

Per-port SOC triage for every host in the NRA scan data. For each open port:
- Service context (what this service is and why it matters)
- Risk rationale (why this specific configuration is dangerous)
- Recommended action (concrete remediation steps)
- Notable CVEs (service-specific known vulnerabilities)
- Priority (1=Critical through 5=Informational)
- MITRE category and subcategory

Output is structured as a list of host objects, each containing a list of port recommendations sorted by priority (Critical first).

---

## 12. Storage Layer

**Modules:** `storage/database.py`, `storage/schema.py`, `storage/models.py`, `storage/store.py`, `storage/repositories/`

### Architecture

```
StorageLayer (store.py)
    ├── Database (database.py)         SQLite connection, WAL mode, migrations
    ├── EventRepository                events table
    ├── AlertRepository                alerts table
    ├── CaseRepository                 cases table
    ├── ScoreRepository                scores table
    └── AuditRepository                audit_log table
```

### Rules

- `StorageLayer.persist_run()` is the **only** method that writes a complete pipeline result. All other writes are coordinated through `StorageLayer` — repositories do not call each other.
- SQLite runs in WAL mode for concurrent read access.
- Schema changes require a new entry in the `MIGRATIONS` dict in `schema.py`. Existing migration statements are never modified.
- The repository pattern isolates the database backend. Swapping SQLite for PostgreSQL requires replacing only the `Database` connection object.

### Data Models

| Model | Table | Key fields |
|-------|-------|-----------|
| `StoredEvent` | `events` | `run_id`, `source_type`, `event_type`, `src_ip`, `dst_ip`, `severity`, `metadata` |
| `StoredAlert` | `alerts` | `run_id`, `alert_type`, `confidence`, `mitre_tactic`, `src_ip`, `dst_ip` |
| `StoredCase` | `cases` | `run_id`, `status`, `priority`, `assigned_to`, `notes` |
| `StoredScore` | `scores` | `run_id`, `score_type`, `entity`, `score`, `label` |
| `AuditEntry` | `audit_log` | `run_id`, `stage`, `action`, `detail`, `timestamp` |
| `PipelineRun` | `pipeline_runs` | `run_id`, `status`, `started_at`, `completed_at`, `summary` |

---

## 13. REST API

**Module:** `api/` — FastAPI application  
**Base URL:** `/api/v1`  
**Docs:** `http://localhost:8000/api/docs` (Swagger UI) · `http://localhost:8000/api/redoc`

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Health check, DB connectivity |
| `GET` | `/api/v1/status` | Summary: event/alert/run counts, top risk hosts |
| `POST` | `/api/v1/pipeline/run` | Submit events for a pipeline run |
| `GET` | `/api/v1/pipeline/runs` | List pipeline run history |
| `GET` | `/api/v1/events` | Query stored events (filter by type, source, severity) |
| `GET` | `/api/v1/alerts` | Query stored alerts (filter by type, confidence, host) |
| `GET` | `/api/v1/scores/hosts` | Host risk scores |
| `GET` | `/api/v1/scores/assets` | Asset exposure scores |
| `GET` | `/api/v1/intel/service/{name}` | Service threat intelligence lookup |
| `GET` | `/api/v1/intel/event/{id}` | Windows Event ID lookup |
| `GET` | `/api/v1/cases` | Case management |
| `GET` | `/dashboard` | Static web dashboard |

### Request/Response

`POST /api/v1/pipeline/run` accepts a JSON body with event arrays in the normalized event schema. It runs the full 8-stage pipeline synchronously and returns the complete report JSON plus a run ID.

All list endpoints support pagination (`limit`, `offset`) and filtering parameters defined in `api/schemas/requests.py`.

---

## 14. SOC Workflow Integration

Sentinel_Fusion is designed to fit into an existing SOC workflow at two integration points:

**1. Batch analysis** (primary use case):  
The CLI (`sentinel run`) ingests scan files and logs, runs the full pipeline, writes to the database, and produces a Markdown report. This fits into a daily/shift-based analysis workflow where analysts receive a generated report for review.

**2. API-driven integration:**  
The REST API allows upstream systems (SIEM, SOAR, scan orchestrators) to submit event data and receive structured JSON responses. Alerts can be queried by confidence threshold for escalation routing.

**Analyst outputs at each layer:**

| Layer | Analyst artifact |
|-------|-----------------|
| Detection | Alert list with rule ID, confidence, MITRE mapping, source/target IPs |
| Scoring | Host risk table (score/label), asset exposure table, attack surface metrics |
| Timeline | Chronological event sequence showing attacker progression |
| Narrative | Plain-English SOC story describing the attack campaign |
| Executive Summary | Verdict + key findings + numbered immediate actions for CISO/management |
| NRA Triage | Per-port remediation steps with CVE references and priority ordering |

---

## 15. Module Dependency Map

```
orchestrator.py
│
├── core/pipeline/ingest.py
│       ├── core/pipeline/nra_parser.py
│       └── core/pipeline/winlog_parser.py
│
├── core/pipeline/normalize.py
│
├── core/pipeline/enrich.py
│       ├── intelligence/ip_reputation.py
│       ├── intelligence/geo_enrichment.py
│       ├── intelligence/threat_feeds.py
│       └── core/pipeline/context_builder.py
│
├── detection/correlation_engine.py
│
├── detection/brute_force_detection.py
├── detection/lateral_movement_detection.py
├── detection/anomaly_detection.py
├── detection/winlog_rules.py
│       └── intelligence/event_intelligence.py
│
├── scoring/host_risk.py
│       └── intelligence/service_intelligence.py
├── scoring/asset_risk.py
└── scoring/attack_surface.py
│       └── core/utils/ip_utils.py
│
├── narrative/timeline_builder.py
│       └── narrative/attack_story_engine.py
│
├── reporting/report_generator.py
│       ├── reporting/recommended_actions.py
│       │       └── intelligence/service_intelligence.py
│       └── reporting/executive_summary.py
│
└── storage/store.py
        ├── storage/database.py
        ├── storage/schema.py
        ├── storage/models.py
        └── storage/repositories/
                ├── events.py
                ├── alerts.py
                ├── cases.py
                ├── scores.py
                └── audit.py
```

---

## 16. Constraints and Invariants

These rules are enforced across the codebase and must not be violated by new contributions:

1. **Pipeline order is strict.** No stage may be skipped or reordered. The 8-stage sequence is an invariant.

2. **Normalization is a one-way gate.** Raw source data never passes beyond `normalize.py`. All downstream modules work against `NormalizedEvent` or its dict serialization.

3. **Enrichment writes to one key only.** `event.metadata["enrichment"]` is the only location enrichment modules may write to. All other event fields are immutable after normalization.

4. **Detection modules are stateless.** No detector maintains state between calls. All context needed for detection must be derivable from the event batch passed to the `detect()` call.

5. **`AttackStoryEngine` has one caller.** Only `TimelineBuilder` may call `AttackStoryEngine.narrate()`.

6. **`StorageLayer.persist_run()` is the sole write entrypoint.** No other caller may write a complete pipeline result. Repositories do not call each other.

7. **Schema changes require a migration entry.** Existing migration statements in `schema.py` are never modified — only new entries are added.

8. **No new top-level folders without architecture fit.** New modules must fit into an existing pipeline layer or explicitly extend one of the 11 core systems.

9. **No ML dependencies.** The system uses only Python stdlib plus `fastapi`, `uvicorn`, `click`, and `rich` for interface layers. No numpy, scikit-learn, or ML frameworks.

10. **Determinism.** Given identical input, identical output. No random state in the scoring, detection, or reporting paths.

---

*Sentinel_Fusion SOC Pipeline — Architecture Design v1.0*
