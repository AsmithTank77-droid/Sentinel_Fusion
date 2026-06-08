# Sentinel_Fusion: Complete Study Guide

> A module-by-module breakdown of every component, engine, and design decision in the Sentinel_Fusion SOC Detection & Correlation Platform.

---

## Table of Contents

1. [The Problem Sentinel_Fusion Solves](#1-the-problem-sentinel_fusion-solves)
2. [Why a Pipeline? The Core Architecture Decision](#2-why-a-pipeline-the-core-architecture-decision)
3. [Stage 1 — Ingest](#3-stage-1--ingest)
4. [Stage 2 — Normalize](#4-stage-2--normalize)
5. [Stage 3 — Enrich](#5-stage-3--enrich)
6. [Stage 4 — Sigma](#6-stage-4--sigma)
7. [Stage 5 — Correlate](#7-stage-5--correlate)
8. [Stage 6 — Detect](#8-stage-6--detect)
9. [Stage 7 — Score](#9-stage-7--score)
10. [Stage 8 — Timeline](#10-stage-8--timeline)
11. [Stage 9 — Report](#11-stage-9--report)
12. [Stage 10 — Hunt](#12-stage-10--hunt)
13. [The Intelligence Layer](#13-the-intelligence-layer)
14. [The Storage Layer](#14-the-storage-layer)
15. [The REST API](#15-the-rest-api)
16. [The CLI and Watch Mode](#16-the-cli-and-watch-mode)
17. [Design Philosophy and Hard Rules](#17-design-philosophy-and-hard-rules)

---

## 1. The Problem Sentinel_Fusion Solves

### What is the real-world problem?

A Security Operations Center (SOC) analyst sits in front of screens filled with raw data:

- Nmap scans showing which hosts are alive and what services they expose
- Windows Event Logs recording every login, privilege change, and audit policy modification
- Alerts from various tools — some real threats, some noise

The analyst's job is to answer three questions fast:

1. **What is happening on the network right now?**
2. **Which hosts are most at risk?**
3. **What do I do first?**

The problem is that the raw data doesn't answer these questions directly. A login event (Event ID 4624) is just a record — it doesn't tell you whether it's an attacker who just succeeded after 50 failed attempts, or a legitimate user starting their shift. An open RDP port is just a number — it doesn't tell you whether it has BlueKeep patched or not.

**Sentinel_Fusion bridges the gap between raw telemetry and analyst-ready intelligence.**

### What does Sentinel_Fusion actually do?

It takes two types of raw data:

- **Network data**: Nmap XML scan files showing hosts, open ports, running services, and OS fingerprints
- **Host data**: Windows Event Logs (`.evtx` binary files or `.json` arrays) recording security-relevant activity

It runs that data through 8 sequential processing stages and produces:

- A **risk score (0–10)** for every host on the network
- **Structured alerts** with MITRE ATT&CK technique mappings and confidence scores
- A **chronological attack timeline** showing exactly how an incident unfolded
- A **Markdown executive summary** written for CISO-level consumption
- A **JSON report** for downstream tool integration
- **Per-service SOC triage guidance** telling analysts exactly what to check and why

### Why does this matter for your career?

When a recruiter or security engineer looks at Sentinel_Fusion, they see:

- You understand the **full detection lifecycle** — not just writing rules, but ingesting data, normalizing it, enriching it, correlating it, scoring it, and reporting on it
- You understand **MITRE ATT&CK** as a framework for structuring detections
- You can build **production-grade APIs** with authentication, error handling, and structured schemas
- You understand **behavioral correlation** — not just matching individual events, but linking chains of events into attack narratives
- You know what a **SOC analyst actually needs** from a tool

---

## 2. Why a Pipeline? The Core Architecture Decision

### The wrong way: monolithic processing

The simplest approach would be a single function:

```python
def analyze(nmap_file, winlog_file):
    # parse everything
    # detect everything
    # report everything
```

This is fast to write and terrible to maintain. Why? Because every concern is mixed together. If you want to change how you score hosts, you have to understand how parsing works. If you want to add a new data source, you have to understand the reporting format. Testing is nearly impossible.

### The right way: a strict 10-stage pipeline

Sentinel_Fusion uses a **directed acyclic pipeline** where each stage has a single responsibility:

```
Raw Files → [Ingest] → [Normalize] → [Enrich] → [Sigma] → [Correlate] → [Detect] → [Score] → [Timeline] → [Report] → [Hunt] → Output
```

The key constraint: **no stage may be skipped and no stage may access the output of a later stage.**

This is enforced architecturally. The orchestrator (`core/pipeline/orchestrator.py`) calls each stage in order and passes only the correct data to each one.

### Why this matters

**Testability**: Each stage can be tested in complete isolation. You can unit test the normalizer by passing it raw parsed data and asserting on the normalized output — no parsing, no detection, no reporting involved.

**Replaceability**: If you want to swap out the risk scoring algorithm, you change `scoring/host_risk.py` and nothing else breaks.

**Debuggability**: When something goes wrong, you can inspect the output of any individual stage to see exactly where the data changed.

**Composability**: The same pipeline can be run against different input types (Nmap XML, Windows EVTX, JSON mock data) because the ingest stage abstracts all input formats before they reach the rest of the pipeline.

### The orchestrator: the conductor

`core/pipeline/orchestrator.py` is the only file that knows about all 10 stages. It calls them in order, passes outputs from one to the next, handles errors at each stage, and calls the storage layer to persist the final result. Nothing else in the codebase orchestrates the pipeline — this is a hard architectural rule.

---

## 3. Stage 1 — Ingest

**Module**: `core/pipeline/ingest.py`  
**Input**: File paths or raw data structures  
**Output**: Raw Python dicts — no transformation, no interpretation

### What it does

Ingest loads raw data from its source format into Python memory. That's it. No parsing logic. No schema enforcement. No enrichment.

For Nmap XML files, it calls `core/pipeline/nra_parser.py` which uses Python's `xml.etree.ElementTree` to walk the XML tree and extract host records:

```python
# What nra_parser produces (example):
{
    "ip": "10.0.0.10",
    "hostname": "DC01",
    "status": "up",
    "ports": [
        {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "state": "open"},
        {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server", "state": "open"},
    ],
    "os": "Windows Server 2019"
}
```

For `.evtx` binary Windows Event Log files, it calls `core/pipeline/winlog_parser.py` which uses the `python-evtx` library to decode the binary format. For `.json` files, it does a straight `json.load()`.

### Why the strict "no transformation" rule?

This rule exists to make debugging unambiguous. If the normalized data looks wrong, you look at the normalizer. If the raw parsed data looks wrong, you look at the ingest stage. These concerns never mix.

### The mock input path

When you run `sentinel run --mock data/samples/simulated_attack.json`, the ingest stage loads a JSON array of pre-formatted event dicts. This lets you test the entire pipeline without any real scan files — useful for development, testing, and demos.

---

## 4. Stage 2 — Normalize

**Module**: `core/pipeline/normalize.py`  
**Input**: Raw parsed dicts from ingest  
**Output**: `NormalizedEvent` objects with a guaranteed unified schema

### The core problem normalization solves

An Nmap port record looks like this:

```python
{"port": 445, "protocol": "tcp", "service": "microsoft-ds", "state": "open", "ip": "10.0.0.10"}
```

A Windows Event Log record looks like this:

```python
{"EventID": 4625, "Computer": "DC01", "SubjectUserName": "SYSTEM", "IpAddress": "185.220.101.45", "TimeCreated": "2026-05-09T02:00:00Z"}
```

A mock event looks like this:

```python
{"timestamp": "2026-05-09T02:00:00Z", "src_ip": "185.220.101.45", "dst_ip": "10.0.0.10", "event_type": "authentication_failure", "severity": "medium"}
```

Three completely different shapes. Every downstream stage would have to know about all three formats — multiplying complexity by 3 for every new module added.

Normalization collapses all of these into one schema: **`NormalizedEvent`**.

### The NormalizedEvent schema

```python
@dataclass
class NormalizedEvent:
    event_id:    str        # unique ID (uuid4)
    timestamp:   str        # ISO 8601
    source_type: str        # "nra", "winlog", or "mock"
    event_type:  str        # "port_scan", "authentication_failure", etc.
    src_ip:      str
    dst_ip:      str
    severity:    str        # "low", "medium", "high", "critical"
    raw:         dict       # original parsed record, preserved
    metadata:    dict       # source-specific extra fields
```

After normalization, every downstream stage operates on `NormalizedEvent` objects. They never need to know whether the original data came from Nmap, Windows logs, or a mock file.

### Why preserve `raw`?

The `raw` field stores the original parsed record exactly as it came from ingest. This is critical for two reasons:

1. **Debugging**: If a detection fires incorrectly, you can always trace back to the exact original record
2. **Reporting**: The report generator can pull source-specific details (like port numbers, CVE references, event IDs) from `raw` when constructing analyst-facing output

### The `source_type` field

`source_type` tells downstream stages where the event came from without requiring them to inspect the data shape. The WINLOG rules detector checks `source_type == "winlog"` before running Windows-specific rules. The NRA scoring engine checks `source_type == "nra"` before running network-specific logic.

---

## 5. Stage 3 — Enrich

**Module**: `core/pipeline/enrich.py`  
**Input**: List of `NormalizedEvent` objects  
**Output**: Same events with additional metadata attached

### What enrichment adds

Enrichment adds context that wasn't in the original data but is needed for accurate detection and scoring:

**IP Reputation**: Is `185.220.101.45` a known Tor exit node? A Shodan-flagged host? Enrichment adds `is_malicious: True`, `reputation_score: 0.95`, `categories: ["tor", "scanning"]`.

**Geolocation**: Is that IP from Russia, China, or another high-risk country? Enrichment adds `country: "Russia"`, `is_tor: True`, `high_risk_country: True`.

**Service Context**: What does port 445 actually mean in a threat context? Enrichment adds the service intelligence — risk score, threat description, CVE references, MITRE ATT&CK phase.

**Host Context**: The `context_builder.py` module assembles a per-host context object that aggregates all events for a given host. This lets scoring and detection modules ask questions like "how many failed logins has this host seen in the last 5 minutes?" without re-scanning the entire event list.

### The two-tier intelligence model

Enrichment doesn't make live API calls for every event. Instead it uses a tiered approach:

1. **Seed table**: A hardcoded dict of known bad IPs (`185.220.101.45` → Tor exit node). Zero latency, always available.
2. **TTL Cache**: Results from live API calls are cached with a configurable time-to-live (default 1 hour). Subsequent lookups hit cache.
3. **Live API**: AbuseIPDB (if `SENTINEL_ABUSEIPDB_KEY` is set) or ip-api.com (if `SENTINEL_GEO_ENABLED=true`).
4. **Stub fallback**: If live API fails or is disabled, return a safe neutral result.

This means the pipeline works perfectly offline (for testing and air-gapped environments) but can leverage live threat intelligence in production.

---

## 6. Stage 4 — Sigma

**Modules**: `detection/sigma_engine.py`, `detection/sigma_field_mapper.py`
**Input**: Enriched event dicts
**Output**: `list[dict]` — Sigma rule match alerts

The `SigmaEngine` evaluates 10 MITRE ATT&CK-mapped Sigma-compatible rules against enriched events. `sigma_field_mapper.py` first translates normalized field names into Sigma-compatible names so that rule conditions can match correctly. Each matched rule produces a confidence-scored alert dict with `alert_type`, `mitre_tactic`, `mitre_technique`, `severity`, and a human-readable `reason`.

The 10 built-in rules cover: LOLBin abuse, WMI child process spawning, encoded PowerShell, PowerShell download cradle, LSASS memory access, PsExec lateral movement, shadow copy deletion, WMI persistence, network share enumeration, and scheduled task creation.

Sigma alerts are pooled with correlated chain alerts (Stage 5) before the stateless detectors run (Stage 6).

---

## 7. Stage 5 — Correlate

**Module**: `detection/correlation_engine.py`  
**Input**: Enriched `NormalizedEvent` objects  
**Output**: Attack chains — groups of related events that form a coherent attack sequence

### Why correlation is its own stage

Individual events are weak signals. A single failed login could be a mistyped password. A port scan could be a legitimate network inventory. But patterns of related events tell a different story.

Correlation groups events into **attack chains** by asking: which events share source/destination IPs and occur within a plausible time window?

### Attack chain structure

```python
{
    "chain_id":    "abc123",
    "src_ip":      "185.220.101.45",
    "dst_ips":     ["10.0.0.10"],
    "event_types": ["port_scan", "authentication_failure", "authentication_failure", "authentication_success"],
    "timestamps":  ["2026-05-09T02:00:00Z", "2026-05-09T02:00:30Z", ...],
    "confidence":  0.82,
    "alert_type":  "correlated_attack_chain",
    "severity":    "high"
}
```

A chain where an attacker scans ports, then fails to log in 20 times, then succeeds — that's a brute-force-to-compromise sequence. Each individual event is noise. The chain is a finding.

### Pivot chain detection

The most sophisticated correlation capability is **pivot chain detection**. This finds multi-hop lateral movement:

- Chain A: `185.220.101.45` attacks `10.0.0.10`
- Chain B: `10.0.0.10` attacks `10.0.0.11`

These two chains connect: `10.0.0.10` appears as a victim in chain A and as an attacker in chain B. This means the attacker compromised `10.0.0.10` and used it as a pivot point to reach `10.0.0.11`.

The pivot chain detector finds this relationship by checking whether any `dst_ip` in chain A appears as the `src_ip` in chain B, AND chain A started before chain B (temporal ordering).

The resulting alert:

```python
{
    "alert_type":         "correlated_pivot_chain",
    "hop_count":          1,
    "initial_src_ip":     "185.220.101.45",
    "pivot_host":         "10.0.0.10",
    "final_targets":      ["10.0.0.11"],
    "mitre_tactics":      ["TA0008"],  # Lateral Movement
    "confidence":         0.87
}
```

This is the kind of detection that separates a tool from a platform.

---

## 8. Stage 6 — Detect

**Modules**: `detection/brute_force_detection.py`, `detection/lateral_movement_detection.py`, `detection/anomaly_detection.py`, `detection/winlog_rules.py`  
**Input**: Enriched events + correlated attack chains  
**Output**: Structured alert dicts with confidence scores and MITRE mappings

### The stateless detector pattern

All detectors in Sentinel_Fusion are **stateless** — they don't remember anything between pipeline runs. Each run starts fresh. This is intentional:

- Stateless detectors are easy to test: give them input, check the output
- They can run in parallel without coordination
- They're predictable — same input always produces same output

State (if needed) lives in the database, not in the detector.

### BruteForceDetector

Finds rapid repeated authentication failures from the same source IP within a sliding time window.

Configurable thresholds (via `config/settings.py`):
- `SENTINEL_BRUTE_FORCE_THRESHOLD` — number of failures before alert fires (default: 3)
- `SENTINEL_BRUTE_FORCE_WINDOW` — time window in seconds (default: 300)

Algorithm: group events by `src_ip`, sort by timestamp, scan with a sliding window, fire alert when failure count exceeds threshold.

### LateralMovementDetector

Looks for network-layer signs of lateral movement:

- A source IP that successfully connects to multiple different destination IPs
- Use of administrative protocols (SMB port 445, RDP port 3389, WMI port 135) toward internal hosts

### AnomalyDetector

Statistical outlier detection:

- Hosts with unusually high event rates
- Source IPs connecting to an unusually large number of destinations
- Event type distributions that deviate from baseline

### WinlogRulesDetector — The WINLOG Engine

This is the most complex detector. It implements 9 named behavioral correlation rules against Windows Event Log data:

| Rule | Event IDs | What it detects |
|------|-----------|-----------------|
| WINLOG-001 | 4625 | Brute-force burst — N failures from same source in time window |
| WINLOG-002 | 4625 + 4624 | Brute-force success — failures followed by a successful login |
| WINLOG-003 | 4728/4732/4756 | Backdoor account — user added to a privileged security group |
| WINLOG-004 | 4648 + 4624 type 3 | Lateral movement — explicit credential use followed by network logon |
| WINLOG-005 | 4624 type 3 + 4672 | Privilege escalation — remote logon with special privileges assigned |
| WINLOG-006 | 1102 | Audit log cleared — direct evidence of evidence tampering |
| WINLOG-007 | 4719 | Audit policy changed — attacker disabling monitoring |
| WINLOG-008 | 4697/7045 | New service installed — persistence mechanism |
| WINLOG-009 | 4698 | Scheduled task created — persistence mechanism |

#### Why these specific Event IDs?

These are the Windows Security Event IDs that Microsoft itself identifies as security-relevant. They're part of the Windows security audit framework and appear in every major threat hunting framework:

- **4625**: Failed logon — the universal brute-force signal
- **4624**: Successful logon — combined with 4625 = compromise
- **4728/4732/4756**: Group membership changes to "Administrators", "Backup Operators", or "Enterprise Admins" — the classic backdoor account move
- **4648**: Explicit credential use (RunAs or pass-the-hash) — lateral movement signature
- **4672**: Special privileges assigned — Domain Admin or SeDebugPrivilege
- **1102**: Security audit log cleared — the "oh no" event, always means someone is hiding
- **4698**: Scheduled task created — the most common persistence mechanism

#### How sliding windows work

```
Timeline: ──────────────────────────────────────────────→
Events:   F  F  F  F  F  F  S  ←─ F=failure, S=success

Window:   [──────────W──────────]
                     [──────────W──────────]
```

The window slides forward. When 5+ failures occur within the window AND a success follows within 120 seconds (the `WINLOG_BRUTE_FORCE_SUCCESS_WINDOW`), WINLOG-002 fires.

All window sizes are configurable via `SENTINEL_WINLOG_*` environment variables.

### Alert deduplication

After all detectors run, the orchestrator deduplicates alerts by `(alert_type, src_ip, dst_ip)` key. If two detectors fire the same type of alert for the same source/destination pair, only the higher-confidence alert is kept.

This prevents the analyst from seeing 5 "brute force" alerts for the same attacker from 5 different detectors.

---

## 9. Stage 7 — Score

**Modules**: `scoring/host_risk.py`, `scoring/asset_risk.py`, `scoring/attack_surface.py`  
**Input**: Enriched events + alerts  
**Output**: Risk scores (0.0–10.0) for each host and an overall attack surface metric

### The 4-component NRA host risk model

Host risk is calculated from four components that sum to 100 points:

**Service Risk (40 points max)**  
Based on what services are exposed. RDP and SMB score 8–10 (critical). SSH scores 5. HTTP scores 2. Telnet scores 9 (critical — unencrypted shell). The scores come from `intelligence/service_intelligence.py`, a knowledge base of 30+ protocols with risk scores calibrated to real-world attacker preference.

**Exposure Risk (25 points max)**  
Based on how many services are exposed. A host with 1 open port is less exposed than a host with 15. There's a curve — the difference between 1 and 5 open ports matters more than the difference between 20 and 25.

**Attack Surface (20 points max)**  
Based on dangerous service combinations. Some service combos are particularly dangerous:
- SMB (445) + RDP (3389) → ransomware staging (these are the two services ransomware operators exploit most)
- SSH (22) + MySQL (3306) → lateral movement risk (database access via SSH tunnel)
- Any critical service + Telnet (23) → the host is both vulnerable and accessible

**Threat Context (15 points max)**  
Based on intelligence enrichment. If the host's IP appears in threat feeds, if connections are coming from high-risk countries, if the host has appeared in correlated attack chains — these boost the score.

The four components are summed and divided by 10 to produce the final 0–10 score.

### Risk labels

| Score | Label |
|-------|-------|
| 0.0–3.9 | Low |
| 4.0–5.9 | Medium |
| 6.0–7.9 | High |
| 8.0–10.0 | Critical |

### Asset risk vs host risk

`asset_risk.py` scores individual assets (IP + port combinations), not entire hosts. A host might be overall "medium" risk, but its port 3389 might be "critical" because that specific port is unpatched.

### Attack surface

`attack_surface.py` produces a network-wide metric (0–10) combining:
- Total number of exposed high-risk services across all hosts
- Number of critical hosts
- Whether lateral movement has been detected
- Total number of high-confidence alerts

This gives the CISO a single number representing the overall network exposure.

---

## 10. Stage 8 — Timeline

**Modules**: `narrative/timeline_builder.py`, `narrative/attack_story_engine.py`  
**Input**: Enriched events + alerts + scores  
**Output**: Chronological timeline + SOC narrative text

### Why a timeline?

Events arrive in the order they're processed, not necessarily in chronological order. The timeline sorts all events by timestamp and builds a coherent sequence showing how the attack unfolded.

A timeline entry looks like:

```
[2026-05-09T02:00:00Z] PORT SCAN — 185.220.101.45 → 10.0.0.10 (low)
[2026-05-09T02:00:30Z] AUTH FAILURE — 185.220.101.45 → 10.0.0.10 (medium)
[2026-05-09T02:01:45Z] AUTH FAILURE — 185.220.101.45 → 10.0.0.10 (medium)
[2026-05-09T02:02:15Z] AUTH SUCCESS — 185.220.101.45 → 10.0.0.10 (high) ← WINLOG-002
[2026-05-09T02:05:00Z] LATERAL MOVEMENT — 10.0.0.10 → 10.0.0.11 (critical)
[2026-05-09T02:06:30Z] AUDIT LOG CLEARED — 10.0.0.10 (critical) ← WINLOG-006
```

This is what an analyst actually uses to understand an incident.

### The attack story engine

`attack_story_engine.py` converts the mechanical timeline into analyst-readable narrative text:

> "At 02:00:00, threat actor `185.220.101.45` (Russia, Tor exit node) began network reconnaissance against `10.0.0.10`. A brute-force attack followed, with 12 authentication failures recorded over 105 seconds. At 02:02:15, the attacker achieved successful authentication (WINLOG-002). The compromised host was subsequently used as a pivot point to attack `10.0.0.11`, with the attacker clearing audit logs (WINLOG-006) at 02:06:30 — consistent with an active attacker attempting to cover tracks."

This narrative is included in the executive summary and is what gets handed to a non-technical stakeholder.

---

## 11. Stage 9 — Report

**Modules**: `reporting/report_generator.py`, `reporting/executive_summary.py`, `reporting/recommended_actions.py`  
**Input**: Everything — events, alerts, scores, timeline, narrative  
**Output**: Structured JSON report + Markdown report

### The JSON report

The JSON report is machine-readable and designed for downstream tool integration. It contains:

```json
{
    "run_id": "uuid",
    "timestamp": "2026-05-09T02:10:00Z",
    "event_count": 15,
    "alert_count": 13,
    "alerts": [...],
    "host_scores": {
        "10.0.0.10": {"score": 9.8, "label": "critical"},
        "10.0.0.20": {"score": 5.2, "label": "medium"}
    },
    "attack_surface": 7.5,
    "lateral_movement_detected": true,
    "timeline": [...],
    "executive_summary": {...}
}
```

This can be ingested by a SIEM, ticketing system, or any downstream tool.

### The Markdown report

The Markdown report is human-readable and structured for analyst consumption. It contains:

1. **Executive Summary** — Overall verdict, key findings, immediate actions (written for CISO)
2. **Risk Surface** table — metrics at a glance
3. **Host Risk Scores** table — every host with score and label
4. **WINLOG Alert Details** — each fired rule with evidence and MITRE mapping
5. **NRA Triage Recommendations** — per-port, per-service guidance with CVE references
6. **Attack Timeline** — chronological event sequence
7. **Attack Narrative** — the story of the incident

### The executive summary engine

`executive_summary.py` applies a **verdict confidence floor** (default 0.3). Alerts below this confidence threshold are not counted when computing the executive verdict. This prevents a single low-confidence anomaly from triggering a "Critical" verdict.

The verdict logic:

```
IF any host score ≥ 8.0 OR any critical-severity alert above confidence floor → "Critical"
ELSE IF any host score ≥ 6.0 OR any high-severity alert → "High"  
ELSE IF any medium alert above floor → "Medium"
ELSE → "Low"
```

### The recommended actions engine

`reporting/recommended_actions.py` generates per-port, per-service triage guidance. For every open port on every scanned host, it pulls the service knowledge from `intelligence/service_intelligence.py` and generates:

- **Context**: What this service does and why it's risky in this specific situation
- **Risk rationale**: Why this is flagged at this severity
- **CVE references**: Specific CVEs affecting this service (e.g., CVE-2019-0708 BlueKeep for RDP)
- **Immediate actions**: Numbered steps the analyst should take right now
- **MITRE ATT&CK phase**: Which phase of the kill chain this service enables

This is the NRA (Network Reconnaissance Analyzer) output — the part of Sentinel_Fusion that came from the original `nmap-recon-analyzer` tool.

---

## 12. Stage 10 — Hunt

**Module**: `hunting/hunt_engine.py`
**Input**: `StorageLayer` — queries aggregated data across all prior pipeline runs
**Output**: `list[dict]` — hunt findings appended to `hunt_findings` in the pipeline result

The `HuntEngine` runs four cross-run strategies against the database. Individual pipeline runs see only the current event batch; the hunt stage sees everything across all runs, making it the only component that can surface low-and-slow attack patterns.

| Strategy | What it finds | Threshold |
|----------|---------------|-----------|
| `low_and_slow_brute_force` | Same src_ip with auth failures across 3+ runs, each below the live threshold | 3 runs, <5/run |
| `alert_cluster` | Same src_ip with 3+ open alerts collectively significant but individually dismissed | 3 open alerts |
| `beacon` | Same (src_ip → dst_ip) pair in 5+ separate runs — consistent with C2 check-in | 5 runs |
| `persistent_threat_actor` | Same external src_ip appearing in events across 5+ runs | 5 runs |

Each finding includes `hunt_confidence`, MITRE tactic, `run_count`, an `evidence` dict, and a plain-English `analyst_note`. If `store` is `None`, returns `[]` immediately so the orchestrator can safely call this stage in test environments.

---

## 13. The Intelligence Layer

**Modules**: `intelligence/service_intelligence.py`, `intelligence/event_intelligence.py`, `intelligence/ip_reputation.py`, `intelligence/geo_enrichment.py`, `intelligence/threat_feeds.py`, `intelligence/_http.py`

### service_intelligence.py — The network service knowledge base

This is a large, carefully curated dictionary of 30+ network protocols. For each protocol, it stores:

- **Risk score** (0–10): calibrated to real attacker interest
- **Threat description**: why this service is dangerous
- **CVE list**: specific known vulnerabilities
- **MITRE ATT&CK techniques**: which techniques exploit this service
- **Recommended actions**: what a SOC analyst should do when they see this

This is the knowledge that makes the NRA output useful rather than generic. Without it, seeing port 445 open is just a number. With it, seeing port 445 open means "SMB: EternalBlue risk, check if SMBv1 is disabled, apply MS17-010."

### event_intelligence.py — The Windows Event ID knowledge base

The same concept applied to Windows Event IDs. For Event ID 4625:

```python
{
    "name": "An account failed to log on",
    "category": "Logon",
    "severity": "medium",
    "mitre_techniques": ["T1110"],  # Brute Force
    "analyst_notes": "High volume of 4625 from a single source is a brute-force indicator. Correlate with 4624 for success.",
    "recommended_actions": ["Block source IP if rate exceeds threshold", "Enable account lockout policy"]
}
```

### ip_reputation.py — The IP reputation engine

Five-tier lookup:

1. **Seed table**: Known bad IPs hardcoded in the module (Tor exits, Shodan crawlers, known C2s)
2. **Private IP check**: RFC 1918 addresses are always `is_malicious: False`
3. **TTL Cache**: Previous lookup results cached for 1 hour (configurable)
4. **AbuseIPDB**: Live lookup if `SENTINEL_ABUSEIPDB_KEY` is set
5. **Stub fallback**: Returns neutral result if everything else fails

### geo_enrichment.py — The geolocation engine

Same tier structure. The `_HIGH_RISK_COUNTRIES` frozenset contains countries with elevated state-sponsored threat actor activity: `{"RU", "CN", "KP", "IR", "SY", "BY", "CU"}`.

An IP from a high-risk country gets `high_risk_country: True` added to its enrichment metadata, which flows into the host risk score (threat context component).

### _http.py — The shared HTTP helper

A thin wrapper around `urllib.request.urlopen` (Python stdlib — no external HTTP library required):

```python
class IntelHttpError(Exception): pass

def get_json(url, headers=None, timeout=5):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())
    # raises IntelHttpError on any network failure
```

All live intelligence modules use this helper. When it raises `IntelHttpError`, the caller falls back to the stub result.

---

## 14. The Storage Layer

**Modules**: `storage/database.py`, `storage/schema.py`, `storage/models.py`, `storage/store.py`, `storage/repositories/`

### Design principle: single write entrypoint

`StorageLayer.persist_run()` is the **only** function that writes a complete pipeline result to the database. Nothing else may call the individual repository write methods directly for a full run. This ensures data consistency — a partial write (where events are stored but alerts aren't) can't happen.

### SQLite in WAL mode

The database uses Write-Ahead Logging (WAL) mode. WAL allows one writer and multiple concurrent readers — important for the watch mode (which writes periodically) and the API (which reads continuously).

### Versioned migrations

`storage/schema.py` contains a `MIGRATIONS` dict mapping version integers to SQL strings:

```python
MIGRATIONS = {
    1: "CREATE TABLE events (...)",
    2: "CREATE TABLE alerts (...)",
    3: "ALTER TABLE events ADD COLUMN enriched_metadata TEXT",
    ...
}
```

On startup, `database.py` checks the current schema version and applies any missing migrations in order. The database schema is always up-to-date, and no migration can be applied twice.

### The dataclasses

`storage/models.py` defines Python dataclasses for each stored type:

- `StoredEvent` — a normalized event persisted after a pipeline run
- `StoredAlert` — a fired alert with all its metadata
- `StoredCase` — an analyst-managed investigation case (groups related alerts)
- `StoredScore` — a host or asset risk score from a specific run
- `PipelineRun` — metadata about a complete pipeline execution (timestamps, counts, run ID)
- `AuditEntry` — immutable audit log entries for analyst actions

### Repositories

Each entity type has its own repository module (`storage/repositories/events.py`, etc.) that handles SQL queries for that type. The repositories expose read methods (query, filter, paginate) but not direct write methods for runs — those go through `StorageLayer.persist_run()`.

---

## 15. The REST API

**Modules**: `api/app.py`, `api/dependencies.py`, `api/routes/`, `api/schemas/`

### FastAPI

Sentinel_Fusion uses FastAPI, which provides:
- Automatic OpenAPI (Swagger) documentation at `/docs`
- Request/response validation via Pydantic
- Dependency injection for shared concerns (authentication, database access)
- Async support for high-throughput scenarios

### API key authentication

Authentication is disabled by default (to keep development simple). Enable it by setting `SENTINEL_API_KEY=your-secret-key`.

When enabled, every data endpoint requires an `X-API-Key` header. The `/health` endpoint is always unauthenticated — load balancers and uptime monitors need it.

The authentication check is implemented as a FastAPI dependency (`api/dependencies.py`) and applied to all data routers at registration time in `api/app.py`. Individual route handlers don't need to think about auth.

### Endpoints

```
GET  /health                    Unauthenticated health check
POST /api/v1/pipeline/run       Run the full pipeline (accepts event arrays)
GET  /api/v1/events             Query stored events (filterable by host, type, severity)
GET  /api/v1/alerts             Query stored alerts (filterable by type, severity, status)
GET  /api/v1/scores             Query host risk scores (filterable by host, label)
GET  /api/v1/intel/ip/{ip}      IP reputation + geolocation lookup
GET  /api/v1/intel/service/{s}  Service intelligence lookup (e.g., "rdp", "smb", "ssh")
GET  /api/v1/intel/event/{id}   Windows Event ID intelligence lookup
GET  /api/v1/runs               Pipeline run history with metadata
```

### Request schemas

`api/schemas/requests.py` defines Pydantic models for POST request bodies. The pipeline run request accepts:

```python
class PipelineRunRequest(BaseModel):
    nra:    list[dict] = []
    winlog: list[dict] = []
    mock:   list[dict] = []
```

At least one of these must be non-empty — the API validates this and returns a 400 if all are empty.

---

## 16. The CLI and Watch Mode

**Modules**: `interface/cli.py`, `interface/commands/`, `interface/banner.py`, `interface/output.py`

### Typer

The CLI uses Typer, which builds command-line interfaces from Python function signatures with type annotations. No argument parsing code needed — just annotate the parameters and Typer handles `--help`, type validation, and error messages.

### Command structure

```
sentinel                    ← root command (cli.py)
├── status                  ← DB stats and system health
├── run                     ← pipeline execution
│   ├── --nra FILE          ← Nmap XML or JSON
│   ├── --winlog FILE       ← .evtx or JSON
│   ├── --mock FILE         ← simulated attack JSON
│   └── --report            ← print full Markdown report
├── watch                   ← continuous monitoring mode
│   ├── --winlog FILE       ← file to tail
│   └── --interval SECONDS  ← poll interval (default: 10)
├── events                  ← query stored events
├── alerts                  ← query stored alerts
├── cases                   ← manage investigation cases
├── scores                  ← query risk scores
├── intel                   ← intelligence lookups
├── runs                    ← pipeline run history
└── purge                   ← clear database
```

### Watch mode: _FileCursor

`interface/commands/watch.py` implements continuous file monitoring using `_FileCursor`:

```python
class _FileCursor:
    def __init__(self, path: Path):
        self.path = path
        self._mtime = None
        self._count = 0

    def poll(self) -> list[dict]:
        if not self.path.exists():
            return []
        mtime = self.path.stat().st_mtime
        if mtime == self._mtime:
            return []          # file unchanged
        self._mtime = mtime
        events = json.loads(self.path.read_text())
        if not isinstance(events, list):
            return []
        if len(events) < self._count:
            self._count = 0    # log rotation — reset cursor
        new_events = events[self._count:]
        self._count = len(events)
        return new_events
```

**How it works**: The cursor remembers the file's last-modified time (`mtime`) and the number of events it has already processed (`_count`). On each poll:

1. If `mtime` hasn't changed — nothing to do
2. If `mtime` changed — read the file
3. If the new event count is *less than* `_count` — log rotation happened (file was replaced with a smaller file). Reset `_count` to 0 and process all events.
4. Otherwise — return only the new events (from `_count` to end)

**Why mtime instead of inotify?** Mtime is stdlib. No OS-specific dependencies, works on Linux, macOS, and Windows, and works across network filesystems.

### _run_watch_cycle

Each watch cycle calls `_run_watch_cycle(cursors, db_path, cycle_n)`:

1. Poll all cursors for new events
2. If no new events → return None (don't run the pipeline)
3. If new events → run the full 10-stage pipeline against just the new events
4. Persist the result to the database
5. Print a Rich-formatted summary table to the terminal
6. Return the pipeline result

The interval between cycles is configurable via `--interval` (default: 10 seconds). The watch loop handles `KeyboardInterrupt` (Ctrl+C) gracefully, printing a summary of all cycles before exiting.

---

## 17. Design Philosophy and Hard Rules

### The 10 hard constraints

These are the rules that cannot be violated without fundamentally breaking the system's reliability:

**1. No stage may be skipped or reordered.**  
The 10-stage pipeline is sequential by design. The orchestrator enforces this. If you bypass the pipeline for "performance" you lose testability, debuggability, and the guarantee that data has been normalized before detection.

**2. `StorageLayer.persist_run()` is the only write entrypoint for complete runs.**  
All 6 entity types (events, alerts, scores, cases, audit entries, run metadata) must be written atomically. If you write them individually, you get inconsistent state.

**3. All configuration via Pydantic Settings with `SENTINEL_*` env var prefix.**  
No hardcoded constants that operators need to change. No ad-hoc env var reading. Every tunable parameter lives in `config/settings.py` and is documented.

**4. All detectors are stateless.**  
Detectors may not read from or write to the database. State belongs in the database, not in running process memory. This makes detectors testable and replaceable.

**5. The `raw` field is never modified.**  
The original parsed record must always be recoverable. Transformation happens in copies, not in place.

**6. The `/health` endpoint is always unauthenticated.**  
Auth applies to data endpoints only. Monitoring systems must be able to check health without credentials.

**7. Intelligence failures never crash the pipeline.**  
The stub fallback ensures that a failed API call or a missing seed table entry doesn't stop processing. The pipeline degrades gracefully.

**8. Alert deduplication runs after all detectors.**  
Multiple detectors may fire on the same event pair. Deduplication is a post-processing step, not a constraint on detector design. Detectors should fire freely; the orchestrator handles dedup.

**9. The verdict confidence floor filters noise from the executive summary.**  
The CISO report reflects only alerts with meaningful confidence. This prevents a single low-confidence anomaly from dominating the executive narrative.

**10. All time comparisons use ISO 8601 string comparison.**  
Timestamps are stored and compared as strings in `YYYY-MM-DDTHH:MM:SSZ` format. String comparison of ISO 8601 is lexicographically equivalent to chronological ordering — no datetime library required for ordering, no timezone conversion bugs.

### Why stdlib only (no ML dependencies)?

Sentinel_Fusion has no machine learning dependencies by design. This means:

- **Reproducible**: Same input always produces same output. No model drift, no retraining cycles.
- **Explainable**: Every alert can be traced to a specific rule, event, and evidence chain. You can show an analyst exactly why an alert fired.
- **Auditable**: For SOC work, you need to be able to explain your detections to a customer, a judge, or an incident report. "The neural network flagged it" is not an acceptable explanation.
- **Fast**: The test suite runs in ~2 seconds. No GPU, no model loading.

### The SOC workflow integration philosophy

Sentinel_Fusion is designed to augment analysts, not replace them. Every output is designed to give the analyst:

1. **What happened** (the timeline)
2. **How confident we are** (confidence scores)
3. **What to do next** (recommended actions)
4. **Why this matters** (MITRE mapping, CVE references, risk rationale)

The analyst makes the final call. Sentinel_Fusion makes the analyst faster and more informed.

---

## Quick Reference: Module Map

```
config/settings.py          ← All configuration (env vars)
core/pipeline/
  ingest.py                 ← Stage 1: load raw files
  nra_parser.py             ← Nmap XML parsing
  winlog_parser.py          ← .evtx binary parsing
  normalize.py              ← Stage 2: unified NormalizedEvent schema
  enrich.py                 ← Stage 3: IP rep, geo, service context
  context_builder.py        ← Per-host context assembly
  orchestrator.py           ← Drives the full 10-stage run
detection/
  sigma_engine.py           ← Stage 4: 10 MITRE-mapped Sigma-compatible rules
  sigma_field_mapper.py     ← Stage 4: maps Sigma field names to normalized schema
  correlation_engine.py     ← Stage 5: attack chains + pivot detection
  brute_force_detection.py  ← Stage 6: rate-based brute force
  lateral_movement_detection.py ← Stage 6: multi-target detection
  anomaly_detection.py      ← Stage 6: statistical outliers
  winlog_rules.py           ← Stage 6: 9 WINLOG behavioral rules
scoring/
  host_risk.py              ← Stage 7: 4-component NRA host score (0–10)
  asset_risk.py             ← Stage 7: per-port asset score
  attack_surface.py         ← Stage 7: network-wide exposure metric
narrative/
  timeline_builder.py       ← Stage 8: chronological event ordering
  attack_story_engine.py    ← Stage 8: analyst narrative text
reporting/
  report_generator.py       ← Stage 9: JSON + Markdown output
  executive_summary.py      ← Stage 9: verdict, key findings, actions
  recommended_actions.py    ← Stage 9: per-port SOC triage (NRA)
hunting/
  hunt_engine.py            ← Stage 10: cross-run proactive threat hunting
intelligence/
  service_intelligence.py   ← Network service knowledge base (30+ protocols)
  event_intelligence.py     ← Windows Event ID knowledge base
  ip_reputation.py          ← IP rep: seed → cache → AbuseIPDB → stub
  geo_enrichment.py         ← Geolocation: seed → cache → ip-api.com → stub
  threat_feeds.py           ← Threat feed membership
  _http.py                  ← Shared stdlib HTTP helper
storage/
  database.py               ← SQLite + WAL + migrations runner
  schema.py                 ← DDL + versioned MIGRATIONS dict
  models.py                 ← StoredEvent, StoredAlert, StoredCase, etc.
  store.py                  ← StorageLayer facade (single write entrypoint)
  repositories/             ← Per-entity read/query methods
api/
  app.py                    ← FastAPI app factory + router registration
  dependencies.py           ← API key auth dependency
  routes/                   ← One file per endpoint group
  schemas/                  ← Pydantic request/response models
interface/
  cli.py                    ← Typer root command group
  commands/
    pipeline.py             ← sentinel run
    watch.py                ← sentinel watch + _FileCursor
    alerts/cases/events/... ← CRUD command groups
```

---

## Converting This Guide to PDF

If Pandoc is installed on your system:

```bash
pandoc docs/SENTINEL_FUSION_GUIDE.md -o sentinel_fusion_guide.pdf \
  --pdf-engine=xelatex \
  -V geometry:margin=1in \
  -V fontsize=11pt
```

If Pandoc is not installed:
```bash
pip install pandoc
# or on Ubuntu/Debian:
sudo apt install pandoc texlive-xetex
```

Alternatively, open the Markdown file in VS Code and use the **Markdown PDF** extension (Ctrl+Shift+P → "Markdown PDF: Export (pdf)").

Online option: paste the contents into https://md-to-pdf.fly.dev or any Markdown-to-PDF converter.
