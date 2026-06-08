# Sentinel_Fusion — Architecture Decision Record

**Author:** Andy Smith
**Version:** 3.0
**Date:** 2026-06-08

This document explains the key architectural decisions made in Sentinel_Fusion — what was chosen, what was considered and rejected, and why. The goal is to show that every major choice was deliberate, not accidental.

---

## 1. SQLite over PostgreSQL

**Decision:** Use SQLite as the storage backend.

**Why:** Sentinel_Fusion is a single-node detection pipeline. SQLite in WAL (Write-Ahead Logging) mode handles concurrent reads cleanly while serialising writes through a threading lock — which is exactly what a single Uvicorn worker needs. There is no connection pool to manage, no external process to run, and no credentials to configure. For a system designed to run on a laptop, a home lab server, or a single container, SQLite is the right tool.

**What I considered instead:** PostgreSQL. It would handle concurrent writes from multiple workers and scale horizontally. But it introduces a separate process, connection pooling, credentials management, and ops overhead that is unnecessary at this scale.

**How I kept the door open:** The repository pattern (`storage/repositories/`) isolates every database call behind a class interface. Swapping SQLite for PostgreSQL means replacing only the `Database` connection object — no detection logic, no scoring logic, no API code changes. The architecture supports the upgrade without requiring it now.

**What I would do at scale:** Move to PostgreSQL or TimescaleDB (optimised for time-series security events) once the system needs to handle multiple concurrent pipeline runs or long-term event retention at volume.

---

## 2. stdlib urllib over the requests library

**Decision:** All HTTP calls use Python's built-in `urllib` — no `requests`, no `httpx`.

**Why:** Every intelligence integration (AbuseIPDB, ip-api.com, AlienVault OTX, abuse.ch, Emerging Threats) and the Elasticsearch SIEM forwarder uses the same shared `intelligence/_http.py` helper built on `urllib`. This keeps the dependency list minimal — one less package to install, one less version to pin, one less CVE surface to track. In a security tool, that matters.

**What I considered instead:** `requests` is more ergonomic and widely used. But for the volume of HTTP calls this system makes (a handful per pipeline run, all cached), the ergonomics difference is negligible. The stdlib is always available and never has breaking changes.

**Trade-off acknowledged:** `urllib` error handling is more verbose and the API is less intuitive. The `_http.py` wrapper exists specifically to hide that complexity behind a clean interface.

---

## 3. Batch processing over real-time streaming

**Decision:** The pipeline processes events in batches submitted via API request, not as a continuous stream.

**Why:** The primary use case is an analyst submitting a scan or a log export and receiving a structured report. Batch processing is deterministic — given the same input you always get the same output, which makes testing, debugging, and explaining results straightforward. It also means the entire pipeline can run in a single request/response cycle with a complete trace attached.

**What I considered instead:** A streaming architecture with something like Kafka or Redis Streams processing events as they arrive. That's how production SIEMs work. But it would add significant infrastructure complexity, make testing much harder, and isn't necessary for the problem this system solves today.

**What I built toward:** The file watcher (`core/pipeline/watch.py`) monitors a directory for new log files and feeds them into the pipeline automatically. That closes the gap between "submit manually" and "process continuously" without requiring a full streaming infrastructure.

**What I would do at scale:** Add a Kafka consumer in front of the ingest stage. The pipeline itself wouldn't change — only the delivery mechanism.

---

## 4. Strict 10-stage pipeline order

**Decision:** All events must travel through exactly 10 stages in a fixed order. No stage may be skipped or reordered.

**Why:** Determinism and traceability. Every detection, score, and recommendation can be traced back to the exact event that produced it, through the exact stage that processed it. If the pipeline order were flexible, that traceability would break — a detection in Stage 6 depends on enrichment from Stage 3 being present. Making the order a hard constraint enforced in `CLAUDE.md` means no future change can accidentally break that dependency.

**Trade-off:** Inflexibility. You cannot run scoring without running detection, even if you only want scores. In practice this hasn't been a problem because the pipeline runs in ~2 seconds.

---

## 5. Stateless detectors

**Decision:** All detection modules are stateless. No detector holds state between calls.

**Why:** Stateless modules are easy to test in isolation, easy to reason about, and trivially parallelisable. Each detector receives the full event batch and produces alerts from that batch alone. All context needed for a detection decision must be present in the events passed to it.

**How correlation across events works:** The correlation engine (Stage 5) runs before detection and assembles events into attack chains. By the time detectors run, the correlated context is already embedded in the event data. Detectors don't need to remember previous events — the correlator already did that work.

---

## 6. Three-tier intelligence fallback

**Decision:** Every intelligence lookup follows the same pattern: seed table → live API → empty stub.

**Why:** The pipeline must never crash because an external API is unavailable. The seed table provides instant, authoritative results for known IPs used in tests and demos. The live API provides real enrichment when configured. The empty stub ensures the pipeline always continues and returns a result even if everything else fails. Network failures are caught, logged, and swallowed — they never propagate as exceptions.

**Applied in:** IP reputation (AbuseIPDB), geolocation (ip-api.com), and threat feeds (Feodo Tracker → Emerging Threats → OTX).

---

## 7. Non-fatal SIEM forwarding

**Decision:** Elasticsearch forwarding runs after the pipeline completes and never affects the pipeline result.

**Why:** The pipeline's job is to analyse events and return a report. The SIEM's job is to store that report for long-term querying and dashboarding. These are separate concerns. If Elasticsearch is down, the pipeline result is still valid and should still be returned to the caller. Wrapping the forwarder in try/except and appending status to the trace (not the result) keeps these concerns cleanly separated.

**Trade-off:** If the forwarder fails silently the caller won't know unless they check the trace. That's an acceptable trade-off at this stage — a future improvement would be an explicit `siem_status` field in the top-level response.

---

## 8. Module-level caches with TTL

**Decision:** Intelligence results are cached at the module level using dictionaries with expiry timestamps, not at the instance level.

**Why:** `ThreatFeeds`, `IpReputation`, and `GeoEnrichment` are instantiated fresh on each pipeline run. If the cache lived on the instance it would be thrown away after every run. Module-level caches persist for the lifetime of the process and are shared across all instances, which is exactly what you want — one HTTP call to AbuseIPDB per IP per hour, regardless of how many pipeline runs happen.

**TTL is configurable:** `SENTINEL_INTEL_CACHE_TTL` (default 3600 seconds) controls expiry. In high-volume environments this can be tuned down.

---

## Summary

| Decision | Chosen | Rejected | Reason |
|----------|--------|----------|--------|
| Storage | SQLite + WAL | PostgreSQL | Single-node, zero ops overhead, repository pattern allows future swap |
| HTTP client | stdlib urllib | requests | Zero extra dependencies, security tool principle |
| Processing model | Batch | Kafka streaming | Determinism, testability, file watcher bridges the gap |
| Pipeline order | Strict fixed | Flexible | Traceability and dependency correctness |
| Detectors | Stateless | Stateful | Testability, isolation, parallelisability |
| Intelligence | Three-tier fallback | Hard dependency on live API | Pipeline must never crash due to network failure |
| SIEM forwarding | Non-fatal post-pipeline | In-pipeline blocking | Separation of concerns, pipeline result always valid |
| Caching | Module-level TTL | Instance-level | Survives across pipeline runs |
