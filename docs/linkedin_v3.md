## Sentinel_Fusion v3 is live 🛡️

Three months ago I shipped a 10-stage SOC detection pipeline in Python. Today I'm dropping v3 — three new capabilities that take it from a detection engine to a full threat intelligence and SIEM-ready platform.

---

**What's new:**

**1. Elasticsearch SIEM Integration**
Every pipeline run now forwards alerts, host risk scores, hunt findings, and a run summary to Elasticsearch via the `_bulk` API — rolling daily indices, zero external dependencies (stdlib urllib only). Plug in Kibana and you have a live SOC dashboard. `SENTINEL_ELASTIC_ENABLED=true` is all it takes.

**2. MITRE ATT&CK Navigator Export**
One API call → a complete ATT&CK Navigator 4.x layer JSON. Techniques are color-coded by detection confidence (red ≥70%, orange 40–69%, yellow <40%), deduplicated across alerts, and mapped to correct tactic slugs automatically. Download the layer, drop it into navigator.attack.mitre.org, and instantly see your detection coverage.

**3. Live Threat Feed Ingestion**
Three-tier enrichment: seed table (instant) → live blocklists (abuse.ch Feodo Tracker + Emerging Threats, cached with TTL) → AlienVault OTX per-IP lookup. All tiers fail gracefully — a network timeout never breaks the pipeline. No API key required for the base feeds.

---

**By the numbers:**
- 10-stage pipeline: Ingest → Normalize → Enrich → Sigma → Correlate → Detect → Score → Timeline → Report → Hunt
- 972 tests (up from 917)
- 55 new tests across 3 new test modules

---

**Stack:** Python · FastAPI · SQLite · Elasticsearch · ATT&CK Navigator · Docker

The project is fully open source. If you're building a home SOC lab, studying for a blue-team cert, or just curious how detection pipelines work end to end — the repo is on GitHub.

#cybersecurity #blueteam #SIEM #MITRE #threathunting #python #SOC #infosec #opensourcetools
