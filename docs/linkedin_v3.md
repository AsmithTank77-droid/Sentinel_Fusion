I just shipped v3 of Sentinel_Fusion.

For those who haven't seen it — it's a 10-stage SOC detection pipeline I built from scratch in Python. It ingests Nmap scans and Windows Event Logs, correlates them into attack chains, scores host risk, and spits out structured SOC reports with MITRE ATT&CK mappings.

v3 adds three things I've wanted in it for a while:

1. Elasticsearch SIEM Integration — every pipeline run now forwards alerts, host risk scores, and hunt findings to Elasticsearch automatically. Hook up Kibana and you've got a live SOC dashboard. No external Python dependencies, just stdlib.

2. MITRE ATT&CK Navigator Export — one API call gives you a full Navigator layer JSON with techniques color-coded by detection confidence. You can drop it straight into the Navigator and see exactly what your detections cover.

3. Live Threat Feed Ingestion — instead of just static seed data, it now pulls from abuse.ch Feodo Tracker and Emerging Threats in real time, with AlienVault OTX as a fallback for per-IP lookups. If a feed goes down it fails gracefully and the pipeline keeps running.

972 tests passing. Built it to show what a detection pipeline actually looks like end to end — not just scripts, but a real system with an API, a storage layer, and proper test coverage.

If you're studying for a blue-team cert, building a home SOC lab, or just want to see how something like this is structured, the full repo is here:
https://github.com/AsmithTank77-droid/Sentinel_Fusion

#cybersecurity #blueteam #SOC #SIEM #MITRE #threathunting #python #infosec
