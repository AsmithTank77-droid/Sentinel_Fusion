I'm just starting out in cybersecurity but I've been building something I'm really proud of.

It's called Sentinel_Fusion — a 10-stage SOC detection pipeline I built from scratch in Python. It takes in Nmap scans and Windows Event Logs, figures out what's going on across them, and produces SOC reports with MITRE ATT&CK mappings and host risk scores. Basically everything a SOC analyst would need to start investigating.

I just dropped v3 and added three new features:

1. Elasticsearch integration — the pipeline now sends all its alerts and findings to Elasticsearch after every run. Connect Kibana and you have an actual SOC dashboard.

2. MITRE ATT&CK Navigator export — you can download a Navigator layer straight from the API and see your detection coverage mapped out visually. That one was really cool to build.

3. Live threat feed ingestion — instead of hardcoded data it now pulls live blocklists from abuse.ch and Emerging Threats, with AlienVault OTX as a backup. If the feeds go down the pipeline just keeps going.

972 tests passing across the whole project.

I built this to learn how detection pipelines actually work under the hood and to have something real to show. I'm looking for junior SOC analyst and blue team roles — if you know of anything or just want to check out the project, the repo is here:

https://github.com/AsmithTank77-droid/Sentinel_Fusion

#cybersecurity #blueteam #SOC #SIEM #MITRE #infosec #python #opentowork
