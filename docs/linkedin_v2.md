I said v2 would be a 10-stage pipeline. It's done.

![Sentinel_Fusion — 10-stage pipeline trace](../assets/screenshot_pipeline.svg)

When I shipped Sentinel_Fusion v1, I was honest about what it wasn't yet. It could detect, correlate, score, and report. But it was still reactive — it only saw what was in front of it. One run at a time.

That bothered me.

Real attackers don't announce themselves. They come in slow. Two failed logins today. Two more next week. Never enough to trigger a single alert. But if you look across 10 sessions? The pattern is obvious.

So I built Stage 10: the Hunt Engine.

It doesn't wait for events to come to it. It queries the database across every previous pipeline run and looks for things the live pipeline can't see:

→ Low-and-slow brute force — auth failures spread across runs, each one sub-threshold
→ Beacon detection — same source hitting the same destination across 5+ separate sessions
→ Alert clustering — the same IP generating medium-confidence alerts that keep getting deprioritized
→ Persistent threat actors — external IPs that keep showing up, run after run

Each finding comes back with a confidence score, a MITRE tactic, a run count, and a plain-English analyst note. Not raw data — actionable context.

Here's where Sentinel_Fusion sits now:

10 stages. 917 tests. GitHub Actions CI on every push. REST API. Live dashboard. Docker. Full SOC report with executive summary, host risk scores, MITRE ATT&CK mappings, NRA triage recommendations, Sigma rule matches, and now cross-run hunt findings.

Reactive detection tells you what happened.
Threat hunting tells you what's been happening.

That's the difference between a tool and a platform.

Repo is open: github.com/AsmithTank77-droid/Sentinel_Fusion

#CyberSecurity #SOC #ThreatHunting #Python #SIEM #MitreAttack #Detection
