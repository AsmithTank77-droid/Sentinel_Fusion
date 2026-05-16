"""
interface/commands/intel.py — sentinel intel <ip>
"""

from __future__ import annotations

import typer

from interface.output import confidence_bar, console, kv_panel
from intelligence.geo_enrichment import GeoEnrichment
from intelligence.ip_reputation import IpReputation
from intelligence.threat_feeds import ThreatFeeds

app = typer.Typer(help="Look up threat intelligence for an IP address.")

_reputation   = IpReputation()
_geo          = GeoEnrichment()
_threat_feeds = ThreatFeeds()


@app.callback(invoke_without_command=True)
def intel(ip: str = typer.Argument(..., help="IP address to look up.")) -> None:
    """
    Display combined threat intelligence for an IP: reputation, geolocation,
    and threat feed membership.
    """
    rep     = _reputation.lookup(ip)
    geo     = _geo.lookup(ip)
    threats = _threat_feeds.check(ip)

    feed_hits = threats.get("feed_hits") or []

    malicious_flag = (
        "[bold red]MALICIOUS[/bold red]"
        if rep["is_malicious"]
        else "[green]CLEAN[/green]"
    )
    tor_flag = "[bold yellow]YES[/bold yellow]" if geo.get("is_tor") else "No"

    items = {
        "IP Address":         ip,
        "Status":             malicious_flag,
        "Reputation Score":   confidence_bar(rep["reputation_score"]),
        "Categories":         ", ".join(rep.get("categories") or []) or "—",
        "Report Count":       str(rep.get("report_count", 0)),
        "Country":            f"{geo.get('country', '—')} ({geo.get('country_code', '??')})",
        "City":               geo.get("city", "—"),
        "ASN / Org":          f"{geo.get('asn', '—')}  {geo.get('org', '')}",
        "TOR Exit Node":      tor_flag,
        "High-Risk Country":  "[red]Yes[/red]" if geo.get("high_risk_country") else "No",
        "Feed Hits":          str(len(feed_hits)),
        "Feeds":              ", ".join(feed_hits) if feed_hits else "—",
        "Feed Confidence":    confidence_bar(threats.get("confidence", 0.0)),
        "First / Last Seen":  f"{threats.get('first_seen', '—')}  /  {threats.get('last_seen', '—')}",
    }

    border = "bold red" if rep["is_malicious"] else "cyan"
    console.print(kv_panel(f"Intel: {ip}", items, style=border))
