"""
api/routes/intel.py — Threat intelligence lookup endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from api.schemas.responses import IntelResponse
from intelligence.geo_enrichment import GeoEnrichment
from intelligence.ip_reputation import IpReputation
from intelligence.threat_feeds import ThreatFeeds

router = APIRouter(prefix="/intel", tags=["intel"])

_reputation   = IpReputation()
_geo          = GeoEnrichment()
_threat_feeds = ThreatFeeds()


@router.get(
    "/ip/{ip}",
    response_model=IntelResponse,
    summary="IP threat intelligence lookup",
)
def lookup_ip(ip: str) -> IntelResponse:
    """
    Returns combined threat intelligence for an IP address:
    reputation score, geolocation, threat feed membership,
    and a condensed summary dict for quick triage.
    """
    if not ip.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="IP address must not be empty.",
        )

    rep     = _reputation.lookup(ip)
    geo     = _geo.lookup(ip)
    threats = _threat_feeds.check(ip)

    return IntelResponse(
        ip=ip,
        reputation=rep,
        geo=geo,
        threats=threats,
        summary={
            "is_malicious":     rep["is_malicious"],
            "reputation_score": rep["reputation_score"],
            "country":          geo.get("country", "unknown"),
            "is_tor":           geo.get("is_tor", False),
            "feed_hits":        len(threats.get("feed_hits", [])),
            "threat_confidence": threats.get("confidence", 0.0),
        },
    )
