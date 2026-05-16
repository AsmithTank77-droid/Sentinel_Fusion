"""
enrich.py — Stage 3: Enrichment
Pipeline: normalize.py → enrich.py → correlation_engine.py

Augments NormalizedEvents with threat intelligence and contextual data.
Enrichment results are written exclusively to event.metadata["enrichment"]
so raw source data is preserved separately from derived intelligence.

No detection, scoring, or reporting logic lives here.

Expected module contracts:

    intelligence.ip_reputation.IpReputation
        .lookup(ip: str) -> dict

    intelligence.geo_enrichment.GeoEnrichment
        .lookup(ip: str) -> dict

    intelligence.threat_feeds.ThreatFeeds
        .check(ip: str) -> dict

    core.pipeline.context_builder.ContextBuilder
        .build(events: list[dict]) -> list[dict]
            Must return exactly one context dict per input event, same index order.
"""

from __future__ import annotations

import intelligence.ip_reputation as _ip_rep_mod
import intelligence.geo_enrichment as _geo_mod
import intelligence.threat_feeds as _feeds_mod
import core.pipeline.context_builder as _context_mod

from core.pipeline.normalize import NormalizedEvent


def _load(module: object, attr: str) -> object:
    """Return module.attr or raise AttributeError with a clear not-implemented message."""
    try:
        return getattr(module, attr)
    except AttributeError:
        raise AttributeError(
            f"{module.__name__!r} does not export {attr!r} — "
            f"enrichment stage cannot run until the module is implemented"
        )


class Enricher:
    """
    Augments a batch of NormalizedEvents with threat intelligence and context.
    Stateless: no state is maintained between calls.

    Each event receives a metadata["enrichment"] sub-dict containing:

        src_reputation  — IpReputation.lookup(src_ip)   when src_ip is non-empty
        src_geo         — GeoEnrichment.lookup(src_ip)  when src_ip is non-empty
        src_threats     — ThreatFeeds.check(src_ip)     when src_ip is non-empty
        dst_reputation  — IpReputation.lookup(dst_ip)   when dst_ip is non-empty
        dst_geo         — GeoEnrichment.lookup(dst_ip)  when dst_ip is non-empty
        dst_threats     — ThreatFeeds.check(dst_ip)     when dst_ip is non-empty
        context         — ContextBuilder slice for this event (always present)

    Only metadata["enrichment"] is written. All other event fields are untouched.
    """

    def enrich(self, events: list[NormalizedEvent]) -> list[NormalizedEvent]:
        """
        Enrich each event in-place under metadata["enrichment"].

        Args:
            events: NormalizedEvent list from the normalize stage.

        Returns:
            The same list with metadata["enrichment"] populated on every event.
            Order and length are unchanged.

        Raises:
            AttributeError: if a required intelligence module is not yet implemented.
            TypeError:      if ContextBuilder.build() returns a non-list, or if any
                            intelligence call returns a non-dict.
            ValueError:     if ContextBuilder.build() returns a different length
                            than the input event count.
        """
        if not events:
            return events

        IpReputation   = _load(_ip_rep_mod,  "IpReputation")
        GeoEnrichment  = _load(_geo_mod,     "GeoEnrichment")
        ThreatFeeds    = _load(_feeds_mod,   "ThreatFeeds")
        ContextBuilder = _load(_context_mod, "ContextBuilder")

        ip_rep  = IpReputation()
        geo     = GeoEnrichment()
        feeds   = ThreatFeeds()

        # Context builder operates on the full batch — must see all events at once
        context_list = ContextBuilder().build([e.to_dict() for e in events])

        if not isinstance(context_list, list):
            raise TypeError(
                f"ContextBuilder.build() must return list, "
                f"got {type(context_list).__name__!r}"
            )
        if len(context_list) != len(events):
            raise ValueError(
                f"ContextBuilder.build() must return exactly one entry per input event "
                f"(expected {len(events)}, got {len(context_list)})"
            )

        for idx, event in enumerate(events):
            enrichment: dict = {}

            if event.src_ip:
                enrichment["src_reputation"] = ip_rep.lookup(event.src_ip)
                enrichment["src_geo"]        = geo.lookup(event.src_ip)
                enrichment["src_threats"]    = feeds.check(event.src_ip)

            if event.dst_ip:
                enrichment["dst_reputation"] = ip_rep.lookup(event.dst_ip)
                enrichment["dst_geo"]        = geo.lookup(event.dst_ip)
                enrichment["dst_threats"]    = feeds.check(event.dst_ip)

            enrichment["context"] = context_list[idx]
            event.metadata["enrichment"] = enrichment

        return events
