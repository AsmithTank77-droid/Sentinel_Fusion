"""Tests for core/pipeline/enrich.py — Stage 3: Enrichment."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pipeline.enrich import Enricher
from core.pipeline.normalize import NormalizedEvent


def _event(src="185.220.101.45", dst="10.0.0.5", etype="port_scan",
           severity=8, ts="2026-05-09T02:14:00Z"):
    return NormalizedEvent(
        timestamp=ts,
        source_type="nra",
        src_ip=src,
        dst_ip=dst,
        event_type=etype,
        severity=severity,
        metadata={},
    )


class TestEnricher:
    def setup_method(self):
        self.enricher = Enricher()

    def test_empty_list_returns_empty(self):
        result = self.enricher.enrich([])
        assert result == []

    def test_returns_same_list_length(self):
        events = [_event(), _event()]
        result = self.enricher.enrich(events)
        assert len(result) == 2

    def test_returns_normalized_event_objects(self):
        events = [_event()]
        result = self.enricher.enrich(events)
        assert isinstance(result[0], NormalizedEvent)

    def test_enrichment_key_added_to_metadata(self):
        events = [_event()]
        result = self.enricher.enrich(events)
        assert "enrichment" in result[0].metadata

    def test_src_reputation_present_for_known_malicious(self):
        events = [_event(src="185.220.101.45")]
        result = self.enricher.enrich(events)
        enrichment = result[0].metadata["enrichment"]
        assert "src_reputation" in enrichment
        assert enrichment["src_reputation"]["is_malicious"] is True

    def test_src_geo_present(self):
        events = [_event(src="185.220.101.45")]
        result = self.enricher.enrich(events)
        enrichment = result[0].metadata["enrichment"]
        assert "src_geo" in enrichment
        assert enrichment["src_geo"]["country"] == "Russia"

    def test_src_threats_present(self):
        events = [_event(src="185.220.101.45")]
        result = self.enricher.enrich(events)
        enrichment = result[0].metadata["enrichment"]
        assert "src_threats" in enrichment
        assert "tor-exit-nodes" in enrichment["src_threats"]["feed_hits"]

    def test_dst_reputation_present_for_known_ip(self):
        events = [_event(dst="23.129.64.101")]
        result = self.enricher.enrich(events)
        enrichment = result[0].metadata["enrichment"]
        assert "dst_reputation" in enrichment

    def test_dst_geo_present(self):
        events = [_event(dst="10.0.0.5")]
        result = self.enricher.enrich(events)
        enrichment = result[0].metadata["enrichment"]
        assert "dst_geo" in enrichment
        assert enrichment["dst_geo"]["country"] == "Internal"

    def test_context_always_present(self):
        events = [_event()]
        result = self.enricher.enrich(events)
        assert "context" in result[0].metadata["enrichment"]

    def test_empty_src_ip_skips_src_enrichment(self):
        events = [_event(src="")]
        result = self.enricher.enrich(events)
        enrichment = result[0].metadata["enrichment"]
        assert "src_reputation" not in enrichment
        assert "src_geo" not in enrichment
        assert "src_threats" not in enrichment

    def test_empty_dst_ip_skips_dst_enrichment(self):
        events = [_event(dst="")]
        result = self.enricher.enrich(events)
        enrichment = result[0].metadata["enrichment"]
        assert "dst_reputation" not in enrichment

    def test_non_enrichment_fields_unchanged(self):
        events = [_event(src="185.220.101.45", dst="10.0.0.5",
                         etype="port_scan", severity=8)]
        result = self.enricher.enrich(events)
        ev = result[0]
        assert ev.src_ip == "185.220.101.45"
        assert ev.dst_ip == "10.0.0.5"
        assert ev.event_type == "port_scan"
        assert ev.severity == 8

    def test_context_batch_size_reflects_input(self):
        events = [_event(), _event(src="10.0.0.1")]
        result = self.enricher.enrich(events)
        for ev in result:
            assert ev.metadata["enrichment"]["context"]["batch_size"] == 2

    def test_multiple_events_all_get_enrichment(self):
        events = [
            _event(src="185.220.101.45", ts="2026-05-09T02:14:00Z"),
            _event(src="185.220.101.45", ts="2026-05-09T02:15:00Z",
                   etype="authentication_failure", severity=5),
        ]
        result = self.enricher.enrich(events)
        for ev in result:
            assert "enrichment" in ev.metadata
            assert "src_reputation" in ev.metadata["enrichment"]
