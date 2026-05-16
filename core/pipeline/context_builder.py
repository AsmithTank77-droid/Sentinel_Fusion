"""
context_builder.py — Enrichment helper: cross-event context assembly.
Pipeline: called by enrich.py before per-event intelligence lookups.

Groups all events in a batch by src_ip and annotates each event with a
context slice showing what else that source IP did in the same batch.
Stateless. No external libraries.
"""

from __future__ import annotations

from collections import defaultdict


class ContextBuilder:
    """
    Builds a cross-event context slice for each event in a batch.
    Stateless: no state is maintained between calls.

    Contract (required by enrich.py):
        build(events: list[dict]) -> list[dict]
        Returns exactly one context dict per input event, same index order.
    """

    def build(self, events: list[dict]) -> list[dict]:
        """
        For each event, return a context dict describing other activity from
        the same src_ip in this batch.

        Args:
            events: list of event dicts (NormalizedEvent.to_dict() format).

        Returns:
            list[dict] of the same length as events. Each dict contains:
                {
                    "same_src_event_count": int,
                    "same_src_event_types": list[str],
                    "same_src_severity_max": int,
                    "same_src_dst_ips": list[str],
                    "batch_size": int,
                }
        """
        if not events:
            return []

        # Build index: src_ip -> list of event indices
        src_to_indices: dict[str, list[int]] = defaultdict(list)
        for idx, event in enumerate(events):
            src = event.get("src_ip") or ""
            if src:
                src_to_indices[src].append(idx)

        results: list[dict] = []
        for idx, event in enumerate(events):
            src = event.get("src_ip") or ""
            peer_indices = [i for i in src_to_indices.get(src, []) if i != idx]

            if not src or not peer_indices:
                results.append({
                    "same_src_event_count": 0,
                    "same_src_event_types": [],
                    "same_src_severity_max": 0,
                    "same_src_dst_ips": [],
                    "batch_size": len(events),
                })
                continue

            peer_events     = [events[i] for i in peer_indices]
            event_types     = list(dict.fromkeys(
                e.get("event_type") or "" for e in peer_events if e.get("event_type")
            ))
            severity_max    = max((e.get("severity") or 0) for e in peer_events)
            dst_ips         = list(dict.fromkeys(
                e.get("dst_ip") or "" for e in peer_events if e.get("dst_ip")
            ))

            results.append({
                "same_src_event_count": len(peer_indices),
                "same_src_event_types": event_types,
                "same_src_severity_max": severity_max,
                "same_src_dst_ips": dst_ips,
                "batch_size": len(events),
            })

        return results
