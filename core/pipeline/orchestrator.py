"""
orchestrator.py — Stage Coordinator
Pipeline: ingest → normalize → enrich → sigma → correlate → detect → score → timeline → report → hunt

Coordinates end-to-end pipeline execution only. No detection, scoring, or
reporting logic lives here. Each stage delegates entirely to its module.

Stage order is fixed per CLAUDE.md §2 and enforced structurally — no stage
method calls a later stage, and no stage is called more than once per run.
"""

from __future__ import annotations

import core.pipeline.ingest as _ingest_mod
import core.pipeline.enrich as _enrich_mod
import detection.sigma_engine as _sigma_mod
import detection.correlation_engine as _correlation_mod
import detection.brute_force_detection as _brute_force_mod
import detection.lateral_movement_detection as _lateral_movement_mod
import detection.anomaly_detection as _anomaly_mod
import detection.winlog_rules as _winlog_rules_mod
import scoring.host_risk as _host_risk_mod
import scoring.asset_risk as _asset_risk_mod
import scoring.attack_surface as _attack_surface_mod
import narrative.timeline_builder as _timeline_mod
import reporting.report_generator as _report_mod
import hunting.hunt_engine as _hunt_mod

from core.pipeline.normalize import Normalizer, NormalizedEvent


# ---------------------------------------------------------------------------
# Pipeline error type
# ---------------------------------------------------------------------------

class PipelineStageError(Exception):
    """
    Raised when any pipeline stage fails.
    Carries the stage name so callers can identify the failure point without
    inspecting the traceback.
    """

    def __init__(self, stage: str, cause: Exception) -> None:
        self.stage = stage
        self.cause = cause
        super().__init__(f"[stage:{stage}] {type(cause).__name__}: {cause}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _require(module: object, attr: str, stage: str) -> object:
    """
    Return module.attr, raising PipelineStageError(stage) if the attribute is
    absent. Used to give a clear "not yet implemented" failure at stage
    invocation rather than a raw AttributeError.
    """
    try:
        return getattr(module, attr)
    except AttributeError as exc:
        raise PipelineStageError(
            stage,
            NotImplementedError(
                f"{module.__name__!r} does not export {attr!r} — "
                f"stage '{stage}' cannot run until the module is implemented"
            ),
        ) from exc


def _dedup_key(alert: dict) -> tuple[str, str, str]:
    """Derive a deduplication key from an alert dict.

    Works across alert shapes: WINLOG rules store IPs in context{}, while
    brute_force / lateral_movement put them at the top level.
    """
    ctx = alert.get("context") or {}
    src = (
        str(alert.get("src_ip") or "")
        or str(alert.get("initial_src_ip") or "")
        or str(ctx.get("src_ip") or "")
    )
    dst = (
        str(alert.get("dst_ip") or "")
        or str(alert.get("lateral_target") or "")
        or str(ctx.get("destination") or "")
        or str(ctx.get("computer") or "")
    )
    return (str(alert.get("alert_type") or ""), src, dst)


def _deduplicate_alerts(alerts: list[dict]) -> list[dict]:
    """Remove duplicate alerts with the same (alert_type, src_ip, dst_ip).

    When duplicates exist, keeps the highest-confidence copy. Order of
    first occurrence is preserved for determinism.
    """
    seen: dict[tuple, dict] = {}
    order: list[tuple] = []
    for alert in alerts:
        key = _dedup_key(alert)
        if key not in seen:
            seen[key] = alert
            order.append(key)
        else:
            existing_conf = float(seen[key].get("confidence") or 0)
            new_conf      = float(alert.get("confidence") or 0)
            if new_conf > existing_conf:
                seen[key] = alert
    return [seen[k] for k in order]


def _assert_list(value: object, origin: str, stage: str) -> list:
    """Raise PipelineStageError if value is not a list."""
    if not isinstance(value, list):
        raise PipelineStageError(
            stage,
            TypeError(f"{origin} must return list, got {type(value).__name__!r}"),
        )
    return value


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class PipelineOrchestrator:
    """
    Executes the Sentinel_Fusion detection pipeline end-to-end.

    Stage order (fixed, CLAUDE.md §2):
        1.  ingest      — raw event intake, source tagging, pre-validation
        2.  normalize   — unified NormalizedEvent schema conversion
        3.  enrich      — threat intelligence and context augmentation
        4.  sigma       — Sigma-compatible rule evaluation against enriched events
        5.  correlate   — cross-event attack chain detection
        6.  detect      — per-module stateless detection (brute force, lateral, anomaly)
        7.  score       — host risk, asset risk, attack surface expansion
        8.  timeline    — chronological attack narrative construction
        9.  report      — structured JSON + Markdown SOC report
        10. hunt        — cross-run proactive threat hunting (requires store)

    The orchestrator holds no mutable state between runs. Every call to run()
    is independent and deterministic given the same inputs.

    Expected module contracts (each downstream module must fulfill these):

        core.pipeline.ingest.Ingester
            .ingest(source_type: str, raw: dict) -> dict

        core.pipeline.enrich.Enricher
            .enrich(events: list[NormalizedEvent]) -> list[NormalizedEvent]
            Writes enrichment data to event.metadata["enrichment"] only.
            Delegates to: IpReputation, GeoEnrichment, ThreatFeeds, ContextBuilder.

        detection.correlation_engine.CorrelationEngine
            .correlate(events: list[dict]) -> list[dict]

        detection.*.{BruteForceDetector,LateralMovementDetector,AnomalyDetector}
            .detect(events: list[dict]) -> list[dict]
            Each alert dict must include at minimum: event_type, confidence (0-1).
            Receives enriched event dicts — metadata["enrichment"] is available.

        scoring.host_risk.HostRisk
            .score(events: list[dict], alerts: list[dict]) -> dict

        scoring.asset_risk.AssetRisk
            .score(events: list[dict], alerts: list[dict]) -> dict

        scoring.attack_surface.AttackSurface
            .score(events: list[dict], alerts: list[dict]) -> dict

        narrative.timeline_builder.TimelineBuilder
            .build(events: list[dict], alerts: list[dict], scores: dict) -> list[dict]
            Internally calls narrative.attack_story_engine.AttackStoryEngine
            .narrate(timeline: list[dict], alerts: list[dict]) -> str
            to produce human-readable SOC narrative for the report.

        reporting.report_generator.ReportGenerator
            .generate(timeline: list[dict], scores: dict, alerts: list[dict])
            -> {"json": dict, "markdown": str}
    """

    _VALID_SOURCES: frozenset[str] = frozenset({"nra", "winlog", "mock"})

    _NORMALIZE_METHOD: dict[str, str] = {
        "nra":    "normalize_nra",
        "winlog": "normalize_winlog",
        "mock":   "normalize_mock",
    }

    def __init__(self) -> None:
        self._normalizer = Normalizer()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, inputs: dict[str, list[dict]], store=None) -> dict:
        """
        Execute the full 10-stage pipeline over a multi-source event batch.

        Args:
            inputs: {source_type: [raw_event_dict, ...]}
                    Valid source_type values: "nra", "winlog", "mock".
                    Any key may be absent; empty lists are accepted.
            store:  Optional StorageLayer. Required for Stage 10 (hunt).
                    If None, hunt returns [] and the stage still appears in trace.

        Returns:
            {
                "event_count":       int,
                "normalized_events": list[dict],   # serialised NormalizedEvent
                "alerts":            list[dict],   # all correlated + detection alerts
                "scores":            dict,         # host_risk, asset_risk, attack_surface
                "timeline":          list[dict],   # chronological attack entries
                "report":            {             # final SOC output
                    "json":     dict,
                    "markdown": str,
                },
                "hunt_findings":     list[dict],   # cross-run proactive hunt results
                "trace":             list[dict],   # per-stage audit log
            }

        Raises:
            ValueError:          on invalid source_type keys or malformed inputs arg.
            PipelineStageError:  on any failure inside a stage; .stage identifies which.
        """
        if not isinstance(inputs, dict):
            raise ValueError(f"inputs must be a dict, got {type(inputs).__name__!r}")

        unknown = set(inputs) - self._VALID_SOURCES
        if unknown:
            raise ValueError(
                f"Unknown source type(s) {sorted(unknown)!r}. "
                f"Must be subset of {sorted(self._VALID_SOURCES)!r}."
            )

        for source_type, events in inputs.items():
            if not isinstance(events, list):
                raise ValueError(
                    f"inputs[{source_type!r}] must be a list of dicts, "
                    f"got {type(events).__name__!r}"
                )

        trace: list[dict] = []

        raw_tagged    = self._stage_ingest(inputs, trace)
        normalized    = self._stage_normalize(raw_tagged, trace)
        enriched      = self._stage_enrich(normalized, trace)
        sigma_alerts  = self._stage_sigma(enriched, trace)
        correlated    = self._stage_correlate(enriched, trace)
        alerts        = self._stage_detect(enriched, correlated, sigma_alerts, trace)
        scores        = self._stage_score(enriched, alerts, trace)
        timeline      = self._stage_timeline(enriched, alerts, scores, trace)
        report        = self._stage_report(timeline, scores, alerts, trace, enriched)
        hunt_findings = self._stage_hunt(store, trace)

        return {
            "event_count":       len(enriched),
            "normalized_events": [e.to_dict() for e in enriched],
            "alerts":            alerts,
            "scores":            scores,
            "timeline":          timeline,
            "report":            report,
            "hunt_findings":     hunt_findings,
            "trace":             trace,
        }

    # ------------------------------------------------------------------
    # Stage 1: Ingest
    # ------------------------------------------------------------------

    def _stage_ingest(
        self,
        inputs: dict[str, list[dict]],
        trace: list[dict],
    ) -> list[tuple[str, dict]]:
        """
        Delegates to ingest.Ingester.ingest(source_type, raw) for each event.
        Returns list of (source_type, ingested_dict) pairs.
        """
        STAGE = "ingest"
        try:
            Ingester = _require(_ingest_mod, "Ingester", STAGE)
            ingester = Ingester()
            tagged: list[tuple[str, dict]] = []
            for source_type, events in inputs.items():
                for idx, raw in enumerate(events):
                    if not isinstance(raw, dict):
                        raise TypeError(
                            f"inputs[{source_type!r}][{idx}] must be a dict, "
                            f"got {type(raw).__name__!r}"
                        )
                    result = ingester.ingest(source_type, raw)
                    if not isinstance(result, dict):
                        raise TypeError(
                            f"Ingester.ingest() must return dict, "
                            f"got {type(result).__name__!r} for {source_type!r}[{idx}]"
                        )
                    tagged.append((source_type, result))
            trace.append({"stage": STAGE, "status": "ok", "count": len(tagged)})
            return tagged
        except PipelineStageError:
            raise
        except Exception as exc:
            raise PipelineStageError(STAGE, exc) from exc

    # ------------------------------------------------------------------
    # Stage 2: Normalize
    # ------------------------------------------------------------------

    def _stage_normalize(
        self,
        raw_tagged: list[tuple[str, dict]],
        trace: list[dict],
    ) -> list[NormalizedEvent]:
        """
        Routes each (source_type, raw) pair to the matching Normalizer method.
        Validates that every output is a NormalizedEvent before continuing.
        """
        STAGE = "normalize"
        try:
            normalized: list[NormalizedEvent] = []
            for idx, (source_type, raw) in enumerate(raw_tagged):
                method = getattr(self._normalizer, self._NORMALIZE_METHOD[source_type])
                event = method(raw)
                if not isinstance(event, NormalizedEvent):
                    raise TypeError(
                        f"Normalizer.normalize_{source_type}() must return NormalizedEvent, "
                        f"got {type(event).__name__!r} at index {idx}"
                    )
                normalized.append(event)
            trace.append({"stage": STAGE, "status": "ok", "count": len(normalized)})
            return normalized
        except PipelineStageError:
            raise
        except Exception as exc:
            raise PipelineStageError(STAGE, exc) from exc

    # ------------------------------------------------------------------
    # Stage 3: Enrich
    # ------------------------------------------------------------------

    def _stage_enrich(
        self,
        normalized: list[NormalizedEvent],
        trace: list[dict],
    ) -> list[NormalizedEvent]:
        """
        Delegates to Enricher.enrich() to augment every NormalizedEvent with
        threat intelligence (ip_reputation, geo_enrichment, threat_feeds) and
        contextual data (context_builder). Enrichment is stored under
        event.metadata["enrichment"] — no other event fields are modified.
        Returns the same list of NormalizedEvent objects, now enriched.
        """
        STAGE = "enrich"
        try:
            Enricher = _require(_enrich_mod, "Enricher", STAGE)
            enricher = Enricher()
            enriched = enricher.enrich(normalized)
            if not isinstance(enriched, list):
                raise TypeError(
                    f"Enricher.enrich() must return list[NormalizedEvent], "
                    f"got {type(enriched).__name__!r}"
                )
            if len(enriched) != len(normalized):
                raise ValueError(
                    f"Enricher.enrich() must return the same number of events as input "
                    f"(expected {len(normalized)}, got {len(enriched)})"
                )
            for idx, ev in enumerate(enriched):
                if not isinstance(ev, NormalizedEvent):
                    raise TypeError(
                        f"Enricher.enrich() must return list[NormalizedEvent]; "
                        f"element {idx} is {type(ev).__name__!r}"
                    )
            trace.append({"stage": STAGE, "status": "ok", "count": len(enriched)})
            return enriched
        except PipelineStageError:
            raise
        except Exception as exc:
            raise PipelineStageError(STAGE, exc) from exc

    # ------------------------------------------------------------------
    # Stage 4: Sigma Rule Evaluation
    # ------------------------------------------------------------------

    def _stage_sigma(
        self,
        enriched: list[NormalizedEvent],
        trace: list[dict],
    ) -> list[dict]:
        """
        Runs SigmaEngine.detect() against the full enriched event batch.

        Sigma rules are evaluated before correlation so that rule-match alerts
        can inform the correlation and detect stages downstream. Results are
        seeded into the detect stage alert pool alongside correlated chains.
        """
        STAGE = "sigma"
        try:
            SigmaEngine  = _require(_sigma_mod, "SigmaEngine", STAGE)
            events_dicts = [e.to_dict() for e in enriched]
            results      = SigmaEngine().detect(events_dicts)
            _assert_list(results, "SigmaEngine.detect()", STAGE)
            trace.append({"stage": STAGE, "status": "ok", "count": len(results)})
            return results
        except PipelineStageError:
            raise
        except Exception as exc:
            raise PipelineStageError(STAGE, exc) from exc

    # ------------------------------------------------------------------
    # Stage 5: Correlate
    # ------------------------------------------------------------------

    def _stage_correlate(
        self,
        normalized: list[NormalizedEvent],
        trace: list[dict],
    ) -> list[dict]:
        """
        Delegates the full normalized event batch to CorrelationEngine.correlate().
        Returns correlated alert chains.
        """
        STAGE = "correlate"
        try:
            CorrelationEngine = _require(_correlation_mod, "CorrelationEngine", STAGE)
            engine = CorrelationEngine()
            events_dicts = [e.to_dict() for e in normalized]
            correlated = engine.correlate(events_dicts)
            _assert_list(correlated, "CorrelationEngine.correlate()", STAGE)
            trace.append({"stage": STAGE, "status": "ok", "count": len(correlated)})
            return correlated
        except PipelineStageError:
            raise
        except Exception as exc:
            raise PipelineStageError(STAGE, exc) from exc

    # ------------------------------------------------------------------
    # Stage 6: Detect
    # ------------------------------------------------------------------

    def _stage_detect(
        self,
        normalized: list[NormalizedEvent],
        correlated: list[dict],
        sigma_alerts: list[dict],
        trace: list[dict],
    ) -> list[dict]:
        """
        Runs all detection modules against the full normalized event batch.
        Alert pool is seeded with correlated chains (Stage 5) and Sigma rule
        matches (Stage 4); each detector appends its own findings. Detection
        modules are stateless and receive the full event list so cross-event
        patterns (e.g. brute force counting) are visible.
        """
        STAGE = "detect"
        try:
            BruteForceDetector      = _require(_brute_force_mod,      "BruteForceDetector",      STAGE)
            LateralMovementDetector = _require(_lateral_movement_mod, "LateralMovementDetector", STAGE)
            AnomalyDetector         = _require(_anomaly_mod,          "AnomalyDetector",         STAGE)
            WinlogRulesDetector     = _require(_winlog_rules_mod,     "WinlogRulesDetector",     STAGE)

            detectors = [
                BruteForceDetector(),
                LateralMovementDetector(),
                AnomalyDetector(),
                WinlogRulesDetector(),
            ]

            events_dicts = [e.to_dict() for e in normalized]
            alerts: list[dict] = list(correlated) + list(sigma_alerts)

            for detector in detectors:
                results = detector.detect(events_dicts)
                _assert_list(results, f"{type(detector).__name__}.detect()", STAGE)
                for result in results:
                    if not isinstance(result, dict):
                        raise TypeError(
                            f"{type(detector).__name__}.detect() must return list[dict]; "
                            f"got element of type {type(result).__name__!r}"
                        )
                alerts.extend(results)

            alerts = _deduplicate_alerts(alerts)
            trace.append({"stage": STAGE, "status": "ok", "count": len(alerts)})
            return alerts
        except PipelineStageError:
            raise
        except Exception as exc:
            raise PipelineStageError(STAGE, exc) from exc

    # ------------------------------------------------------------------
    # Stage 7: Score
    # ------------------------------------------------------------------

    def _stage_score(
        self,
        normalized: list[NormalizedEvent],
        alerts: list[dict],
        trace: list[dict],
    ) -> dict:
        """
        Delegates to HostRisk, AssetRisk, and AttackSurface scorers.
        Returns a unified scores dict keyed by scorer domain.
        """
        STAGE = "score"
        try:
            HostRisk      = _require(_host_risk_mod,     "HostRisk",      STAGE)
            AssetRisk     = _require(_asset_risk_mod,    "AssetRisk",     STAGE)
            AttackSurface = _require(_attack_surface_mod, "AttackSurface", STAGE)

            events_dicts = [e.to_dict() for e in normalized]

            scores = {
                "host_risk":      HostRisk().score(events_dicts, alerts),
                "asset_risk":     AssetRisk().score(events_dicts, alerts),
                "attack_surface": AttackSurface().score(events_dicts, alerts),
            }
            trace.append({"stage": STAGE, "status": "ok"})
            return scores
        except PipelineStageError:
            raise
        except Exception as exc:
            raise PipelineStageError(STAGE, exc) from exc

    # ------------------------------------------------------------------
    # Stage 8: Timeline
    # ------------------------------------------------------------------

    def _stage_timeline(
        self,
        normalized: list[NormalizedEvent],
        alerts: list[dict],
        scores: dict,
        trace: list[dict],
    ) -> list[dict]:
        """
        Delegates to TimelineBuilder.build() to construct the chronological
        attack narrative from normalized events, alerts, and risk scores.
        """
        STAGE = "timeline"
        try:
            TimelineBuilder = _require(_timeline_mod, "TimelineBuilder", STAGE)
            builder = TimelineBuilder()
            timeline = builder.build(
                events=[e.to_dict() for e in normalized],
                alerts=alerts,
                scores=scores,
            )
            _assert_list(timeline, "TimelineBuilder.build()", STAGE)
            trace.append({"stage": STAGE, "status": "ok", "count": len(timeline)})
            return timeline
        except PipelineStageError:
            raise
        except Exception as exc:
            raise PipelineStageError(STAGE, exc) from exc

    # ------------------------------------------------------------------
    # Stage 9: Report
    # ------------------------------------------------------------------

    def _stage_report(
        self,
        timeline: list[dict],
        scores: dict,
        alerts: list[dict],
        trace: list[dict],
        enriched: list | None = None,
    ) -> dict:
        """
        Delegates to ReportGenerator.generate() to produce the final SOC report.
        Validates that the result contains both 'json' and 'markdown' keys
        per CLAUDE.md §9 output requirements.
        """
        STAGE = "report"
        try:
            ReportGenerator = _require(_report_mod, "ReportGenerator", STAGE)
            generator = ReportGenerator()
            normalized_events = [e.to_dict() for e in enriched] if enriched else []
            report = generator.generate(
                timeline=timeline,
                scores=scores,
                alerts=alerts,
                normalized_events=normalized_events,
            )
            if not isinstance(report, dict):
                raise TypeError(
                    f"ReportGenerator.generate() must return dict, "
                    f"got {type(report).__name__!r}"
                )
            missing = {"json", "markdown"} - set(report)
            if missing:
                raise ValueError(
                    f"ReportGenerator.generate() result is missing required "
                    f"key(s): {sorted(missing)!r}"
                )
            trace.append({"stage": STAGE, "status": "ok"})
            return report
        except PipelineStageError:
            raise
        except Exception as exc:
            raise PipelineStageError(STAGE, exc) from exc

    # ------------------------------------------------------------------
    # Stage 10: Hunt
    # ------------------------------------------------------------------

    def _stage_hunt(self, store, trace: list[dict]) -> list[dict]:
        """
        Runs HuntEngine.hunt() against StorageLayer to surface cross-run
        threat patterns. If store is None (test / no-DB environments),
        returns [] — the stage still appears in the trace with count=0.
        """
        STAGE = "hunt"
        try:
            HuntEngine = _require(_hunt_mod, "HuntEngine", STAGE)
            findings   = HuntEngine().hunt(store)
            _assert_list(findings, "HuntEngine.hunt()", STAGE)
            trace.append({"stage": STAGE, "status": "ok", "count": len(findings)})
            return findings
        except PipelineStageError:
            raise
        except Exception as exc:
            raise PipelineStageError(STAGE, exc) from exc
