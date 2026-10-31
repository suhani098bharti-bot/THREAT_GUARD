"""SIEM threat detection orchestration engine for ThreatGuard."""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import pandas as pd

from config.settings import DEFAULT_DETECTION_THRESHOLDS
from database.db_operations import (
    create_incident,
    find_active_incident_by_source_and_category,
    insert_detection_event,
)
from detection.detection_rules import ACTIVE_DETECTION_RULES, DetectionResult

logger = logging.getLogger("threatguard.detection_engine")


class DetectionEngine:
    """Orchestrator that evaluates security log batches against all registered detection rules."""

    def __init__(self, thresholds: Optional[Dict[str, Any]] = None):
        self.thresholds = thresholds or DEFAULT_DETECTION_THRESHOLDS.copy()
        self.rules = ACTIVE_DETECTION_RULES

    def analyze_logs(
        self,
        logs_df: pd.DataFrame,
        persist_to_db: bool = True,
        db_path: Optional[Union[str, Path]] = None,
    ) -> List[DetectionResult]:
        """Execute detection rules across logs and optionally persist incidents and events."""
        if logs_df.empty:
            return []

        all_results: List[DetectionResult] = []

        # Evaluate each rule independently
        for rule in self.rules:
            try:
                rule_hits = rule.evaluate(logs_df, self.thresholds)
                all_results.extend(rule_hits)
            except Exception as e:
                logger.error("Error evaluating rule %s: %s", getattr(rule, "rule_id", "unknown"), str(e))

        # Persist to database if requested
        if persist_to_db and all_results:
            self._persist_detections(all_results, db_path=db_path)

        return all_results

    def _persist_detections(
        self, results: List[DetectionResult], db_path: Optional[Union[str, Path]] = None
    ) -> None:
        """Store detection events and correlate with active incidents without duplication."""
        for det in results:
            try:
                # Deduplication logic: Check for existing active incident with same source IP and category
                existing_inc = find_active_incident_by_source_and_category(
                    source_ip=det.source_ip,
                    category=det.category,
                    db_path=db_path,
                )

                if existing_inc:
                    incident_id = existing_inc["id"]
                else:
                    # Create new incident
                    title = f"Alert: {det.category} from {det.source_ip}"
                    description = (
                        f"{det.explanation}\n\n"
                        f"Recommended Mitigation:\n{det.recommended_response}"
                    )
                    incident_id = create_incident(
                        title=title,
                        category=det.category,
                        source_ip=det.source_ip,
                        severity=det.severity,
                        risk_score=det.risk_score,
                        description=description,
                        status="New",
                        assigned_to="Unassigned",
                        db_path=db_path,
                    )

                # Record the detection event linked to the incident
                insert_detection_event(
                    rule_id=det.rule_id,
                    incident_id=incident_id,
                    source_ip=det.source_ip,
                    severity=det.severity,
                    risk_score=det.risk_score,
                    explanation=det.explanation,
                    db_path=db_path,
                )

            except Exception as e:
                logger.error("Failed to persist detection result for %s: %s", det.rule_id, str(e))


def run_threat_detection(
    logs_df: pd.DataFrame,
    thresholds: Optional[Dict[str, Any]] = None,
    persist_to_db: bool = True,
    db_path: Optional[Union[str, Path]] = None,
) -> List[DetectionResult]:
    """Convenience functional wrapper to run detection engine."""
    engine = DetectionEngine(thresholds=thresholds)
    return engine.analyze_logs(logs_df, persist_to_db=persist_to_db, db_path=db_path)
