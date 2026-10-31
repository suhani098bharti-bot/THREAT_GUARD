"""Incident lifecycle management, analyst workflow, and status tracking."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import pandas as pd

from database.db_operations import (
    add_incident_note,
    get_all_incidents,
    get_detection_events_for_incident,
    get_incident_by_id,
    get_notes_for_incident,
    update_incident_status,
)


def get_incident_full_context(
    incident_id: int, db_path: Optional[Union[str, Path]] = None
) -> Optional[Dict[str, Any]]:
    """Retrieve complete incident profile including linked detection events and notes."""
    incident = get_incident_by_id(incident_id, db_path=db_path)
    if not incident:
        return None

    detection_events = get_detection_events_for_incident(incident_id, db_path=db_path)
    notes = get_notes_for_incident(incident_id, db_path=db_path)

    incident_dict = dict(incident)
    incident_dict["events"] = detection_events
    incident_dict["notes"] = notes
    return incident_dict


def update_incident_workflow(
    incident_id: int,
    status: str,
    resolution_notes: Optional[str] = None,
    assigned_to: Optional[str] = None,
    author_username: str = "System",
    author_id: Optional[int] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> bool:
    """Update incident status/assignment and record chronological audit note."""
    success = update_incident_status(
        incident_id=incident_id,
        status=status,
        resolution_notes=resolution_notes,
        assigned_to=assigned_to,
        db_path=db_path,
    )

    if success:
        log_parts = [f"Status changed to '{status}'."]
        if assigned_to:
            log_parts.append(f"Assigned to {assigned_to}.")
        if resolution_notes:
            log_parts.append(f"Notes: {resolution_notes}")

        audit_msg = " | ".join(log_parts)
        add_incident_note(
            incident_id=incident_id,
            user_id=author_id,
            username=author_username,
            note=audit_msg,
            db_path=db_path,
        )

    return success


def add_analyst_note(
    incident_id: int,
    note: str,
    username: str,
    user_id: Optional[int] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> bool:
    """Add a manual investigation finding note to an incident."""
    if not note or not note.strip():
        return False
    row_id = add_incident_note(
        incident_id=incident_id,
        user_id=user_id,
        username=username,
        note=note.strip(),
        db_path=db_path,
    )
    return row_id > 0


def fetch_incidents_as_dataframe(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    search_query: Optional[str] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> pd.DataFrame:
    """Retrieve incidents matching filter criteria as a clean DataFrame."""
    incidents = get_all_incidents(
        status=status,
        severity=severity,
        category=category,
        search_query=search_query,
        db_path=db_path,
    )
    if not incidents:
        return pd.DataFrame(
            columns=[
                "id",
                "title",
                "category",
                "source_ip",
                "severity",
                "risk_score",
                "status",
                "assigned_to",
                "created_at",
                "updated_at",
            ]
        )
    return pd.DataFrame(incidents)
