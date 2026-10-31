"""Unit and integration tests for incident management and response workflows."""

import pytest
import tempfile
from pathlib import Path
import pandas as pd

from database.db_operations import (
    create_incident,
    find_active_incident_by_source_and_category,
    get_all_incidents,
    get_incident_by_id,
)
from database.db_setup import initialize_database
from detection.detection_engine import run_threat_detection
from incident_response.incident_manager import (
    add_analyst_note,
    fetch_incidents_as_dataframe,
    get_incident_full_context,
    update_incident_workflow,
)


@pytest.fixture
def temp_db():
    """Create isolated temporary database for test execution."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_path = Path(f.name)

    initialize_database(db_path=temp_path)
    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


def test_create_and_retrieve_incident(temp_db):
    """Test incident insertion and detail retrieval."""
    inc_id = create_incident(
        title="Alert: Port Scanning from 203.0.113.10",
        category="Port Scanning",
        source_ip="203.0.113.10",
        severity="HIGH",
        risk_score=78,
        description="Reconnaissance scan across multiple TCP ports.",
        status="New",
        assigned_to="Analyst John",
        db_path=temp_db,
    )

    assert inc_id > 0
    inc = get_incident_by_id(inc_id, db_path=temp_db)
    assert inc is not None
    assert inc["title"] == "Alert: Port Scanning from 203.0.113.10"
    assert inc["status"] == "New"
    assert inc["risk_score"] == 78


def test_update_incident_workflow_and_notes(temp_db):
    """Test updating incident status, assignee, and audit trail."""
    inc_id = create_incident(
        title="Alert: SQLi Attack",
        category="SQL Injection",
        source_ip="198.51.100.55",
        severity="CRITICAL",
        risk_score=95,
        description="SQL injection in search form.",
        db_path=temp_db,
    )

    # Update workflow status to Investigating
    updated = update_incident_workflow(
        incident_id=inc_id,
        status="Investigating",
        resolution_notes="Initiated query parameter validation check.",
        assigned_to="Analyst Sarah",
        author_username="admin",
        db_path=temp_db,
    )
    assert updated is True

    # Add custom analyst finding note
    note_added = add_analyst_note(
        incident_id=inc_id,
        note="Inspected WAF logs. Request was blocked by signature rule 942100.",
        username="Analyst Sarah",
        db_path=temp_db,
    )
    assert note_added is True

    # Retrieve full context and verify notes
    context = get_incident_full_context(inc_id, db_path=temp_db)
    assert context is not None
    assert context["status"] == "Investigating"
    assert context["assigned_to"] == "Analyst Sarah"
    assert len(context["notes"]) >= 2  # Audit note + analyst note


def test_incident_deduplication_prevention(temp_db):
    """Test that recurring detections from the same source IP and category do not duplicate incidents."""
    df_hits = pd.DataFrame(
        [
            {
                "timestamp": f"2026-10-31 11:0{i}:00",
                "source_ip": "198.51.100.42",
                "destination_ip": "10.0.0.5",
                "username": "root",
                "event_type": "login",
                "status": "FAILED",
                "port": 443,
                "protocol": "TCP",
                "message": "Auth failure",
            }
            for i in range(6)
        ]
    )

    # First run
    run_threat_detection(df_hits, persist_to_db=True, db_path=temp_db)
    incidents_run1 = get_all_incidents(db_path=temp_db)
    assert len(incidents_run1) == 1

    # Second run with same threat
    run_threat_detection(df_hits, persist_to_db=True, db_path=temp_db)
    incidents_run2 = get_all_incidents(db_path=temp_db)
    # Count of active incidents should remain 1, not duplicate
    assert len(incidents_run2) == 1


def test_fetch_incidents_dataframe(temp_db):
    """Test incident query filtering into Pandas DataFrame."""
    create_incident("Inc 1", "Brute Force", "1.1.1.1", "HIGH", 80, "Desc 1", status="New", db_path=temp_db)
    create_incident("Inc 2", "SQL Injection", "2.2.2.2", "CRITICAL", 95, "Desc 2", status="Resolved", db_path=temp_db)

    df_all = fetch_incidents_as_dataframe(db_path=temp_db)
    assert len(df_all) == 2

    df_new = fetch_incidents_as_dataframe(status="New", db_path=temp_db)
    assert len(df_new) == 1
    assert df_new.iloc[0]["category"] == "Brute Force"
