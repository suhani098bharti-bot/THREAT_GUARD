"""Historical incident audit trail and metric calculation."""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import pandas as pd

from database.db_operations import get_all_incidents


def get_incident_resolution_metrics(
    db_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Calculate historical incident resolution metrics and mean time estimates."""
    incidents = get_all_incidents(db_path=db_path)
    if not incidents:
        return {
            "total_incidents": 0,
            "resolved_count": 0,
            "false_positive_count": 0,
            "active_count": 0,
            "resolution_rate_percent": 0.0,
        }

    total = len(incidents)
    resolved = sum(1 for inc in incidents if inc["status"] == "Resolved")
    false_pos = sum(1 for inc in incidents if inc["status"] == "False Positive")
    active = sum(
        1
        for inc in incidents
        if inc["status"] in ["New", "Investigating", "Contained"]
    )

    resolution_rate = round(((resolved + false_pos) / total) * 100, 1) if total > 0 else 0.0

    return {
        "total_incidents": total,
        "resolved_count": resolved,
        "false_positive_count": false_pos,
        "active_count": active,
        "resolution_rate_percent": resolution_rate,
    }


def get_historical_audit_log(
    limit: int = 50, db_path: Optional[Union[str, Path]] = None
) -> pd.DataFrame:
    """Retrieve chronologically ordered list of recent incident audit notes."""
    from database.db_connection import get_db_connection

    with get_db_connection(db_path) as conn:
        query = """
            SELECT n.id, n.incident_id, i.title, n.username, n.note, n.created_at
            FROM incident_notes n
            LEFT JOIN incidents i ON n.incident_id = i.id
            ORDER BY n.id DESC
            LIMIT ?
        """
        return pd.read_sql_query(query, conn, params=[limit])
