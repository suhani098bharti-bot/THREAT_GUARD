"""Database CRUD operations and analytical queries for ThreatGuard."""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import pandas as pd

from database.db_connection import get_db_connection


# ==========================================
# USER OPERATIONS
# ==========================================

def get_user_by_username(
    username: str, db_path: Optional[Union[str, Path]] = None
) -> Optional[Dict[str, Any]]:
    """Retrieve user record by username."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_user_by_id(
    user_id: int, db_path: Optional[Union[str, Path]] = None
) -> Optional[Dict[str, Any]]:
    """Retrieve user record by user ID."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def create_user(
    username: str,
    password_hash: str,
    role: str = "Analyst",
    db_path: Optional[Union[str, Path]] = None,
) -> int:
    """Create a new user record in the database."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role),
        )
        return cursor.lastrowid  # type: ignore


def get_all_users(db_path: Optional[Union[str, Path]] = None) -> List[Dict[str, Any]]:
    """Retrieve all users without revealing password hashes."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, role, created_at FROM users ORDER BY created_at DESC"
        )
        return [dict(row) for row in cursor.fetchall()]


def update_user_role(
    user_id: int, role: str, db_path: Optional[Union[str, Path]] = None
) -> bool:
    """Update user role (Admin/Analyst)."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        return cursor.rowcount > 0


def delete_user(
    user_id: int, db_path: Optional[Union[str, Path]] = None
) -> bool:
    """Delete a user account."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return cursor.rowcount > 0


# ==========================================
# SECURITY LOG OPERATIONS
# ==========================================

def insert_security_logs(
    logs: List[Dict[str, Any]], db_path: Optional[Union[str, Path]] = None
) -> int:
    """Insert a batch of security log records."""
    if not logs:
        return 0
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        records = [
            (
                str(log.get("timestamp", "")),
                str(log.get("source_ip", "")),
                str(log.get("destination_ip", "") or ""),
                str(log.get("username", "") or ""),
                str(log.get("event_type", "")),
                str(log.get("status", "")),
                int(log["port"]) if log.get("port") is not None and str(log["port"]).isdigit() else None,
                str(log.get("protocol", "") or ""),
                str(log.get("message", "") or ""),
            )
            for log in logs
        ]
        cursor.executemany(
            """
            INSERT INTO security_logs (
                timestamp, source_ip, destination_ip, username,
                event_type, status, port, protocol, message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            records,
        )
        return cursor.rowcount


def get_security_logs_dataframe(
    limit: int = 10000,
    offset: int = 0,
    source_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    status: Optional[str] = None,
    search_query: Optional[str] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> pd.DataFrame:
    """Fetch filtered security logs as a Pandas DataFrame."""
    with get_db_connection(db_path) as conn:
        query = "SELECT * FROM security_logs WHERE 1=1"
        params: List[Any] = []

        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if status:
            query += " AND status = ?"
            params.append(status)
        if search_query:
            query += " AND (message LIKE ? OR username LIKE ? OR destination_ip LIKE ?)"
            like_term = f"%{search_query}%"
            params.extend([like_term, like_term, like_term])

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        return pd.read_sql_query(query, conn, params=params)


def get_total_logs_count(db_path: Optional[Union[str, Path]] = None) -> int:
    """Return total number of ingested security logs."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM security_logs")
        row = cursor.fetchone()
        return row[0] if row else 0


def clear_security_logs(db_path: Optional[Union[str, Path]] = None) -> None:
    """Purge security logs from database."""
    with get_db_connection(db_path) as conn:
        conn.execute("DELETE FROM security_logs")


# ==========================================
# INCIDENT OPERATIONS
# ==========================================

def find_active_incident_by_source_and_category(
    source_ip: str,
    category: str,
    db_path: Optional[Union[str, Path]] = None,
) -> Optional[Dict[str, Any]]:
    """Check if an active (non-resolved, non-false positive) incident exists for source IP and category."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM incidents
            WHERE source_ip = ? AND category = ? AND status IN ('New', 'Investigating', 'Contained')
            ORDER BY id DESC LIMIT 1
            """,
            (source_ip, category),
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def create_incident(
    title: str,
    category: str,
    source_ip: str,
    severity: str,
    risk_score: int,
    description: str,
    status: str = "New",
    assigned_to: Optional[str] = None,
    resolution_notes: Optional[str] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> int:
    """Create an incident record in the database."""
    now_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO incidents (
                title, category, source_ip, severity, risk_score,
                description, status, assigned_to, created_at, updated_at, resolution_notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                category,
                source_ip,
                severity,
                risk_score,
                description,
                status,
                assigned_to,
                now_iso,
                now_iso,
                resolution_notes,
            ),
        )
        return cursor.lastrowid  # type: ignore


def update_incident_status(
    incident_id: int,
    status: str,
    resolution_notes: Optional[str] = None,
    assigned_to: Optional[str] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> bool:
    """Update incident status, assignment, and resolution notes."""
    now_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        updates = ["status = ?", "updated_at = ?"]
        params: List[Any] = [status, now_iso]

        if resolution_notes is not None:
            updates.append("resolution_notes = ?")
            params.append(resolution_notes)
        if assigned_to is not None:
            updates.append("assigned_to = ?")
            params.append(assigned_to)

        params.append(incident_id)
        sql = f"UPDATE incidents SET {', '.join(updates)} WHERE id = ?"
        cursor.execute(sql, params)
        return cursor.rowcount > 0


def get_incident_by_id(
    incident_id: int, db_path: Optional[Union[str, Path]] = None
) -> Optional[Dict[str, Any]]:
    """Retrieve full incident details by ID."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_all_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    search_query: Optional[str] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> List[Dict[str, Any]]:
    """Retrieve all incidents with optional filtering."""
    with get_db_connection(db_path) as conn:
        query = "SELECT * FROM incidents WHERE 1=1"
        params: List[Any] = []

        if status and status != "All":
            query += " AND status = ?"
            params.append(status)
        if severity and severity != "All":
            query += " AND severity = ?"
            params.append(severity)
        if category and category != "All":
            query += " AND category = ?"
            params.append(category)
        if search_query:
            query += " AND (title LIKE ? OR description LIKE ? OR source_ip LIKE ?)"
            like_term = f"%{search_query}%"
            params.extend([like_term, like_term, like_term])

        query += " ORDER BY id DESC"
        cursor = conn.cursor()
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]


# ==========================================
# DETECTION EVENTS OPERATIONS
# ==========================================

def insert_detection_event(
    rule_id: str,
    incident_id: Optional[int],
    source_ip: str,
    severity: str,
    risk_score: int,
    explanation: str,
    db_path: Optional[Union[str, Path]] = None,
) -> int:
    """Record a detection engine match event."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO detection_events (
                rule_id, incident_id, source_ip, severity, risk_score, explanation
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (rule_id, incident_id, source_ip, severity, risk_score, explanation),
        )
        return cursor.lastrowid  # type: ignore


def get_detection_events_for_incident(
    incident_id: int, db_path: Optional[Union[str, Path]] = None
) -> List[Dict[str, Any]]:
    """Retrieve all detection events associated with a specific incident."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM detection_events WHERE incident_id = ? ORDER BY id DESC",
            (incident_id,),
        )
        return [dict(row) for row in cursor.fetchall()]


def get_all_detection_events(
    limit: int = 500, db_path: Optional[Union[str, Path]] = None
) -> List[Dict[str, Any]]:
    """Retrieve recent detection events."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM detection_events ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]


# ==========================================
# INCIDENT NOTES OPERATIONS
# ==========================================

def add_incident_note(
    incident_id: int,
    user_id: Optional[int],
    username: str,
    note: str,
    db_path: Optional[Union[str, Path]] = None,
) -> int:
    """Add an investigation or resolution note to an incident."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO incident_notes (incident_id, user_id, username, note)
            VALUES (?, ?, ?, ?)
            """,
            (incident_id, user_id, username, note),
        )
        return cursor.lastrowid  # type: ignore


def get_notes_for_incident(
    incident_id: int, db_path: Optional[Union[str, Path]] = None
) -> List[Dict[str, Any]]:
    """Retrieve chronological audit notes for an incident."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM incident_notes
            WHERE incident_id = ?
            ORDER BY created_at ASC
            """,
            (incident_id,),
        )
        return [dict(row) for row in cursor.fetchall()]


# ==========================================
# ANALYTICS & DASHBOARD METRIC QUERIES
# ==========================================

def get_dashboard_kpis(db_path: Optional[Union[str, Path]] = None) -> Dict[str, int]:
    """Calculate core KPI counts for the executive SOC overview."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        
        # Total security event logs
        cursor.execute("SELECT COUNT(*) FROM security_logs")
        total_logs = cursor.fetchone()[0]
        
        # Total threats detected
        cursor.execute("SELECT COUNT(*) FROM detection_events")
        total_threats = cursor.fetchone()[0]
        
        # Incidents by severity and status
        cursor.execute(
            """
            SELECT
                SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_cnt,
                SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high_cnt,
                SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END) AS resolved_cnt,
                SUM(CASE WHEN status IN ('New', 'Investigating', 'Contained') THEN 1 ELSE 0 END) AS pending_cnt
            FROM incidents
            """
        )
        row = cursor.fetchone()
        
        return {
            "total_security_events": total_logs or 0,
            "total_threats_detected": total_threats or 0,
            "critical_incidents": row[0] or 0 if row else 0,
            "high_risk_incidents": row[1] or 0 if row else 0,
            "resolved_incidents": row[2] or 0 if row else 0,
            "pending_incidents": row[3] or 0 if row else 0,
        }


def get_threats_over_time_data(db_path: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """Group detection events by date for timeline visualization."""
    with get_db_connection(db_path) as conn:
        query = """
            SELECT substr(detected_at, 1, 10) AS detection_date,
                   severity,
                   COUNT(*) AS count
            FROM detection_events
            GROUP BY detection_date, severity
            ORDER BY detection_date ASC
        """
        return pd.read_sql_query(query, conn)


def get_severity_distribution_data(db_path: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """Count incidents across severity tiers."""
    with get_db_connection(db_path) as conn:
        query = """
            SELECT severity, COUNT(*) AS count
            FROM incidents
            GROUP BY severity
            ORDER BY count DESC
        """
        return pd.read_sql_query(query, conn)


def get_category_distribution_data(db_path: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """Count incidents by cyber threat category."""
    with get_db_connection(db_path) as conn:
        query = """
            SELECT category, COUNT(*) AS count
            FROM incidents
            GROUP BY category
            ORDER BY count DESC
        """
        return pd.read_sql_query(query, conn)


def get_incident_status_data(db_path: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """Count incidents by current workflow status."""
    with get_db_connection(db_path) as conn:
        query = """
            SELECT status, COUNT(*) AS count
            FROM incidents
            GROUP BY status
            ORDER BY count DESC
        """
        return pd.read_sql_query(query, conn)


def get_top_suspicious_ips_data(
    limit: int = 5, db_path: Optional[Union[str, Path]] = None
) -> pd.DataFrame:
    """Aggregate highest risk source IP addresses."""
    with get_db_connection(db_path) as conn:
        query = """
            SELECT source_ip,
                   COUNT(*) AS threat_count,
                   MAX(risk_score) AS max_risk_score,
                   GROUP_CONCAT(DISTINCT rule_id) AS matched_rules
            FROM detection_events
            WHERE source_ip IS NOT NULL AND source_ip != ''
            GROUP BY source_ip
            ORDER BY threat_count DESC, max_risk_score DESC
            LIMIT ?
        """
        return pd.read_sql_query(query, conn, params=[limit])


def get_event_type_distribution_data(db_path: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """Distribution of raw security events by event type."""
    with get_db_connection(db_path) as conn:
        query = """
            SELECT event_type, COUNT(*) AS count
            FROM security_logs
            GROUP BY event_type
            ORDER BY count DESC
        """
        return pd.read_sql_query(query, conn)
