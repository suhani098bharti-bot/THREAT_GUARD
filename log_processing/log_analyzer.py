"""High-level analysis and summary routines for security log data."""

from typing import Any, Dict, List, Optional
import pandas as pd


def get_log_summary_statistics(df: pd.DataFrame) -> Dict[str, Any]:
    """Compute aggregate statistics for a log DataFrame."""
    if df.empty:
        return {
            "total_records": 0,
            "unique_source_ips": 0,
            "unique_dest_ips": 0,
            "unique_users": 0,
            "event_types": {},
            "statuses": {},
            "start_time": "N/A",
            "end_time": "N/A",
        }

    # Date range
    sorted_times = df["timestamp"].dropna().sort_values()
    start_time = str(sorted_times.iloc[0]) if not sorted_times.empty else "N/A"
    end_time = str(sorted_times.iloc[-1]) if not sorted_times.empty else "N/A"

    return {
        "total_records": len(df),
        "unique_source_ips": df["source_ip"].nunique() if "source_ip" in df.columns else 0,
        "unique_dest_ips": df["destination_ip"].nunique() if "destination_ip" in df.columns else 0,
        "unique_users": df["username"].nunique() if "username" in df.columns else 0,
        "event_types": df["event_type"].value_counts().to_dict() if "event_type" in df.columns else {},
        "statuses": df["status"].value_counts().to_dict() if "status" in df.columns else {},
        "start_time": start_time,
        "end_time": end_time,
    }


def filter_logs(
    df: pd.DataFrame,
    source_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    status: Optional[str] = None,
    search_query: Optional[str] = None,
) -> pd.DataFrame:
    """Apply client-side filters to a security log DataFrame."""
    filtered = df.copy()

    if source_ip and source_ip != "All":
        filtered = filtered[filtered["source_ip"] == source_ip]

    if event_type and event_type != "All":
        filtered = filtered[filtered["event_type"] == event_type]

    if status and status != "All":
        filtered = filtered[filtered["status"].str.upper() == status.upper()]

    if search_query:
        query = search_query.lower()
        mask = (
            filtered["message"].astype(str).str.lower().str.contains(query, na=False)
            | filtered["source_ip"].astype(str).str.lower().str.contains(query, na=False)
            | filtered["username"].astype(str).str.lower().str.contains(query, na=False)
            | filtered["event_type"].astype(str).str.lower().str.contains(query, na=False)
        )
        filtered = filtered[mask]

    return filtered
