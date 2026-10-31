"""Analytics aggregation routines for ThreatGuard dashboard."""

from pathlib import Path
from typing import Any, Dict, Optional, Union
import pandas as pd

from database.db_operations import (
    get_attack_category_distribution,
    get_dashboard_kpis,
    get_event_type_distribution_data,
    get_incident_status_data,
    get_severity_distribution_data,
    get_threats_over_time_data,
    get_top_suspicious_ips_data,
)


def get_full_analytics_bundle(
    db_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Retrieve all dashboard charts and metrics data in a single bundle."""
    return {
        "kpis": get_dashboard_kpis(db_path=db_path),
        "threats_over_time": get_threats_over_time_data(db_path=db_path),
        "severity_dist": get_severity_distribution_data(db_path=db_path),
        "category_dist": get_attack_category_distribution(db_path=db_path),
        "status_dist": get_incident_status_data(db_path=db_path),
        "event_dist": get_event_type_distribution_data(db_path=db_path),
        "top_ips": get_top_suspicious_ips_data(limit=5, db_path=db_path),
    }
