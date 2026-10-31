"""Application settings and global configuration for ThreatGuard."""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
ASSETS_DIR = BASE_DIR / "assets"
SAMPLE_DATA_DIR = BASE_DIR / "sample_data"
DOCS_DIR = BASE_DIR / "docs"

# Application Metadata
APP_NAME = "ThreatGuard"
APP_SUBTITLE = "Cyber Incident Detection & Response System"
APP_VERSION = "1.0.0"
ACADEMIC_DISCLAIMER = (
    "ThreatGuard is an educational defensive cybersecurity monitoring and incident response "
    "simulation platform designed for Computer Science Engineering demonstration. It is not an enterprise SIEM."
)

# Helper to read from Streamlit Secrets or Environment Variables
def get_config_value(key: str, default: str = "") -> str:
    """Retrieve configuration value from Streamlit Secrets or Environment Variables."""
    try:
        import streamlit as st
        # Try top-level or sections
        if hasattr(st, "secrets"):
            if key in st.secrets:
                return str(st.secrets[key])
            for section in ["general", "security", "database", "detection"]:
                if section in st.secrets and key in st.secrets[section]:
                    return str(st.secrets[section][key])
    except Exception:
        pass
    return os.environ.get(key.upper(), os.environ.get(key, default))

# Database Configuration
# Default database stored locally in workspace or temporary folder
DEFAULT_DB_PATH = BASE_DIR / "threatguard.db"
DATABASE_PATH = Path(get_config_value("DATABASE_PATH", str(DEFAULT_DB_PATH)))

# Initial Admin Credentials (used during auto-initialization)
INITIAL_ADMIN_USERNAME = get_config_value("INITIAL_ADMIN_USERNAME", "admin")
INITIAL_ADMIN_PASSWORD = get_config_value("INITIAL_ADMIN_PASSWORD", "Admin@ThreatGuard2026!")
INITIAL_ADMIN_ROLE = "Admin"

# Security and Upload Boundaries
ALLOWED_EXTENSIONS = {".csv", ".json"}
MAX_UPLOAD_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB max
ALLOWED_COLUMNS = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "username",
    "event_type",
    "status",
    "port",
    "protocol",
    "message",
]

# Detection Rule Thresholds (Configurable)
DEFAULT_DETECTION_THRESHOLDS = {
    "brute_force_failed_attempts": int(get_config_value("BRUTE_FORCE_THRESHOLD", "5")),
    "brute_force_window_minutes": int(get_config_value("BRUTE_FORCE_WINDOW_MINUTES", "10")),
    "port_scan_port_count": int(get_config_value("PORT_SCAN_PORT_THRESHOLD", "5")),
    "port_scan_window_minutes": int(get_config_value("PORT_SCAN_WINDOW_MINUTES", "10")),
    "suspicious_ip_threshold": int(get_config_value("SUSPICIOUS_IP_THRESHOLD", "8")),
    "suspicious_ip_window_minutes": int(get_config_value("SUSPICIOUS_IP_WINDOW_MINUTES", "30")),
    "unusual_volume_threshold": int(get_config_value("UNUSUAL_VOLUME_THRESHOLD", "25")),
}

# Severity Levels
SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

SEVERITY_COLORS = {
    "CRITICAL": "#FF4B4B",  # Vibrant Red
    "HIGH": "#FFA500",      # Bright Amber / Orange
    "MEDIUM": "#F4D03F",    # Yellow
    "LOW": "#00D2FF",       # Neon Cyan
    "INFO": "#A0AEC0",      # Gray
}

# Incident Statuses
INCIDENT_STATUSES = [
    "New",
    "Investigating",
    "Contained",
    "Resolved",
    "False Positive",
]

# User Roles
USER_ROLES = ["Admin", "Analyst"]
