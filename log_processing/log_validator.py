"""Validation and normalization utilities for security log uploads."""

import ipaddress
import re
from pathlib import Path
from typing import Dict, List, Tuple
import pandas as pd

from config.settings import ALLOWED_EXTENSIONS, MAX_UPLOAD_SIZE_BYTES

# Common column aliases for flexible ingestion
COLUMN_ALIASES: Dict[str, List[str]] = {
    "timestamp": ["timestamp", "time", "date", "datetime", "event_time", "log_time", "@timestamp"],
    "source_ip": ["source_ip", "src_ip", "src", "client_ip", "ip_address", "ip", "source_address"],
    "destination_ip": ["destination_ip", "dest_ip", "dst_ip", "dst", "target_ip", "dest_address"],
    "username": ["username", "user", "account", "login_user", "usr", "user_id"],
    "event_type": ["event_type", "event", "action", "activity", "type", "category"],
    "status": ["status", "result", "state", "outcome", "disposition"],
    "port": ["port", "dst_port", "destination_port", "target_port", "dport"],
    "protocol": ["protocol", "proto", "transport"],
    "message": ["message", "msg", "details", "description", "log_message", "payload"],
}


def validate_file_metadata(filename: str, file_size: int) -> Tuple[bool, str]:
    """Validate uploaded file extension and size constraints safely."""
    if not filename:
        return False, "File has no name."

    # Prevent path traversal in uploaded filename
    safe_name = Path(filename).name
    ext = Path(safe_name).suffix.lower()

    if ext not in ALLOWED_EXTENSIONS:
        return (
            False,
            f"Unsupported file format '{ext}'. Allowed extensions are: {', '.join(ALLOWED_EXTENSIONS)}",
        )

    if file_size > MAX_UPLOAD_SIZE_BYTES:
        mb_size = file_size / (1024 * 1024)
        return (
            False,
            f"File exceeds maximum allowed size of 25MB (Uploaded: {mb_size:.2f}MB).",
        )

    return True, ""


def normalize_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize varying column names to canonical ThreatGuard schema."""
    df_copy = df.copy()
    current_cols = {col.lower().strip(): col for col in df_copy.columns}
    rename_mapping = {}

    for canonical_name, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in current_cols:
                rename_mapping[current_cols[alias]] = canonical_name
                break

    df_copy = df_copy.rename(columns=rename_mapping)
    return df_copy


def is_valid_ip(ip_str: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def validate_and_clean_logs(
    df: pd.DataFrame,
) -> Tuple[bool, List[str], pd.DataFrame]:
    """Inspect and sanitize log DataFrame.
    
    Returns:
        (is_valid, list_of_warning_or_error_messages, cleaned_dataframe)
    """
    messages: List[str] = []

    if df.empty:
        return False, ["Uploaded file contains no data rows."], df

    # Normalize columns
    df = normalize_column_names(df)

    # Required core fields
    critical_fields = ["timestamp", "source_ip", "event_type", "status"]
    missing_critical = [col for col in critical_fields if col not in df.columns]

    if missing_critical:
        return (
            False,
            [f"Missing mandatory security log fields: {', '.join(missing_critical)}."],
            df,
        )

    # Ensure optional fields exist
    optional_fields = ["destination_ip", "username", "port", "protocol", "message"]
    for field in optional_fields:
        if field not in df.columns:
            df[field] = ""
            messages.append(f"Optional field '{field}' was missing and populated with defaults.")

    # Clean data types
    df["timestamp"] = df["timestamp"].astype(str).str.strip()
    df["source_ip"] = df["source_ip"].astype(str).str.strip()
    df["destination_ip"] = df["destination_ip"].fillna("").astype(str).str.strip()
    df["username"] = df["username"].fillna("unknown").astype(str).str.strip()
    df["event_type"] = df["event_type"].astype(str).str.strip()
    df["status"] = df["status"].astype(str).str.strip().str.upper()
    df["protocol"] = df["protocol"].fillna("TCP").astype(str).str.strip().str.upper()
    df["message"] = df["message"].fillna("").astype(str)

    # Clean port: convert to numeric or NaN
    df["port"] = pd.to_numeric(df["port"], errors="coerce").fillna(0).astype(int)

    # Audit invalid IP entries
    invalid_ips = df[~df["source_ip"].apply(is_valid_ip)]
    if not invalid_ips.empty:
        messages.append(
            f"Notice: {len(invalid_ips)} records contain non-standard IP formats (e.g., hostnames or malformed IPs)."
        )

    # Standardize timestamp parse check
    invalid_timestamps = 0
    try:
        # Check a sample
        pd.to_datetime(df["timestamp"].head(10), errors="coerce")
    except Exception:
        invalid_timestamps += 1

    if invalid_timestamps > 0:
        messages.append("Some timestamps could not be automatically parsed into standard datetime format.")

    return True, messages, df
