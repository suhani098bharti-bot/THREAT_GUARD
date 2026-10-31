"""Unit and integration tests for log parsing and validation."""

import io
import json
import pytest
import pandas as pd

from log_processing.log_analyzer import filter_logs, get_log_summary_statistics
from log_processing.log_parser import parse_csv_logs, parse_json_logs
from log_processing.log_validator import (
    is_valid_ip,
    normalize_column_names,
    validate_and_clean_logs,
    validate_file_metadata,
)


def test_validate_file_metadata():
    """Test uploaded file format and size constraints."""
    # Valid files
    ok, _ = validate_file_metadata("security.csv", 1024)
    assert ok is True

    ok, _ = validate_file_metadata("events.json", 2048)
    assert ok is True

    # Invalid extension
    ok, msg = validate_file_metadata("malware.exe", 1024)
    assert ok is False
    assert "Unsupported file format" in msg

    # File exceeding 25MB
    huge_size = 30 * 1024 * 1024
    ok, msg = validate_file_metadata("huge.csv", huge_size)
    assert ok is False
    assert "exceeds maximum allowed size" in msg


def test_ip_validation():
    """Test IP address validation for IPv4 and IPv6."""
    assert is_valid_ip("192.168.1.1") is True
    assert is_valid_ip("10.0.0.5") is True
    assert is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True
    assert is_valid_ip("invalid_ip_string") is False
    assert is_valid_ip("999.999.999.999") is False
    assert is_valid_ip("") is False


def test_column_name_normalization():
    """Test varying field aliases map to canonical ThreatGuard schema."""
    df_raw = pd.DataFrame(
        {
            "src_ip": ["192.168.1.10"],
            "dst_ip": ["10.0.0.1"],
            "user": ["alice"],
            "action": ["login"],
            "outcome": ["SUCCESS"],
            "dport": [443],
            "proto": ["TCP"],
            "msg": ["User logged in successfully"],
            "time": ["2026-10-31 10:00:00"],
        }
    )

    normalized = normalize_column_names(df_raw)
    assert "source_ip" in normalized.columns
    assert "destination_ip" in normalized.columns
    assert "username" in normalized.columns
    assert "event_type" in normalized.columns
    assert "status" in normalized.columns
    assert "port" in normalized.columns
    assert "protocol" in normalized.columns
    assert "message" in normalized.columns
    assert "timestamp" in normalized.columns


def test_parse_csv_logs():
    """Test parsing standard CSV data."""
    csv_data = """timestamp,source_ip,destination_ip,username,event_type,status,port,protocol,message
2026-10-31 12:00:00,192.168.1.1,10.0.0.1,admin,login,SUCCESS,443,TCP,Logged in
2026-10-31 12:00:05,192.168.1.2,10.0.0.1,guest,login,FAILED,443,TCP,Bad password
"""
    file_obj = io.StringIO(csv_data)
    valid, msg, df = parse_csv_logs(file_obj)

    assert valid is True
    assert len(df) == 2
    assert "source_ip" in df.columns
    assert df["status"].iloc[1] == "FAILED"


def test_parse_json_logs_array():
    """Test parsing standard JSON array of objects."""
    json_data = json.dumps(
        [
            {
                "timestamp": "2026-10-31 12:00:00",
                "source_ip": "192.168.1.5",
                "event_type": "web_access",
                "status": "SUCCESS",
                "port": 80,
                "message": "GET /index.html",
            },
            {
                "timestamp": "2026-10-31 12:00:02",
                "source_ip": "192.168.1.5",
                "event_type": "web_access",
                "status": "SUCCESS",
                "port": 80,
                "message": "GET /style.css",
            },
        ]
    )
    file_obj = io.StringIO(json_data)
    valid, msg, df = parse_json_logs(file_obj)

    assert valid is True
    assert len(df) == 2
    assert df["source_ip"].iloc[0] == "192.168.1.5"


def test_parse_empty_and_corrupt_logs():
    """Test graceful handling of corrupt or empty input data."""
    # Empty CSV
    valid, msg, _ = parse_csv_logs(io.StringIO(""))
    assert valid is False
    assert "empty" in msg.lower()

    # Empty JSON
    valid, msg, _ = parse_json_logs(io.StringIO(""))
    assert valid is False
    assert "empty" in msg.lower()

    # Malformed JSON
    valid, msg, _ = parse_json_logs(io.StringIO("{corrupted-json"))
    assert valid is False
    assert "failed" in msg.lower()


def test_log_filtering():
    """Test client-side filtering logic."""
    df = pd.DataFrame(
        {
            "timestamp": ["2026-10-31 10:00:00", "2026-10-31 10:01:00"],
            "source_ip": ["192.168.1.10", "198.51.100.5"],
            "destination_ip": ["10.0.0.1", "10.0.0.1"],
            "username": ["alice", "bob"],
            "event_type": ["login", "login"],
            "status": ["SUCCESS", "FAILED"],
            "port": [443, 443],
            "protocol": ["TCP", "TCP"],
            "message": ["Session created", "Password incorrect"],
        }
    )

    filtered = filter_logs(df, source_ip="198.51.100.5")
    assert len(filtered) == 1
    assert filtered.iloc[0]["username"] == "bob"

    filtered_status = filter_logs(df, status="SUCCESS")
    assert len(filtered_status) == 1
    assert filtered_status.iloc[0]["username"] == "alice"
