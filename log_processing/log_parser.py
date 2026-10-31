"""Parsers for ingesting CSV and JSON security event logs."""

import io
import json
from pathlib import Path
from typing import Any, Tuple, Union
import pandas as pd

from log_processing.log_validator import validate_and_clean_logs, validate_file_metadata


def parse_csv_logs(
    file_source: Any, filename: str = "upload.csv"
) -> Tuple[bool, str, pd.DataFrame]:
    """Parse CSV logs with automatic delimiter detection and schema cleaning."""
    try:
        content = ""
        if isinstance(file_source, (str, Path)):
            with open(file_source, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        elif hasattr(file_source, "read"):
            # Streamlit UploadedFile or StringIO or BytesIO
            raw = file_source.read()
            if isinstance(raw, bytes):
                content = raw.decode("utf-8", errors="replace")
            else:
                content = raw
            if hasattr(file_source, "seek"):
                file_source.seek(0)
        else:
            return False, "Unsupported file source type.", pd.DataFrame()

        if not content.strip():
            return False, "CSV file is empty.", pd.DataFrame()

        df = pd.read_csv(io.StringIO(content), sep=None, engine="python")

        if df.empty:
            return False, "CSV file is empty.", pd.DataFrame()

        is_valid, validation_msgs, cleaned_df = validate_and_clean_logs(df)
        msg_str = " | ".join(validation_msgs) if validation_msgs else "CSV parsed successfully."
        return is_valid, msg_str, cleaned_df

    except Exception as e:
        return False, f"Failed to parse CSV log file: {str(e)}", pd.DataFrame()



def parse_json_logs(
    file_source: Any, filename: str = "upload.json"
) -> Tuple[bool, str, pd.DataFrame]:
    """Parse JSON or NDJSON (JSON Lines) formatted logs."""
    try:
        raw_text = ""
        if isinstance(file_source, (str, Path)):
            with open(file_source, "r", encoding="utf-8", errors="replace") as f:
                raw_text = f.read()
        elif hasattr(file_source, "read"):
            raw_data = file_source.read()
            if isinstance(raw_data, bytes):
                raw_text = raw_data.decode("utf-8", errors="replace")
            else:
                raw_text = raw_data
            if hasattr(file_source, "seek"):
                file_source.seek(0)
        else:
            return False, "Unsupported file source type.", pd.DataFrame()

        raw_text = raw_text.strip()
        if not raw_text:
            return False, "JSON file is empty.", pd.DataFrame()

        # Try standard JSON list of objects
        records = None
        try:
            parsed = json.loads(raw_text)
            if isinstance(parsed, list):
                records = parsed
            elif isinstance(parsed, dict):
                # Check if wrapped in key like 'logs' or 'events'
                for key in ["logs", "events", "records", "data"]:
                    if key in parsed and isinstance(parsed[key], list):
                        records = parsed[key]
                        break
                if records is None:
                    records = [parsed]
        except json.JSONDecodeError:
            # Try line-delimited JSON (NDJSON)
            lines = raw_text.splitlines()
            records = []
            for line in lines:
                line = line.strip()
                if line:
                    records.append(json.loads(line))

        if not records:
            return False, "No valid log records found in JSON structure.", pd.DataFrame()

        df = pd.DataFrame(records)
        is_valid, validation_msgs, cleaned_df = validate_and_clean_logs(df)
        msg_str = " | ".join(validation_msgs) if validation_msgs else "JSON parsed successfully."
        return is_valid, msg_str, cleaned_df

    except Exception as e:
        return False, f"Failed to parse JSON log file: {str(e)}", pd.DataFrame()


def parse_uploaded_file(uploaded_file: Any) -> Tuple[bool, str, pd.DataFrame]:
    """Router to parse an uploaded file from Streamlit file_uploader safely."""
    if uploaded_file is None:
        return False, "No file provided.", pd.DataFrame()

    file_name = getattr(uploaded_file, "name", "unknown")
    file_size = getattr(uploaded_file, "size", 0)

    # Security check on file size and extension
    valid_meta, meta_err = validate_file_metadata(file_name, file_size)
    if not valid_meta:
        return False, meta_err, pd.DataFrame()

    suffix = Path(file_name).suffix.lower()
    if suffix == ".csv":
        return parse_csv_logs(uploaded_file, filename=file_name)
    elif suffix == ".json":
        return parse_json_logs(uploaded_file, filename=file_name)
    else:
        return False, f"Unsupported file extension: {suffix}", pd.DataFrame()
