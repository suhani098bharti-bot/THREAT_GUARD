"""Page 2: Security Log Ingestion, Validation, and Exploratory Analysis."""

import streamlit as st
import pandas as pd

from authentication.auth import enforce_authentication
from config.settings import SAMPLE_DATA_DIR
from database.db_operations import get_security_logs_dataframe, insert_security_logs
from detection.detection_engine import run_threat_detection
from log_processing.log_analyzer import filter_logs, get_log_summary_statistics
from log_processing.log_parser import parse_csv_logs, parse_uploaded_file
from utils.export_utils import export_dataframe_to_csv
from utils.helpers import render_page_header, render_sidebar_profile

enforce_authentication()
render_sidebar_profile()

render_page_header(
    title="Security Log Analysis",
    subtitle="Ingest, Validate, Filter, and Parse Telemetry from CSV and JSON Log Streams",
    badge_text="SIEM Ingestion",
)

# Tabs: File Ingestion vs Ingested Database Logs
tab_upload, tab_database = st.tabs(["📤 Upload & Parse New Logs", "🗄️ Ingested Database Logs"])

# ========================================================
# TAB 1: FILE INGESTION & PARSING
# ========================================================
with tab_upload:
    st.markdown("### 📥 Upload Security Log File")
    st.caption("Supported formats: Structured CSV or JSON (Standard Array or NDJSON). Max 25MB.")

    col_up, col_sample = st.columns([3, 1])
    with col_up:
        uploaded_file = st.file_uploader(
            "Choose a log file",
            type=["csv", "json"],
            help="Upload security event logs containing IP, event type, and timestamp telemetry.",
        )
    with col_sample:
        st.markdown("**Sample Telemetry**")
        if st.button("Load Built-in Sample CSV", use_container_width=True):
            sample_file = SAMPLE_DATA_DIR / "sample_security_logs.csv"
            if sample_file.exists():
                with open(sample_file, "rb") as f:
                    st.session_state["parsed_log_df"] = pd.read_csv(sample_file)
                    st.session_state["log_parse_msg"] = "Loaded built-in sample security logs."
                st.rerun()

    # Process uploaded file if provided
    if uploaded_file is not None:
        with st.spinner("Validating and parsing uploaded log stream..."):
            valid, msg, df = parse_uploaded_file(uploaded_file)
            if valid and not df.empty:
                st.session_state["parsed_log_df"] = df
                st.session_state["log_parse_msg"] = msg
                st.success(f"File validated successfully! {msg}")
            else:
                st.error(f"Validation Error: {msg}")

    # Display parsed log data if present in session state
    if "parsed_log_df" in st.session_state and not st.session_state["parsed_log_df"].empty:
        df_active = st.session_state["parsed_log_df"]
        st.markdown("---")
        st.markdown("### 📋 Log Validation & Data Preview")

        # Telemetry Summary Metrics
        stats = get_log_summary_statistics(df_active)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Records", f"{stats['total_records']:,}")
        m2.metric("Unique Source IPs", f"{stats['unique_source_ips']:,}")
        m3.metric("Unique Users", f"{stats['unique_users']:,}")
        m4.metric("Time Window", f"{stats['start_time'][:10]} - {stats['end_time'][:10]}")

        # Quick Actions
        act_col1, act_col2, act_col3 = st.columns([1, 1, 1])
        with act_col1:
            if st.button("💾 Ingest Logs into Database", type="primary", use_container_width=True):
                records = df_active.to_dict(orient="records")
                inserted = insert_security_logs(records)
                st.success(f"Successfully committed {inserted} logs into the SIEM database!")

        with act_col2:
            if st.button("⚡ Run Threat Detection on File", use_container_width=True):
                with st.spinner("Executing rule engine across uploaded logs..."):
                    detections = run_threat_detection(df_active, persist_to_db=True)
                    st.success(f"Detection engine generated {len(detections)} threat indicators and created incidents!")

        with act_col3:
            csv_bytes = export_dataframe_to_csv(df_active)
            st.download_button(
                "📥 Export Processed Logs (CSV)",
                data=csv_bytes,
                file_name="threatguard_processed_logs.csv",
                mime="text/csv",
                use_container_width=True,
            )

        # Filters for Active Preview
        st.markdown("#### 🔍 Filter & Search Active Logs")
        fl1, fl2, fl3, fl4 = st.columns(4)
        with fl1:
            all_ips = ["All"] + sorted([str(ip) for ip in df_active["source_ip"].dropna().unique()])
            sel_ip = st.selectbox("Source IP", all_ips)
        with fl2:
            all_events = ["All"] + sorted([str(e) for e in df_active["event_type"].dropna().unique()])
            sel_event = st.selectbox("Event Type", all_events)
        with fl3:
            all_status = ["All"] + sorted([str(s) for s in df_active["status"].dropna().unique()])
            sel_status = st.selectbox("Status", all_status)
        with fl4:
            search_txt = st.text_input("Search Message Content", "")

        filtered_df = filter_logs(
            df_active,
            source_ip=sel_ip if sel_ip != "All" else None,
            event_type=sel_event if sel_event != "All" else None,
            status=sel_status if sel_status != "All" else None,
            search_query=search_txt if search_txt.strip() else None,
        )

        st.caption(f"Displaying {len(filtered_df)} of {len(df_active)} records:")
        st.dataframe(filtered_df, use_container_width=True, hide_index=True)


# ========================================================
# TAB 2: INGESTED DATABASE LOGS
# ========================================================
with tab_database:
    st.markdown("### 🗄️ Ingested Security Database Telemetry")
    st.caption("Logs committed to the permanent SQLite database for SIEM correlation.")

    # Filter controls for database logs
    d_f1, d_f2, d_f3 = st.columns(3)
    with d_f1:
        db_ip = st.text_input("Filter by Source IP", "")
    with d_f2:
        db_type = st.text_input("Filter by Event Type", "")
    with d_f3:
        db_search = st.text_input("Search Payload / Message", "")

    db_logs_df = get_security_logs_dataframe(
        limit=5000,
        source_ip=db_ip.strip() if db_ip.strip() else None,
        event_type=db_type.strip() if db_type.strip() else None,
        search_query=db_search.strip() if db_search.strip() else None,
    )

    if db_logs_df.empty:
        st.info("No security logs stored in the database matching these criteria.")
    else:
        st.caption(f"Retrieved {len(db_logs_df)} record(s) from database.")
        st.dataframe(db_logs_df, use_container_width=True, hide_index=True)

        exp_csv = export_dataframe_to_csv(db_logs_df)
        st.download_button(
            "📥 Export Database Query to CSV",
            data=exp_csv,
            file_name="threatguard_db_logs_export.csv",
            mime="text/csv",
        )
