"""SOC Overview component rendering KPI metrics, charts, and incident summaries."""

from pathlib import Path
from typing import Optional, Union
import streamlit as st
import pandas as pd

from dashboard.analytics import get_full_analytics_bundle
from dashboard.charts import (
    create_attack_category_chart,
    create_event_activity_chart,
    create_incident_status_chart,
    create_severity_pie_chart,
    create_threats_timeline_chart,
    create_top_ips_chart,
)
from database.db_operations import get_all_incidents
from detection.threat_classifier import get_severity_badge_html
from utils.helpers import load_demo_security_data, render_kpi_card_html, render_page_header


def render_dashboard_view(db_path: Optional[Union[str, Path]] = None) -> None:
    """Render the primary SIEM Monitoring Operations Center dashboard."""
    render_page_header(
        title="Security Operations Center (SOC)",
        subtitle="Real-time Defensive Threat Monitoring & Incident Response Telemetry",
        badge_text="SIEM Simulation",
    )

    bundle = get_full_analytics_bundle(db_path=db_path)
    kpis = bundle["kpis"]

    # Empty State Handling
    if kpis["total_security_events"] == 0 and kpis["total_threats_detected"] == 0:
        st.info("ℹ️ **Database Empty**: No security telemetry or incident logs are currently ingested.")
        col_btn, _ = st.columns([1, 3])
        with col_btn:
            if st.button("🚀 Load Demo Security Data", type="primary", use_container_width=True):
                success, msg = load_demo_security_data(db_path=str(db_path) if db_path else None)
                if success:
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)
        return

    # Top Control Bar (Demo Reload or Data Quick Action)
    col_l, col_r = st.columns([3, 1])
    with col_l:
        st.caption("Displaying real-time SIEM analytics aggregated from ingested system logs.")
    with col_r:
        if st.button("🔄 Refresh Telemetry", use_container_width=True):
            st.rerun()

    # 1. KPI Metric Cards
    kpi_html = f"""
    <div class="kpi-container">
        {render_kpi_card_html("Security Events", kpis["total_security_events"], "Total ingested records", "default")}
        {render_kpi_card_html("Threats Detected", kpis["total_threats_detected"], "Matched rule events", "pending")}
        {render_kpi_card_html("Critical Incidents", kpis["critical_incidents"], "High severity triage", "critical")}
        {render_kpi_card_html("High-Risk Incidents", kpis["high_risk_incidents"], "Severe indicators", "high")}
        {render_kpi_card_html("Resolved Incidents", kpis["resolved_incidents"], "Successfully mitigated", "success")}
        {render_kpi_card_html("Pending Triage", kpis["pending_incidents"], "Action required", "pending")}
    </div>
    """
    st.markdown(kpi_html, unsafe_allow_html=True)

    # 2. SOC Interactive Visualization Charts
    st.markdown("### 📊 Security Analytics & Telemetry Breakdown")

    row1_c1, row1_c2 = st.columns(2)
    with row1_c1:
        st.plotly_chart(
            create_threats_timeline_chart(bundle["threats_over_time"]),
            use_container_width=True,
        )
    with row1_c2:
        st.plotly_chart(
            create_severity_pie_chart(bundle["severity_dist"]),
            use_container_width=True,
        )

    row2_c1, row2_c2 = st.columns(2)
    with row2_c1:
        st.plotly_chart(
            create_attack_category_chart(bundle["category_dist"]),
            use_container_width=True,
        )
    with row2_c2:
        st.plotly_chart(
            create_incident_status_chart(bundle["status_dist"]),
            use_container_width=True,
        )

    row3_c1, row3_c2 = st.columns(2)
    with row3_c1:
        st.plotly_chart(
            create_event_activity_chart(bundle["event_dist"]),
            use_container_width=True,
        )
    with row3_c2:
        st.plotly_chart(
            create_top_ips_chart(bundle["top_ips"]),
            use_container_width=True,
        )

    # 3. Recent Security Incidents Table with Filters
    st.markdown("### 🚨 Recent Security Incidents")

    # Filter controls
    f_col1, f_col2, f_col3, f_col4 = st.columns(4)
    with f_col1:
        status_filter = st.selectbox(
            "Filter Status",
            ["All", "New", "Investigating", "Contained", "Resolved", "False Positive"],
            key="dash_status_filter",
        )
    with f_col2:
        severity_filter = st.selectbox(
            "Filter Severity",
            ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            key="dash_sev_filter",
        )
    with f_col3:
        category_filter = st.selectbox(
            "Filter Attack Category",
            [
                "All",
                "Brute Force",
                "Port Scanning",
                "SQL Injection",
                "Cross-Site Scripting (XSS)",
                "Suspicious IP Activity",
                "Unauthorized Access",
                "Unusual Network Activity",
            ],
            key="dash_cat_filter",
        )
    with f_col4:
        search_query = st.text_input("Search Incidents (IP / Title)", "", key="dash_search")

    incidents = get_all_incidents(
        status=status_filter if status_filter != "All" else None,
        severity=severity_filter if severity_filter != "All" else None,
        category=category_filter if category_filter != "All" else None,
        search_query=search_query if search_query.strip() else None,
        db_path=db_path,
    )

    if not incidents:
        st.info("No security incidents match the selected filter criteria.")
    else:
        df_display = pd.DataFrame(incidents)
        # Select and format columns for clean display
        show_cols = ["id", "title", "category", "source_ip", "severity", "risk_score", "status", "assigned_to", "created_at"]
        clean_df = df_display[[c for c in show_cols if c in df_display.columns]].rename(
            columns={
                "id": "Incident ID",
                "title": "Incident Title",
                "category": "Attack Category",
                "source_ip": "Source IP",
                "severity": "Severity",
                "risk_score": "Risk Score",
                "status": "Status",
                "assigned_to": "Analyst",
                "created_at": "Timestamp",
            }
        )

        st.dataframe(
            clean_df,
            use_container_width=True,
            hide_index=True,
        )

        st.caption(f"Showing {len(clean_df)} incident record(s). Open **Incident Management** page to investigate.")
