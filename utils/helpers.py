"""Streamlit UI helpers, CSS loaders, and shared component renderers."""

from pathlib import Path
from typing import Optional, Tuple
import streamlit as st
import pandas as pd

from authentication.auth import get_current_role, get_current_user, is_authenticated, logout
from config.settings import ASSETS_DIR, SAMPLE_DATA_DIR


def load_custom_css() -> None:
    """Inject custom CSS rules from assets/styles.css into the active Streamlit app."""
    css_path = ASSETS_DIR / "styles.css"
    if css_path.exists():
        with open(css_path, "r", encoding="utf-8") as f:
            css_content = f.read()
        st.markdown(f"<style>{css_content}</style>", unsafe_allow_html=True)


def render_page_header(title: str, subtitle: str, badge_text: str = "SOC Operations") -> None:
    """Render unified cyber SOC banner header."""
    load_custom_css()
    html = f"""
    <div class="threatguard-header">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 10px;">
            <div>
                <div class="threatguard-title">🛡️ {title}</div>
                <div class="threatguard-subtitle">{subtitle}</div>
            </div>
            <div class="academic-badge">{badge_text}</div>
        </div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)


def render_sidebar_profile() -> None:
    """Render authenticated user badge, role indicator, and logout button in the sidebar."""
    with st.sidebar:
        st.markdown("---")
        if is_authenticated():
            user = get_current_user()
            username = user.get("username", "Analyst") if user else "Analyst"
            role = get_current_role() or "Analyst"
            role_color = "#9333EA" if role == "Admin" else "#00D2FF"

            st.markdown(
                f"""
                <div style="background: #131B2E; border: 1px solid rgba(255,255,255,0.08); padding: 12px 14px; border-radius: 8px; margin-bottom: 12px;">
                    <div style="font-size: 0.72rem; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.5px;">Operator Profile</div>
                    <div style="font-size: 1.05rem; font-weight: 700; color: #F8FAFC;">👤 {username}</div>
                    <div style="margin-top: 4px;">
                        <span style="background: {role_color}22; color: {role_color}; border: 1px solid {role_color}66; padding: 2px 8px; border-radius: 6px; font-size: 0.72rem; font-weight: 600;">
                            {role}
                        </span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if st.button("🚪 Log Out", use_container_width=True, key="sidebar_logout_btn"):
                logout()
                st.rerun()
        else:
            st.info("🔒 Guest Session. Please log in from the main portal.")


def render_kpi_card_html(
    label: str, value: int, subtext: str, card_type: str = "default"
) -> str:
    """Generate HTML snippet for an individual KPI metric card."""
    type_class = card_type.lower()
    return f"""
    <div class="metric-card {type_class}">
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value:,}</div>
        <div class="metric-sub">{subtext}</div>
    </div>
    """


def load_demo_security_data(db_path: Optional[str] = None) -> Tuple[bool, str]:
    """Load synthetic demonstration logs and trigger SIEM detection engine."""
    from database.db_operations import (
        add_incident_note,
        get_all_incidents,
        get_total_logs_count,
        insert_security_logs,
    )
    from detection.detection_engine import run_threat_detection
    from log_processing.log_parser import parse_csv_logs

    csv_path = SAMPLE_DATA_DIR / "sample_security_logs.csv"
    if not csv_path.exists():
        return False, f"Sample data file not found at {csv_path}"

    valid, msg, df = parse_csv_logs(csv_path)
    if not valid or df.empty:
        return False, f"Failed to load sample dataset: {msg}"

    # Check for existing logs to avoid duplicate loading
    current_count = get_total_logs_count(db_path=db_path)
    if current_count > 0:
        return (
            False,
            f"Database already contains {current_count} log records. Reset data in Settings if you wish to reload.",
        )

    # Ingest logs
    records = df.to_dict(orient="records")
    insert_security_logs(records, db_path=db_path)

    # Run detection engine to populate detection_events and incidents
    results = run_threat_detection(df, persist_to_db=True, db_path=db_path)

    # Add initial analyst note on the first incident for demo context
    incidents = get_all_incidents(db_path=db_path)
    if incidents:
        add_incident_note(
            incident_id=incidents[0]["id"],
            user_id=None,
            username="System",
            note="Incident created automatically via ThreatGuard synthetic detection ruleset.",
            db_path=db_path,
        )

    return (
        True,
        f"Successfully loaded {len(records)} simulated security events and generated {len(results)} threat detection matches!",
    )

