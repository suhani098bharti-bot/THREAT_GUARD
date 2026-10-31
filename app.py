"""ThreatGuard – Cyber Incident Detection & Response System.

Main Application Entry Point and Authentication Portal.
"""

from pathlib import Path
import streamlit as st

# Configure Streamlit page parameters
st.set_page_config(
    page_title="ThreatGuard – Cyber Incident Detection & Response System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

from authentication.auth import (
    authenticate_user,
    get_current_role,
    get_current_user,
    init_session_state,
    is_authenticated,
    login,
    logout,
    register_user,
)
from config.settings import (
    ACADEMIC_DISCLAIMER,
    APP_NAME,
    APP_SUBTITLE,
    APP_VERSION,
    ASSETS_DIR,
    INITIAL_ADMIN_PASSWORD,
    INITIAL_ADMIN_USERNAME,
)
from database.db_operations import get_dashboard_kpis
from database.db_setup import initialize_database
from utils.helpers import load_custom_css, load_demo_security_data, render_sidebar_profile

# Ensure database is bootstrapped with default schema and admin
initialize_database()
init_session_state()
load_custom_css()

# Sidebar Branding
with st.sidebar:
    logo_path = ASSETS_DIR / "logo.png"
    if logo_path.exists():
        st.image(str(logo_path), width=70)
    st.markdown(f"### {APP_NAME}")
    st.caption(f"{APP_SUBTITLE} (v{APP_VERSION})")
    render_sidebar_profile()


# Main View Logic
if not is_authenticated():
    # Header Banner
    st.markdown(
        f"""
        <div class="threatguard-header">
            <div class="threatguard-title">🛡️ {APP_NAME}</div>
            <div class="threatguard-subtitle">{APP_SUBTITLE}</div>
            <div style="margin-top: 12px;">
                <span class="academic-badge">Academic SIEM Simulation Platform</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Academic Disclaimer Alert
    st.info(f"ℹ️ **Project Notice**: {ACADEMIC_DISCLAIMER}")

    # Authentication Container
    col_left, col_right = st.columns([1, 1], gap="large")

    with col_left:
        st.markdown("### 🔐 Security Operator Portal")
        auth_tab1, auth_tab2 = st.tabs(["Operator Login", "Register Analyst"])

        with auth_tab1:
            st.markdown("Enter your authorized credentials to access the SOC console.")
            with st.form("login_form", clear_on_submit=False):
                username_input = st.text_input("Username", value="", placeholder="e.g. admin or analyst")
                password_input = st.text_input("Password", type="password", placeholder="Enter your password")
                submitted = st.form_submit_button("Log In to ThreatGuard", type="primary", use_container_width=True)

                if submitted:
                    success, user_dict, msg = authenticate_user(username_input, password_input)
                    if success and user_dict:
                        login(user_dict)
                        st.success(f"Welcome, {user_dict['username']}! Redirecting to SOC dashboard...")
                        st.rerun()
                    else:
                        st.error(msg)

            st.caption("Default Administrator Setup:")
            st.code(f"Username: {INITIAL_ADMIN_USERNAME}\nPassword: {INITIAL_ADMIN_PASSWORD}", language="text")

        with auth_tab2:
            st.markdown("Create a new analyst or operator profile.")
            with st.form("register_form", clear_on_submit=False):
                new_user = st.text_input("Choose Username", placeholder="e.g. j_doe")
                new_pass = st.text_input("Password", type="password", placeholder="Min 8 chars, 1 uppercase, 1 digit, 1 symbol")
                confirm_pass = st.text_input("Confirm Password", type="password")
                role_choice = st.selectbox("Role", ["Analyst", "Admin"], index=0)
                reg_submitted = st.form_submit_button("Register New User", use_container_width=True)

                if reg_submitted:
                    if new_pass != confirm_pass:
                        st.error("Passwords do not match.")
                    else:
                        reg_ok, reg_msg = register_user(new_user, new_pass, role=role_choice)
                        if reg_ok:
                            st.success(reg_msg)
                        else:
                            st.error(reg_msg)

    with col_right:
        st.markdown("### 🌐 Platform Core Capabilities")
        st.markdown(
            """
            ThreatGuard provides a realistic, modular cybersecurity incident detection and response 
            environment designed for defensive security education:

            - 📥 **Log Ingestion & Parsing**: Ingest standard CSV and JSON security logs with validation and normalization.
            - 🔍 **SIEM Threat Detection Engine**: Heuristic detection for Brute Force, Port Scanning, SQL Injection, XSS, Suspicious IPs, Unauthorized Access, and Unusual Network Activity.
            - ⚖️ **Risk Scoring & Classification**: Calculate dynamic 0–100 risk scores across LOW, MEDIUM, HIGH, and CRITICAL severity tiers.
            - 🚨 **Incident Response Management**: Triage security alerts, assign analysts, document findings, and follow response playbooks.
            - 📈 **SOC Analytics Dashboard**: Interactive Plotly visualizations for event activity, threat trends, and top attacking IP addresses.
            - 📑 **Executive Reporting**: One-click export of structured security reports in CSV and professional PDF formats.
            """
        )

else:
    # Authenticated Welcome View
    user = get_current_user() or {}
    username = user.get("username", "Analyst")
    role = get_current_role()

    st.markdown(
        f"""
        <div class="threatguard-header">
            <div class="threatguard-title">🛡️ Welcome, {username}!</div>
            <div class="threatguard-subtitle">ThreatGuard SIEM Operations Portal | Authenticated as <b>{role}</b></div>
            <div style="margin-top: 10px;">
                <span class="academic-badge">SOC Station Active</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Real-time System KPI Glance
    kpis = get_dashboard_kpis()
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Security Events", f"{kpis['total_security_events']:,}")
    col2.metric("Threats Detected", f"{kpis['total_threats_detected']:,}")
    col3.metric("Critical Incidents", f"{kpis['critical_incidents']:,}")
    col4.metric("Pending Triage", f"{kpis['pending_incidents']:,}")

    st.markdown("---")
    st.markdown("### 🚀 SOC Navigation Modules")

    # Quick Navigation Cards
    nav_c1, nav_c2, nav_c3 = st.columns(3)
    with nav_c1:
        st.markdown(
            """
            <div class="soc-card">
                <div class="soc-card-title">📊 1. SOC Dashboard</div>
                <p style="color: #94A3B8; font-size: 0.88rem;">Executive overview of threat distributions, incident queues, and timeline charts.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.page_link("pages/1_Dashboard.py", label="Open SOC Dashboard ➔", icon="📊")

    with nav_c2:
        st.markdown(
            """
            <div class="soc-card">
                <div class="soc-card-title">📁 2. Log Analysis</div>
                <p style="color: #94A3B8; font-size: 0.88rem;">Upload, validate, inspect, and filter CSV/JSON security event logs.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.page_link("pages/2_Log_Analysis.py", label="Open Log Analysis ➔", icon="📁")

    with nav_c3:
        st.markdown(
            """
            <div class="soc-card">
                <div class="soc-card-title">⚡ 3. Threat Detection</div>
                <p style="color: #94A3B8; font-size: 0.88rem;">Run the SIEM rule engine against logs to detect cyberattack patterns.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.page_link("pages/3_Threat_Detection.py", label="Run Threat Detection ➔", icon="⚡")

    nav_c4, nav_c5, nav_c6 = st.columns(3)
    with nav_c4:
        st.markdown(
            """
            <div class="soc-card">
                <div class="soc-card-title">🚨 4. Incident Management</div>
                <p style="color: #94A3B8; font-size: 0.88rem;">Investigate incidents, update lifecycle status, assign analysts, and apply response playbooks.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.page_link("pages/4_Incident_Management.py", label="Manage Incidents ➔", icon="🚨")

    with nav_c5:
        st.markdown(
            """
            <div class="soc-card">
                <div class="soc-card-title">📑 5. Security Reports</div>
                <p style="color: #94A3B8; font-size: 0.88rem;">Export audit summaries and generate executive PDF/CSV compliance reports.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.page_link("pages/5_Security_Reports.py", label="Generate Reports ➔", icon="📑")

    with nav_c6:
        st.markdown(
            """
            <div class="soc-card">
                <div class="soc-card-title">⚙️ 6. System Settings</div>
                <p style="color: #94A3B8; font-size: 0.88rem;">Configure detection sensitivity thresholds and manage user accounts.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.page_link("pages/6_Settings.py", label="Open Settings ➔", icon="⚙️")

    st.markdown("---")
    # Quick Demo Dataset Loader
    d_c1, d_c2 = st.columns([2, 1])
    with d_c1:
        st.markdown("#### 🧪 Demonstration Mode")
        st.write("Quickly populate the SIEM platform with synthetic cybersecurity attack scenarios.")
    with d_c2:
        if st.button("🚀 Load Demo Security Data", type="primary", use_container_width=True):
            ok, msg = load_demo_security_data()
            if ok:
                st.success(msg)
                st.rerun()
            else:
                st.warning(msg)
