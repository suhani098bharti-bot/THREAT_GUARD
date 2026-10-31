"""Page 5: Security Reporting, Executive Compliance Summaries, and Export Center."""

from datetime import datetime
import streamlit as st
import pandas as pd

from authentication.auth import enforce_authentication, get_current_user
from database.db_operations import (
    get_all_incidents,
    get_dashboard_kpis,
    get_security_logs_dataframe,
    get_top_suspicious_ips_data,
)
from incident_response.incident_history import get_incident_resolution_metrics
from utils.export_utils import export_dataframe_to_csv, generate_security_pdf_report
from utils.helpers import render_page_header, render_sidebar_profile

enforce_authentication()
render_sidebar_profile()

current_user = get_current_user() or {}
current_username = current_user.get("username", "ThreatGuard Analyst")

render_page_header(
    title="Security Intelligence & Reports",
    subtitle="Executive Incident Auditing, Telemetry Export, and PDF / CSV Compliance Reporting",
    badge_text="Executive Reporting",
)

kpis = get_dashboard_kpis()
res_metrics = get_incident_resolution_metrics()
incidents = get_all_incidents()

# ========================================================
# EXECUTIVE METRICS SUMMARY
# ========================================================
st.markdown("### 📊 Executive Telemetry Audit Summary")

m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Events Analyzed", f"{kpis['total_security_events']:,}")
m2.metric("Threats Detected", f"{kpis['total_threats_detected']:,}")
m3.metric("Critical Incidents", f"{kpis['critical_incidents']:,}")
m4.metric("Incident Resolution Rate", f"{res_metrics['resolution_rate_percent']}%")

# Severity Breakdown Card
st.markdown("#### Severity Triage Distribution")
sev_c1, sev_c2, sev_c3, sev_c4 = st.columns(4)
crit_cnt = sum(1 for i in incidents if i["severity"] == "CRITICAL")
high_cnt = sum(1 for i in incidents if i["severity"] == "HIGH")
med_cnt = sum(1 for i in incidents if i["severity"] == "MEDIUM")
low_cnt = sum(1 for i in incidents if i["severity"] == "LOW")

sev_c1.metric("Critical Threats", crit_cnt)
sev_c2.metric("High-Risk Incidents", high_cnt)
sev_c3.metric("Medium-Risk", med_cnt)
sev_c4.metric("Low-Risk / Info", low_cnt)

st.markdown("---")

# ========================================================
# REPORT EXPORT GENERATION
# ========================================================
st.markdown("### 📥 Document Export Operations")
st.write("Generate and download formal security reports for archival, management review, or CSE project submission.")

rep_col1, rep_col2, rep_col3 = st.columns(3)

with rep_col1:
    st.markdown(
        """
        <div class="soc-card">
            <div class="soc-card-title">📄 Executive PDF Report</div>
            <p style="color: #94A3B8; font-size: 0.85rem;">Formatted PDF document with executive summary, KPI tables, incident audit list, and defensive recommendations.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if st.button("Generate Executive PDF Report", type="primary", use_container_width=True):
        with st.spinner("Compiling security metrics and rendering PDF document..."):
            pdf_bytes = generate_security_pdf_report(
                kpis=kpis,
                incidents=incidents,
                generated_by=current_username,
            )
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            st.download_button(
                label="⬇️ Download Executive PDF",
                data=pdf_bytes,
                file_name=f"ThreatGuard_Security_Report_{timestamp_str}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

with rep_col2:
    st.markdown(
        """
        <div class="soc-card">
            <div class="soc-card-title">📊 Incidents CSV Export</div>
            <p style="color: #94A3B8; font-size: 0.85rem;">Comprehensive CSV spreadsheet of all registered incidents, including risk scores, categories, and resolution notes.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if incidents:
        df_inc = pd.DataFrame(incidents)
        csv_inc = export_dataframe_to_csv(df_inc)
        st.download_button(
            label="⬇️ Download Incidents CSV",
            data=csv_inc,
            file_name="threatguard_incidents_full.csv",
            mime="text/csv",
            use_container_width=True,
        )
    else:
        st.info("No incidents on record to export.")

with rep_col3:
    st.markdown(
        """
        <div class="soc-card">
            <div class="soc-card-title">🗄️ Ingested Logs CSV Export</div>
            <p style="color: #94A3B8; font-size: 0.85rem;">Raw security event logs currently stored in the SQLite database, suitable for external SIEM correlation.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    raw_logs_df = get_security_logs_dataframe(limit=10000)
    if not raw_logs_df.empty:
        csv_logs = export_dataframe_to_csv(raw_logs_df)
        st.download_button(
            label="⬇️ Download Security Logs CSV",
            data=csv_logs,
            file_name="threatguard_security_logs_dump.csv",
            mime="text/csv",
            use_container_width=True,
        )
    else:
        st.info("No logs on record to export.")

st.markdown("---")

# ========================================================
# TOP SUSPICIOUS IPS & STRATEGIC RECOMMENDATIONS
# ========================================================
c_ip, c_rec = st.columns([1, 1], gap="large")

with c_ip:
    st.markdown("### 🎯 Highest-Threat Origin IP Addresses")
    top_ips = get_top_suspicious_ips_data(limit=8)
    if top_ips.empty:
        st.info("No suspicious IPs identified yet.")
    else:
        st.dataframe(top_ips, use_container_width=True, hide_index=True)

with c_rec:
    st.markdown("### 🛡️ Recommended Security Improvements")
    st.markdown(
        """
        Based on observed telemetry in this reporting window:
        
        1. **Privileged Account Defense:** Enforce hardware/FIDO2 MFA for administrative roles to neutralize brute force attempts.
        2. **Perimeter Hardening:** Drop non-standard inbound traffic at external borders to impede automated network port reconnaissance sweeps.
        3. **Application Layer Sanitization:** Enforce strict query parameterization and Content Security Policy (CSP) headers across all web forms.
        4. **Zero-Trust Network Segmentation:** Restrict internal endpoints from listening on unencrypted legacy or backdoor ports (e.g. 4444, 31337).
        """
    )
