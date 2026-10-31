"""Page 3: Rule-Based Threat Detection Engine & Heuristic Risk Evaluation."""

import streamlit as st
import pandas as pd

from authentication.auth import enforce_authentication
from config.settings import DEFAULT_DETECTION_THRESHOLDS, SEVERITY_COLORS
from database.db_operations import (
    get_all_detection_events,
    get_security_logs_dataframe,
    get_total_logs_count,
)
from detection.detection_engine import run_threat_detection
from detection.detection_rules import ACTIVE_DETECTION_RULES
from detection.risk_scoring import get_risk_assessment_details
from detection.threat_classifier import get_mitre_mapping, get_severity_badge_html
from utils.helpers import render_page_header, render_sidebar_profile

enforce_authentication()
render_sidebar_profile()

render_page_header(
    title="Cyber Threat Detection Engine",
    subtitle="Rule-Based SIEM Threat Identification, Heuristic Risk Scoring, and Alert Generation",
    badge_text="Detection Engine",
)

tab_engine, tab_rules, tab_events = st.tabs(
    ["⚡ Run Detection Engine", "📖 Active SIEM Ruleset", "📜 Historic Detection Events"]
)

# ========================================================
# TAB 1: RUN DETECTION ENGINE
# ========================================================
with tab_engine:
    st.markdown("### 🔍 SIEM Detection Orchestrator")
    st.write(
        "Execute automated rule correlation across ingested security event logs. "
        "Threat indicators generate correlated incidents in the incident management database."
    )

    total_logs = get_total_logs_count()
    if total_logs == 0:
        st.warning("⚠️ No security logs are currently present in the database. Please upload logs in **Log Analysis** or load demo data.")
    else:
        st.info(f"Ready to evaluate **{total_logs:,}** stored security event records.")

    # Detection Threshold Sensitivity Controls
    with st.expander("⚙️ Adjust Detection Engine Sensitivity Thresholds", expanded=False):
        c1, c2 = st.columns(2)
        with c1:
            bf_thresh = st.slider(
                "Brute Force: Failed Logins Threshold",
                min_value=2,
                max_value=20,
                value=int(DEFAULT_DETECTION_THRESHOLDS["brute_force_failed_attempts"]),
                help="Minimum consecutive failed authentication attempts required to trigger alert.",
            )
            ps_thresh = st.slider(
                "Port Scanning: Distinct Ports Threshold",
                min_value=3,
                max_value=30,
                value=int(DEFAULT_DETECTION_THRESHOLDS["port_scan_port_count"]),
                help="Minimum distinct non-zero ports probed by a single IP.",
            )
        with c2:
            sip_thresh = st.slider(
                "Suspicious IP: Anomalous Event Threshold",
                min_value=3,
                max_value=30,
                value=int(DEFAULT_DETECTION_THRESHOLDS["suspicious_ip_threshold"]),
                help="Minimum anomalous or rejected statuses from an individual IP.",
            )
            vol_thresh = st.slider(
                "Unusual Network: Traffic Volume Spike",
                min_value=10,
                max_value=100,
                value=int(DEFAULT_DETECTION_THRESHOLDS["unusual_volume_threshold"]),
                help="Extreme event volume threshold per IP.",
            )

        custom_thresholds = {
            "brute_force_failed_attempts": bf_thresh,
            "port_scan_port_count": ps_thresh,
            "suspicious_ip_threshold": sip_thresh,
            "unusual_volume_threshold": vol_thresh,
        }

    # Execute Button
    btn_col, _ = st.columns([1, 2])
    with btn_col:
        run_btn = st.button("🚀 Run Threat Detection Engine", type="primary", use_container_width=True, disabled=(total_logs == 0))

    if run_btn:
        with st.spinner("Analyzing telemetry logs against all 7 cyber detection rules..."):
            all_logs_df = get_security_logs_dataframe(limit=20000)
            thresholds_to_use = custom_thresholds if "custom_thresholds" in locals() else DEFAULT_DETECTION_THRESHOLDS
            detections = run_threat_detection(
                all_logs_df,
                thresholds=thresholds_to_use,
                persist_to_db=True,
            )
            st.session_state["latest_detections"] = detections
            st.success(f"Detection engine run complete! Identified **{len(detections)}** threat indicators.")

    # Display detections if available
    if "latest_detections" in st.session_state and st.session_state["latest_detections"]:
        results = st.session_state["latest_detections"]
        st.markdown("---")
        st.markdown(f"### 🎯 Detection Results Summary ({len(results)} Matches)")

        # Summary Metrics
        crit_count = sum(1 for r in results if r.severity == "CRITICAL")
        high_count = sum(1 for r in results if r.severity == "HIGH")
        med_count = sum(1 for r in results if r.severity == "MEDIUM")
        low_count = sum(1 for r in results if r.severity == "LOW")

        sc1, sc2, sc3, sc4 = st.columns(4)
        sc1.metric("Critical Alerts", crit_count)
        sc2.metric("High Severity", high_count)
        sc3.metric("Medium Severity", med_count)
        sc4.metric("Low Severity", low_count)

        st.markdown("#### Detailed Threat Indicators")
        for i, det in enumerate(results):
            sev_color = SEVERITY_COLORS.get(det.severity, "#00D2FF")
            with st.container():
                st.markdown(
                    f"""
                    <div style="background: #131B2E; border-left: 4px solid {sev_color}; border-top: 1px solid rgba(255,255,255,0.08); border-right: 1px solid rgba(255,255,255,0.08); border-bottom: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 16px 20px; margin-bottom: 16px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap; gap: 8px;">
                            <div style="font-size: 1.15rem; font-weight: 700; color: #F8FAFC;">
                                🚨 {det.category} &nbsp; 
                                <span style="font-size: 0.85rem; color: #94A3B8; font-weight: 400;">({det.rule_id})</span>
                            </div>
                            <div>
                                {get_severity_badge_html(det.severity)}
                                &nbsp;
                                <span style="background: rgba(255,255,255,0.08); padding: 2px 8px; border-radius: 6px; font-size: 0.78rem; font-weight: 700; color: #E2E8F0;">
                                    Risk Score: {det.risk_score}/100
                                </span>
                            </div>
                        </div>
                        <div style="font-size: 0.88rem; color: #CBD5E1; margin-bottom: 10px;">
                            <b>Source IP:</b> <code>{det.source_ip}</code> &nbsp;|&nbsp; 
                            <b>Timestamp:</b> {det.timestamp} &nbsp;|&nbsp; 
                            <b>Evidence Matches:</b> {det.evidence_count} event(s)
                        </div>
                        <div style="background: rgba(11, 15, 25, 0.6); padding: 12px; border-radius: 6px; margin-bottom: 10px; font-size: 0.86rem; color: #E2E8F0; line-height: 1.4;">
                            {det.explanation}
                        </div>
                        <div style="font-size: 0.84rem; color: #00D2FF;">
                            🛡️ <b>Recommended Action:</b> {det.recommended_response}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        st.info("ℹ️ Detected threats have been correlated and saved into **Incident Management** for triage.")
        st.page_link("pages/4_Incident_Management.py", label="Go to Incident Management ➔", icon="🚨")


# ========================================================
# TAB 2: ACTIVE SIEM RULESET CATALOG
# ========================================================
with tab_rules:
    st.markdown("### 📖 ThreatGuard SIEM Detection Ruleset")
    st.write("Catalog of rule-based detection signatures implemented in ThreatGuard:")

    for rule in ACTIVE_DETECTION_RULES:
        mitre = get_mitre_mapping(rule.category)
        with st.expander(f"📌 {rule.rule_id}: {rule.name} ({rule.category})", expanded=False):
            st.markdown(f"**Description**: {rule.description}")
            st.markdown(f"**Threat Category**: `{rule.category}`")
            st.markdown(
                f"**MITRE ATT&CK Mapping**: `{mitre['technique_id']}` - "
                f"**{mitre['technique_name']}** (Tactic: *{mitre['tactic']}*)"
            )
            st.markdown(
                "> **Academic Note**: Keyword signatures and heuristic thresholds flag suspicious indicators "
                "for analyst triage. Detections do not constitute definitive proof of breach without human verification."
            )


# ========================================================
# TAB 3: HISTORIC DETECTION EVENTS
# ========================================================
with tab_events:
    st.markdown("### 📜 Historic Detection Events Log")
    events = get_all_detection_events(limit=500)
    if not events:
        st.info("No detection events recorded in the database.")
    else:
        df_ev = pd.DataFrame(events)
        st.dataframe(df_ev, use_container_width=True, hide_index=True)
