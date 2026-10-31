"""Page 4: Incident Response Triage, Lifecycle Workflow, and Analyst Playbooks."""

import streamlit as st
import pandas as pd

from authentication.auth import enforce_authentication, get_current_user
from database.db_operations import get_all_incidents, get_all_users
from detection.threat_classifier import get_mitre_mapping, get_severity_badge_html
from incident_response.incident_manager import (
    add_analyst_note,
    fetch_incidents_as_dataframe,
    get_incident_full_context,
    update_incident_workflow,
)
from incident_response.response_recommendations import get_recommendations_for_incident
from utils.export_utils import export_dataframe_to_csv
from utils.helpers import render_page_header, render_sidebar_profile

enforce_authentication()
render_sidebar_profile()

current_user = get_current_user() or {}
current_username = current_user.get("username", "Analyst")
current_user_id = current_user.get("id")

render_page_header(
    title="Incident Management & Response",
    subtitle="SOC Triage, Workflow Tracking, Analyst Playbooks, and Incident Lifecycle Management",
    badge_text="Incident Triage",
)

tab_queue, tab_detail = st.tabs(["📋 Incident Queue & Filter", "🔍 Incident Investigation & Playbook"])

# ========================================================
# TAB 1: INCIDENT QUEUE
# ========================================================
with tab_queue:
    st.markdown("### 🚨 Active Incident Queue")

    # Filter Controls
    col_f1, col_f2, col_f3, col_f4 = st.columns(4)
    with col_f1:
        st_filter = st.selectbox("Status", ["All", "New", "Investigating", "Contained", "Resolved", "False Positive"])
    with col_f2:
        sev_filter = st.selectbox("Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with col_f3:
        cat_filter = st.selectbox(
            "Category",
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
        )
    with col_f4:
        search_kw = st.text_input("Search IP / Title", "")

    incidents_df = fetch_incidents_as_dataframe(
        status=st_filter if st_filter != "All" else None,
        severity=sev_filter if sev_filter != "All" else None,
        category=cat_filter if cat_filter != "All" else None,
        search_query=search_kw.strip() if search_kw.strip() else None,
    )

    if incidents_df.empty:
        st.info("No incidents found matching the selected filter criteria.")
    else:
        st.caption(f"Displaying {len(incidents_df)} incident record(s):")
        
        # Display clean table
        show_cols = ["id", "title", "category", "source_ip", "severity", "risk_score", "status", "assigned_to", "created_at"]
        disp_df = incidents_df[[c for c in show_cols if c in incidents_df.columns]].rename(
            columns={
                "id": "ID",
                "title": "Incident Title",
                "category": "Category",
                "source_ip": "Source IP",
                "severity": "Severity",
                "risk_score": "Risk",
                "status": "Status",
                "assigned_to": "Assigned Analyst",
                "created_at": "Created At",
            }
        )
        st.dataframe(disp_df, use_container_width=True, hide_index=True)

        exp_col, _ = st.columns([1, 3])
        with exp_col:
            csv_data = export_dataframe_to_csv(incidents_df)
            st.download_button(
                "📥 Export Incident Queue (CSV)",
                data=csv_data,
                file_name="threatguard_incidents_queue.csv",
                mime="text/csv",
                use_container_width=True,
            )


# ========================================================
# TAB 2: INCIDENT INVESTIGATION DRAWER & PLAYBOOK
# ========================================================
with tab_detail:
    st.markdown("### 🔍 Incident Detail & SOC Playbook Workbench")

    all_incidents = get_all_incidents()
    if not all_incidents:
        st.info("No incidents on record to inspect. Please load demo data or run the detection engine.")
    else:
        incident_options = {
            f"#{inc['id']} - [{inc['severity']}] {inc['title']} ({inc['status']})": inc["id"]
            for inc in all_incidents
        }

        selected_label = st.selectbox("Select Incident to Investigate", list(incident_options.keys()))
        selected_id = incident_options[selected_label]

        # Load full context
        inc_context = get_incident_full_context(selected_id)

        if inc_context:
            # Header card
            st.markdown(
                f"""
                <div style="background: #131B2E; border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; padding: 20px; margin-bottom: 20px;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 10px;">
                        <div>
                            <div style="font-size: 1.4rem; font-weight: 800; color: #F8FAFC;">
                                #{inc_context['id']}: {inc_context['title']}
                            </div>
                            <div style="color: #94A3B8; font-size: 0.88rem; margin-top: 4px;">
                                <b>Category:</b> {inc_context['category']} &nbsp;|&nbsp;
                                <b>Source IP:</b> <code>{inc_context.get('source_ip', 'N/A')}</code> &nbsp;|&nbsp;
                                <b>Detected:</b> {inc_context.get('created_at', '')}
                            </div>
                        </div>
                        <div style="text-align: right;">
                            {get_severity_badge_html(inc_context['severity'])}
                            <div style="margin-top: 6px; font-weight: 700; color: #00D2FF; font-size: 0.9rem;">
                                Risk Score: {inc_context['risk_score']}/100
                            </div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Two columns: Workflow Form vs Response Playbook
            w_col, p_col = st.columns([1, 1], gap="large")

            with w_col:
                st.markdown("#### 🛠️ Update Incident Workflow")

                # Get registered analysts for assignment
                users = get_all_users()
                analyst_list = ["Unassigned"] + [u["username"] for u in users]
                current_assigned = inc_context.get("assigned_to") or "Unassigned"
                assigned_idx = analyst_list.index(current_assigned) if current_assigned in analyst_list else 0

                status_list = ["New", "Investigating", "Contained", "Resolved", "False Positive"]
                curr_status = inc_context.get("status", "New")
                status_idx = status_list.index(curr_status) if curr_status in status_list else 0

                with st.form(f"workflow_form_{selected_id}"):
                    new_status = st.selectbox("Workflow Status", status_list, index=status_idx)
                    new_assignee = st.selectbox("Assignee", analyst_list, index=assigned_idx)
                    res_notes = st.text_area(
                        "Resolution / Triage Notes",
                        value=inc_context.get("resolution_notes") or "",
                        help="Document containment steps taken and reason for status closure.",
                    )
                    submit_workflow = st.form_submit_button("Update Incident Status", type="primary", use_container_width=True)

                    if submit_workflow:
                        ok = update_incident_workflow(
                            incident_id=selected_id,
                            status=new_status,
                            resolution_notes=res_notes,
                            assigned_to=new_assignee,
                            author_username=current_username,
                            author_id=current_user_id,
                        )
                        if ok:
                            st.success(f"Incident #{selected_id} updated successfully!")
                            st.rerun()
                        else:
                            st.error("Failed to update incident.")

                st.markdown("#### 📝 Add Investigation Note")
                with st.form(f"note_form_{selected_id}"):
                    new_note_text = st.text_area("Analyst Findings / Telemetry Note", placeholder="e.g. Verified target endpoint logs...")
                    submit_note = st.form_submit_button("Post Note to Audit Trail", use_container_width=True)

                    if submit_note:
                        if new_note_text.strip():
                            add_analyst_note(
                                incident_id=selected_id,
                                note=new_note_text.strip(),
                                username=current_username,
                                user_id=current_user_id,
                            )
                            st.success("Note added to investigation audit log.")
                            st.rerun()
                        else:
                            st.warning("Note cannot be empty.")

            with p_col:
                st.markdown("#### 📖 Defensive Response Playbook")
                playbook = get_recommendations_for_incident(inc_context["category"])
                mitre = get_mitre_mapping(inc_context["category"])

                st.markdown(
                    f"""
                    <div style="background: rgba(0, 210, 255, 0.05); border: 1px solid rgba(0, 210, 255, 0.2); padding: 14px; border-radius: 8px; margin-bottom: 12px;">
                        <div style="font-weight: 700; color: #00D2FF; font-size: 0.95rem;">📘 {playbook['playbook_title']}</div>
                        <div style="font-size: 0.8rem; color: #94A3B8; margin-top: 4px;">
                            MITRE ATT&CK: <code>{mitre['technique_id']}</code> - {mitre['technique_name']} ({mitre['tactic']})
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                st.markdown("**⚡ Immediate Actions for SOC Operator:**")
                for act in playbook["immediate_actions"]:
                    st.markdown(f"- [ ] {act}")

                st.markdown("**🛡️ Long-Term Defense & Hardening:**")
                for hard in playbook["long_term_hardening"]:
                    st.markdown(f"- • {hard}")

                st.markdown("**❓ Investigative Key Questions:**")
                for q in playbook["investigation_questions"]:
                    st.markdown(f"- 💬 *{q}*")

                st.caption(f"⚠️ {playbook['disclaimer']}")

            # Chronological Audit History & Linked Events
            st.markdown("---")
            st.markdown("#### 📜 Incident Chronological Audit Trail & Detection Events")

            c_audit1, c_audit2 = st.columns(2)
            with c_audit1:
                st.markdown("**Analyst Notes & Audit Log**")
                notes = inc_context.get("notes", [])
                if not notes:
                    st.caption("No notes or workflow actions recorded yet.")
                else:
                    for n in notes:
                        st.markdown(
                            f"""
                            <div style="border-left: 2px solid #00D2FF; padding-left: 10px; margin-bottom: 10px;">
                                <div style="font-size: 0.78rem; color: #94A3B8;">
                                    <b>{n.get('username', 'System')}</b> at {n.get('created_at', '')}
                                </div>
                                <div style="font-size: 0.86rem; color: #E2E8F0;">
                                    {n.get('note', '')}
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

            with c_audit2:
                st.markdown("**Linked Detection Match Events**")
                events = inc_context.get("events", [])
                if not events:
                    st.caption("No individual detection events recorded.")
                else:
                    for ev in events:
                        st.markdown(
                            f"""
                            <div style="background: #0E1424; border: 1px solid rgba(255,255,255,0.06); padding: 10px; border-radius: 6px; margin-bottom: 8px;">
                                <div style="font-size: 0.78rem; color: #94A3B8;">
                                    <b>Rule:</b> <code>{ev.get('rule_id')}</code> | <b>Detected:</b> {ev.get('detected_at')}
                                </div>
                                <div style="font-size: 0.84rem; color: #CBD5E1; margin-top: 4px;">
                                    {ev.get('explanation')}
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
