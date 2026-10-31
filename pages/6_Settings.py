"""Page 6: System Settings, User Administration (RBAC), and Database Maintenance."""

import sys
import streamlit as st
import pandas as pd

from authentication.auth import (
    enforce_authentication,
    get_current_role,
    get_current_user,
    is_admin,
    logout,
    register_user,
)
from config.settings import (
    ACADEMIC_DISCLAIMER,
    APP_NAME,
    APP_VERSION,
    DATABASE_PATH,
    DEFAULT_DETECTION_THRESHOLDS,
)
from database.db_operations import delete_user, get_all_users, update_user_role
from database.db_setup import reset_database
from utils.helpers import load_demo_security_data, render_page_header, render_sidebar_profile

enforce_authentication()
render_sidebar_profile()

current_user = get_current_user() or {}
current_username = current_user.get("username", "Analyst")
current_role = get_current_role()
user_is_admin = is_admin()

render_page_header(
    title="System Settings & Administration",
    subtitle="User Profile, Role-Based Access Control (RBAC), SIEM Thresholds, and Database Utilities",
    badge_text="System Config",
)

tab_profile, tab_thresh, tab_users, tab_db, tab_info = st.tabs(
    [
        "👤 Profile",
        "⚙️ Detection Thresholds",
        "👥 User Management" if user_is_admin else "👥 User Management (Admin Only)",
        "🗄️ Database Maintenance",
        "ℹ️ System Information",
    ]
)

# ========================================================
# TAB 1: OPERATOR PROFILE
# ========================================================
with tab_profile:
    st.markdown("### 👤 Active Operator Profile")
    st.markdown(
        f"""
        <div style="background: #131B2E; border: 1px solid rgba(255,255,255,0.08); padding: 20px; border-radius: 8px; max-width: 500px;">
            <div style="font-size: 1.2rem; font-weight: 700; color: #F8FAFC; margin-bottom: 8px;">
                Operator: {current_username}
            </div>
            <div style="color: #94A3B8; font-size: 0.9rem; margin-bottom: 6px;">
                <b>System Role:</b> <span style="color: #00D2FF; font-weight: 600;">{current_role}</span>
            </div>
            <div style="color: #94A3B8; font-size: 0.9rem; margin-bottom: 12px;">
                <b>Account ID:</b> {current_user.get('id', 'N/A')}
            </div>
            <div style="color: #64748B; font-size: 0.8rem;">
                Session authenticated via secure bcrypt-hashed identity credentials.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")
    if st.button("🚪 Log Out of ThreatGuard", type="secondary"):
        logout()
        st.success("Session terminated.")
        st.rerun()


# ========================================================
# TAB 2: DETECTION THRESHOLDS
# ========================================================
with tab_thresh:
    st.markdown("### ⚙️ Global Detection Thresholds")
    st.write("Review the default SIEM detection rule trigger sensitivities:")

    st.markdown(
        f"""
        - **Brute Force Detection:** Triggers upon **{DEFAULT_DETECTION_THRESHOLDS['brute_force_failed_attempts']}** or more failed login attempts from a single IP.
        - **Port Scanning Detection:** Triggers upon **{DEFAULT_DETECTION_THRESHOLDS['port_scan_port_count']}** or more unique probed destination ports.
        - **Suspicious IP Threshold:** Triggers upon **{DEFAULT_DETECTION_THRESHOLDS['suspicious_ip_threshold']}** anomalous or rejected events.
        - **Unusual Network Volume:** Triggers upon **{DEFAULT_DETECTION_THRESHOLDS['unusual_volume_threshold']}** events from one source.
        """
    )
    st.caption("Custom per-run sensitivities can also be adjusted dynamically in the **Threat Detection** page.")


# ========================================================
# TAB 3: USER MANAGEMENT (ADMIN ONLY)
# ========================================================
with tab_users:
    if not user_is_admin:
        st.warning("🔒 Access Restricted: User administration and RBAC role assignment require Administrator permissions.")
        st.info(f"Your current role is **{current_role}**. Contact a system administrator to manage operator accounts.")
    else:
        st.markdown("### 👥 Operator Account Management (RBAC)")

        # List all users
        users = get_all_users()
        df_users = pd.DataFrame(users)
        st.markdown("#### Registered System Users")
        st.dataframe(df_users, use_container_width=True, hide_index=True)

        st.markdown("---")
        u_col1, u_col2 = st.columns(2, gap="large")

        with u_col1:
            st.markdown("#### ➕ Create New System Account")
            with st.form("admin_create_user_form"):
                new_uname = st.text_input("New Username", placeholder="e.g. sec_analyst_2")
                new_pwd = st.text_input("Password", type="password", placeholder="Secure password")
                new_role = st.selectbox("Role", ["Analyst", "Admin"], index=0)
                submit_new_user = st.form_submit_button("Create User Account", type="primary")

                if submit_new_user:
                    ok, msg = register_user(new_uname, new_pwd, role=new_role)
                    if ok:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)

        with u_col2:
            st.markdown("#### 🔄 Modify Role or Remove User")
            other_users = [u for u in users if u["username"] != current_username]
            if not other_users:
                st.caption("No other users available to modify.")
            else:
                user_map = {f"{u['username']} ({u['role']})": u for u in other_users}
                target_label = st.selectbox("Select User", list(user_map.keys()))
                target_user = user_map[target_label]

                role_col, del_col = st.columns(2)
                with role_col:
                    new_r = st.selectbox("Assign New Role", ["Analyst", "Admin"], index=0 if target_user["role"] == "Analyst" else 1)
                    if st.button("Update Role"):
                        update_user_role(target_user["id"], new_r)
                        st.success(f"Role updated for {target_user['username']}!")
                        st.rerun()

                with del_col:
                    st.write("Account Deletion")
                    if st.button("❌ Delete Account", type="secondary"):
                        delete_user(target_user["id"])
                        st.warning(f"Deleted user {target_user['username']}.")
                        st.rerun()


# ========================================================
# TAB 4: DATABASE MAINTENANCE
# ========================================================
with tab_db:
    st.markdown("### 🗄️ Database Storage & Telemetry Maintenance")
    st.markdown(f"**Database Engine:** SQLite 3 (ACID-compliant with WAL mode)")
    st.markdown(f"**Active Database File:** `{DATABASE_PATH}`")

    st.markdown("---")
    st.markdown("#### 🧪 Demonstration Mode Quick Data Reset")
    st.write("Reset database tables or reload synthetic cybersecurity demonstration logs:")

    d_col1, d_col2 = st.columns(2)
    with d_col1:
        if st.button("📥 Load Demo Security Dataset", use_container_width=True):
            ok, msg = load_demo_security_data()
            if ok:
                st.success(msg)
            else:
                st.warning(msg)

    with d_col2:
        if user_is_admin:
            confirm_reset = st.checkbox("Confirm: Wipe all logs and incidents")
            if st.button("🗑️ Reset All Data to Clean State", disabled=not confirm_reset, use_container_width=True):
                reset_database()
                st.success("Database wiped and reset to initial state with default admin account.")
                st.rerun()
        else:
            st.caption("Data reset requires Administrator privileges.")


# ========================================================
# TAB 5: SYSTEM INFORMATION & STREAMLIT CLOUD NOTES
# ========================================================
with tab_info:
    st.markdown("### ℹ️ Application Architecture & Deployment Information")

    st.markdown(
        f"""
        - **Application Name:** {APP_NAME}
        - **Version:** {APP_VERSION}
        - **Python Runtime:** {sys.version.split()[0]}
        - **Framework:** Streamlit Multi-Page Architecture
        - **Database Storage:** SQLite with parameterized SQL and foreign keys
        - **Academic Classification:** Computer Science Engineering Final Year Project
        """
    )

    st.markdown("#### ☁️ Streamlit Community Cloud Persistence Considerations")
    st.info(
        """
        **Important Cloud Persistence Documentation:**
        - Streamlit Community Cloud runs applications inside stateless ephemeral Docker containers.
        - The local SQLite database (`threatguard.db`) operates with full ACID compliance within the running session, 
          but changes will reset if the cloud container spins down after inactivity or restarts during redeployment.
        - For permanent production enterprise deployment, the database operations module (`database/db_operations.py`) 
          can be redirected to a managed PostgreSQL instance (e.g. Supabase, Neon, or Railway) by swapping the connection factory.
        """
    )

    st.markdown("#### 🛡️ Defensive Academic Scope")
    st.caption(ACADEMIC_DISCLAIMER)
