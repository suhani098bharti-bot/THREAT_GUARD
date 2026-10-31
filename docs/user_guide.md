# ThreatGuard – End-User & SOC Operator Guide

This user manual walks through typical security operations center (SOC) workflows within ThreatGuard.

---

## 1. Authentication & Session Access
1. Open the ThreatGuard portal.
2. Under **Operator Login**, enter your credentials (default: `admin` / `Admin@ThreatGuard2026!`).
3. If you do not have an account, switch to **Register Analyst**, fill in your desired username, password meeting complexity requirements, and select your role (**Analyst** or **Admin**).
4. Once authenticated, the sidebar displays your operator profile and active role badge.

---

## 2. Security Operations Center (SOC) Dashboard
Navigate to **1_Dashboard** from the sidebar navigation:
- **KPI Overview**: Displays total security logs ingested, threats detected, critical incidents, and pending triage counts.
- **Threat Timeline**: Plots detections over time colored by severity tiers (Critical, High, Medium, Low).
- **Distribution Charts**:
  - Donut chart of severity breakdown.
  - Horizontal bar chart of attack categories.
  - Donut chart of incident lifecycle statuses (New, Investigating, Contained, Resolved, False Positive).
- **Recent Incidents**: Real-time table of recent alerts with live multi-column filtering.
- **Empty State Quick Action**: If the database is clean, click **Load Demo Security Data** to immediately populate realistic cyber scenarios.

---

## 3. Log Ingestion & Analysis
Navigate to **2_Log_Analysis**:
1. **Upload**: Drag-and-drop your security log file (supports standard `.csv` or `.json` formats).
2. Alternatively, click **Load Built-in Sample CSV** to load test data.
3. Review data validation metrics (total rows, unique source IPs, identified fields).
4. Apply client-side filters (Source IP, Event Type, Status, keyword message search).
5. **Database Commit**: Click **Ingest Logs into Database** to permanently store the records.
6. **Instant Detection**: Click **Run Threat Detection on File** to immediately evaluate the uploaded data against all SIEM rules.
7. **CSV Export**: Click **Export Processed Logs** to save sanitized CSV records to your workstation.

---

## 4. Running the Threat Detection Engine
Navigate to **3_Threat_Detection**:
1. Under **Run Detection Engine**, inspect the count of available database logs.
2. Optionally expand **Adjust Detection Engine Sensitivity Thresholds** to customize trigger thresholds (e.g. failed login limits).
3. Click **Run Threat Detection Engine**.
4. ThreatGuard evaluates all 7 detection rules, generates heuristic risk scores (0–100), and correlates alerts into incidents.
5. Review matched threats in the container list showing matched IP, evidence count, severity badge, explanation, and response actions.
6. Switch to **Active SIEM Ruleset** to review MITRE ATT&CK mappings.

---

## 5. Incident Management & Response Triage
Navigate to **4_Incident_Management**:
1. **Queue View**: View all active alerts with dropdown filters for Status, Severity, and Category.
2. Switch to **Incident Investigation & Playbook** and pick an incident from the dropdown.
3. Review the **Defensive Response Playbook** containing:
   - Immediate triage steps.
   - Long-term defense hardening guidelines.
   - Key investigation questions.
4. **Update Workflow**:
   - Change Status (e.g., from *New* to *Investigating* or *Contained*).
   - Assign to an active Analyst.
   - Enter Resolution / Triage Notes and click **Update Incident Status**.
5. **Post Findings**: Type notes in the analyst notepad to record chronological investigation findings into the permanent audit log.

---

## 6. Security Reporting & Document Generation
Navigate to **5_Security_Reports**:
1. Review the executive summary metrics and incident resolution percentage.
2. Click **Generate Executive PDF Report** to produce an executive-ready PDF document including KPI tables, incident audit listings, and security recommendations.
3. Click **Download Incidents CSV** or **Download Security Logs CSV** for raw data exports.

---

## 7. System Administration & RBAC
Navigate to **6_Settings**:
- **Profile**: Review your active session privileges or log out.
- **User Management (Admin Only)**:
  - Create new Analyst or Administrator accounts.
  - Modify existing user roles.
  - Delete retired user accounts.
- **Database Maintenance**:
  - View SQLite database storage file location.
  - Reset database to clean state.
  - Reload demonstration datasets.
