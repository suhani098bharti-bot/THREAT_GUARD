# 🛡️ ThreatGuard – Cyber Incident Detection & Response System

[![Python Version](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Streamlit-FF4B4B.svg)](https://streamlit.io/)
[![Database](https://img.shields.io/badge/Database-SQLite3-00D2FF.svg)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Pytest-24%20Passed-success.svg)](tests/)

> **Academic Defensive Project Notice**: ThreatGuard is an educational defensive cybersecurity monitoring and incident response simulation platform designed for Computer Science Engineering (CSE) academic demonstration. It demonstrates Security Information and Event Management (SIEM) concepts. It is not an enterprise-grade commercial SIEM and does not claim automated AI-powered breach prevention.

---

## 📋 Table of Contents
1. [Project Overview](#1-project-overview)
2. [Problem Statement](#2-problem-statement)
3. [Project Objectives](#3-project-objectives)
4. [Key Features](#4-key-features)
5. [Technology Stack](#5-technology-stack)
6. [Architecture Overview](#6-architecture-overview)
7. [Modular Folder Structure](#7-modular-folder-structure)
8. [Installation Instructions](#8-installation-instructions)
9. [Authentication Setup & RBAC](#9-authentication-setup--rbac)
10. [Database Design](#10-database-design)
11. [Detection Mechanism & MITRE ATT&CK](#11-detection-mechanism--mitre-attck)
12. [Running the Application](#12-running-the-application)
13. [Running Automated Tests](#13-running-automated-tests)
14. [Streamlit Cloud Deployment](#14-streamlit-cloud-deployment)
15. [User Interface & Visual Design](#15-user-interface--visual-design)
16. [Future Enhancements](#16-future-enhancements)
17. [Academic Scope & Limitations](#17-academic-scope--limitations)
18. [License](#18-license)

---

## 1. Project Overview
**ThreatGuard** is a full-stack, modular web application built with Python and Streamlit designed to simulate core Security Operations Center (SOC) workflows. It provides log ingestion, rule-based cyber threat identification, heuristic risk evaluation, alert generation, incident lifecycle tracking, analyst defensive playbooks, interactive telemetry visualization, and formal PDF/CSV compliance reporting.

---

## 2. Problem Statement
Security analysts must continuously monitor heterogenous network telemetry to identify anomalies before breaches escalate. However:
- Commercial SIEM platforms (Splunk, IBM QRadar, Datadog) are proprietary, cost-prohibitive, and complex to configure for academic laboratories.
- Basic classroom scripts lack real-time visualization, role-based access control, persistent incident management, and structured triage playbooks.

ThreatGuard solves this problem by offering a transparent, lightweight, self-contained SIEM simulation platform engineered specifically for computer science education and defensive security research.

---

## 3. Project Objectives
- Ingest and normalize raw security event logs from standard CSV and JSON data streams.
- Implement seven classic cyberattack detection algorithms mapped to the MITRE ATT&CK matrix.
- Calculate dynamic heuristic risk scores bounded between 0 and 100.
- Classify threats across four distinct severity tiers: `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.
- Model full incident lifecycle workflows: `New` ➔ `Investigating` ➔ `Contained` ➔ `Resolved` ➔ `False Positive`.
- Provide defensive remediation playbooks to guide SOC operators through containment.
- Export executive reports in CSV and professional ReportLab PDF formats.

---

## 4. Key Features
- **🔐 Session-Based Authentication & RBAC**: Secure user authentication powered by `bcrypt` password hashing with salt, password strength enforcement, and role permissions distinguishing **Admin** and **Analyst** tiers.
- **📁 Flexible Log Ingestion & Validation**: Ingest CSV and JSON logs with file size boundaries (25MB limit), schema normalization for common column aliases, IP address validation, and interactive filtering.
- **⚡ 7 Predefined Cyber Threat Detection Signatures**:
  1. *Brute Force Authentication Attack* (Credential guessing detection)
  2. *Port Scanning / Service Discovery* (Sequential port sweep detection)
  3. *SQL Injection (SQLi)* (Boolean tautologies, `UNION SELECT`, `DROP TABLE`)
  4. *Cross-Site Scripting (XSS)* (`<script>` tags, DOM event handlers, `document.cookie`)
  5. *Suspicious IP Activity* (Repetitive error and rejection rate correlation)
  6. *Unauthorized Access Attempts* (Sensitive file and path traversal probing)
  7. *Unusual Network Activity* (Known trojan/backdoor ports e.g. 4444, 31337 or traffic spikes)
- **⚖️ Dynamic Heuristic Risk Scoring**: Evaluates indicator confidence, base severity weights, and event frequencies into calibrated 0–100 risk scores.
- **🚨 Incident Management Workbench**: Assign incidents to analysts, update workflow statuses, add chronological investigation notes, and follow defensive response playbooks.
- **📊 SOC Telemetry Dashboard**: Dark-navy high-contrast cybersecurity theme featuring real-time KPI cards and interactive Plotly visualization charts.
- **📑 Executive Reporting Engine**: Download incident spreadsheets and generate styled executive PDF reports with one click.
- **🧪 Demonstration Mode**: Instant one-click loading of realistic synthetic attack datasets with duplicate prevention.

---

## 5. Technology Stack
- **Frontend / UI**: [Streamlit](https://streamlit.io/) with custom SOC dark CSS (`assets/styles.css`).
- **Backend**: Python 3.11+ / 3.13.
- **Data Processing**: [Pandas](https://pandas.pydata.org/) & [NumPy](https://numpy.org/).
- **Visualizations**: [Plotly Express & Graph Objects](https://plotly.com/python/).
- **Database**: [SQLite 3](https://www.sqlite.org/) with parameterized queries, indexes, and foreign keys.
- **Security & Cryptography**: [bcrypt](https://pypi.org/project/bcrypt/) with per-user salt rounds.
- **Reporting**: [ReportLab](https://www.reportlab.com/) for executive PDF generation.
- **Testing**: [Pytest](https://docs.pytest.org/).

---

## 6. Architecture Overview
```
+-------------------------------------------------------------------------+
|                         PRESENTATION LAYER                              |
|   Streamlit Multi-Page UI | Custom Dark SOC CSS | Plotly Visualizations |
+--------------------+---------------------+--------------------+---------+
                     |                     |                    |
+--------------------v---------------------v--------------------v---------+
|                         APPLICATION LOGIC                               |
|   authentication/ (RBAC)        log_processing/ (Ingestion)             |
|   incident_response/ (Workflow) dashboard/ (Analytics Engine)           |
+--------------------+---------------------+--------------------+---------+
                     |                     |
+--------------------v---------------------v------------------------------+
|                         DETECTION ENGINE                                |
|   detection/ (Engine, Rules, MITRE Mapping, Heuristic Risk Scoring)     |
+------------------------------------------+------------------------------+
                                           |
+------------------------------------------v------------------------------+
|                          PERSISTENCE LAYER                              |
|   database/ (SQLite, Parameterized SQL, Indexes, Foreign Keys)          |
+-------------------------------------------------------------------------+
```

---

## 7. Modular Folder Structure
```
ThreatGuard/
│
├── app.py                         # Application entry point & login portal
├── requirements.txt               # Pinned package dependencies
├── README.md                      # Complete system documentation
├── .gitignore                     # Git exclusion rules
├── .env.example                   # Environment configuration template
├── LICENSE                        # Open-source MIT license
│
├── .streamlit/
│   ├── config.toml                # Streamlit SOC dark theme & server options
│   └── secrets.toml.example       # Deployment secrets configuration template
│
├── config/
│   ├── __init__.py
│   └── settings.py                # Global settings, paths, boundaries, thresholds
│
├── authentication/
│   ├── __init__.py
│   ├── auth.py                    # Session state, login verification, RBAC guards
│   └── password_utils.py          # bcrypt password hashing & validation policy
│
├── database/
│   ├── __init__.py
│   ├── db_connection.py           # Thread-safe SQLite connection context manager
│   ├── db_setup.py                # Schema DDL, table indexes, admin bootstrap
│   └── db_operations.py           # Parameterized SQL CRUD & SOC analytical queries
│
├── detection/
│   ├── __init__.py
│   ├── detection_engine.py        # Detection orchestrator & incident deduplication
│   ├── detection_rules.py         # 7 MITRE-aligned SIEM cyber detection rules
│   ├── threat_classifier.py       # Severity classification & MITRE technique maps
│   └── risk_scoring.py            # Bounded 0-100 heuristic risk scoring model
│
├── log_processing/
│   ├── __init__.py
│   ├── log_parser.py              # CSV delimiter-sniffing & JSON/NDJSON parsers
│   ├── log_validator.py           # Upload sanitization & column normalization
│   └── log_analyzer.py            # Telemetry aggregations & multi-criteria filtering
│
├── incident_response/
│   ├── __init__.py
│   ├── incident_manager.py        # Incident lifecycle, assignments, note auditing
│   ├── response_recommendations.py# Structured defensive playbooks per threat type
│   └── incident_history.py        # Resolution rates & historical audit trails
│
├── dashboard/
│   ├── __init__.py
│   ├── overview.py                # Primary SOC overview component & KPI cards
│   ├── analytics.py               # Analytical aggregation routines
│   └── charts.py                  # Plotly interactive timeline & distribution charts
│
├── pages/
│   ├── 1_Dashboard.py             # Security Operations Center view
│   ├── 2_Log_Analysis.py          # Log ingestion, parsing, and filtering view
│   ├── 3_Threat_Detection.py      # Rule engine execution & sensitivity controls
│   ├── 4_Incident_Management.py   # Incident triage workbench & analyst playbooks
│   ├── 5_Security_Reports.py      # PDF report generation & CSV export center
│   └── 6_Settings.py              # User administration (RBAC) & DB utilities
│
├── utils/
│   ├── __init__.py
│   ├── helpers.py                 # CSS loaders, header banners, demo loader
│   ├── validators.py              # IP, port, and string format validators
│   └── export_utils.py            # ReportLab executive PDF & CSV generators
│
├── assets/
│   ├── logo.png                   # ThreatGuard glowing cyber shield emblem
│   └── styles.css                 # SOC dark theme high-contrast stylesheet
│
├── sample_data/
│   ├── sample_security_logs.csv   # Comprehensive synthetic multi-attack log stream
│   ├── sample_authentication_logs.csv # Focused identity & brute force test stream
│   └── sample_incidents.csv       # Pre-built incident benchmark records
│
├── tests/
│   ├── __init__.py
│   ├── test_auth.py               # Tests for bcrypt, policy checks, session login
│   ├── test_detection.py          # Tests for all 7 rules, scoring, and severity
│   ├── test_log_processing.py     # Tests for CSV, JSON, invalid files, filtering
│   └── test_incident_management.py# Tests for incident CRUD, notes, deduplication
│
└── docs/
    ├── project_overview.md        # Academic problem statement & motivation
    ├── architecture.md            # Detailed multi-tier architectural breakdown
    ├── detection_rules.md         # In-depth detection signatures & formula specs
    ├── installation.md            # Step-by-step setup for Mac, Linux, and Windows
    └── user_guide.md              # Operator walkthrough manual for all pages
```

---

## 8. Installation Instructions

### Prerequisites
- Python 3.11 or higher
- Git

### Quick Setup
```bash
# 1. Clone repository
git clone https://github.com/<your-username>/ThreatGuard.git
cd ThreatGuard

# 2. Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate       # On Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 9. Authentication Setup & RBAC
ThreatGuard automatically provisions an initial administrator account upon startup:
- **Default Username**: `admin`
- **Default Password**: `Admin@ThreatGuard2026!`

### Role Permissions Matrix
| Capability | Administrator (`Admin`) | Security Analyst (`Analyst`) |
|:---|:---:|:---:|
| View SOC Dashboard & Charts | ✅ | ✅ |
| Ingest & Filter Logs | ✅ | ✅ |
| Execute Threat Detection Engine | ✅ | ✅ |
| Investigate & Update Incidents | ✅ | ✅ |
| Add Investigation Notes | ✅ | ✅ |
| Export PDF & CSV Reports | ✅ | ✅ |
| Create New User Accounts | ✅ | ❌ |
| Change User Roles | ✅ | ❌ |
| Delete User Accounts | ✅ | ❌ |
| Wipe / Reset Database | ✅ | ❌ |

---

## 10. Database Design
ThreatGuard uses a normalized SQLite database with enforced foreign keys:

```
+--------------------+        +-----------------------+        +------------------------+
|      users         |        |       incidents       |        |    detection_events    |
+--------------------+        +-----------------------+        +------------------------+
| id (PK)            |        | id (PK)               |<-------| id (PK)                |
| username (UNIQUE)  |        | title                 |        | rule_id                |
| password_hash      |        | category              |        | incident_id (FK)       |
| role               |        | source_ip             |        | source_ip              |
| created_at         |        | severity              |        | severity               |
+--------------------+        | risk_score            |        | risk_score             |
          ^                   | description           |        | explanation            |
          |                   | status                |        | detected_at            |
          |                   | assigned_to           |        +------------------------+
          |                   | created_at            |
          |                   | updated_at            |
          |                   | resolution_notes      |
          |                   +-----------------------+
          |                               ^
          |                               |
+--------------------+                    |
|   incident_notes   |                    |
+--------------------+                    |
| id (PK)            |                    |
| incident_id (FK)---|--------------------+
| user_id (FK)-------+
| username           |
| note               |
| created_at         |
+--------------------+
```

---

## 11. Detection Mechanism & MITRE ATT&CK

| Rule ID | Threat Category | MITRE ATT&CK | Trigger Signature | Default Threshold |
|:---|:---|:---:|:---|:---:|
| `RULE-AUTH-001` | **Brute Force** | T1110 | Repeated authentication failures from single IP | $\ge 5$ failures |
| `RULE-NET-002` | **Port Scanning** | T1046 | Single IP connecting to multiple destination ports | $\ge 5$ distinct ports |
| `RULE-WEB-003` | **SQL Injection** | T1190 | Boolean tautology (`' OR 1=1`), `UNION SELECT`, `DROP TABLE` | Regex pattern match |
| `RULE-WEB-004` | **Cross-Site Scripting** | T1189 | `<script>`, DOM event handlers (`onerror=`), `document.cookie` | Regex pattern match |
| `RULE-IP-005` | **Suspicious IP** | T1071 | High frequency of rejected/blocked events from single IP | $\ge 8$ anomalous events |
| `RULE-ACCESS-006` | **Unauthorized Access** | T1078 | Access to `/etc/passwd`, `.env`, `/admin/config.php` + 403 status | Pattern + status match |
| `RULE-NET-007` | **Unusual Network** | T1571 | Backdoor ports (4444, 31337, 6667) or event volume spikes | Port match or $\ge 25$ events |

---

## 12. Running the Application
Launch ThreatGuard locally:
```bash
streamlit run app.py
```
Open your web browser and navigate to `http://localhost:8501`.

---

## 13. Running Automated Tests
Run the complete Pytest validation suite:
```bash
pytest -v
```
All 24 automated test cases validate authentication, detection rules, log parsing, and incident lifecycle routines in isolated temporary test databases.

---

## 14. Streamlit Cloud Deployment
ThreatGuard is 100% compatible with **Streamlit Community Cloud**:
1. Push this repository to GitHub.
2. Visit [share.streamlit.io](https://share.streamlit.io/) and click **New App**.
3. Point to your repository, select branch `main`, and set main file to `app.py`.
4. In **Settings > Secrets**, supply:
   ```toml
   [general]
   app_name = "ThreatGuard – Cyber Incident Detection & Response System"
   environment = "production"

   [security]
   initial_admin_username = "admin"
   initial_admin_password = "Admin@ThreatGuard2026!"
   secret_key = "replace-with-a-random-secure-secret-token"

   [database]
   path = "threatguard.db"

   [detection]
   brute_force_threshold = 5
   port_scan_port_threshold = 5
   suspicious_ip_threshold = 8
   ```
5. Click **Deploy**.

> **Cloud Persistence Documentation**: Streamlit Community Cloud runs in stateless ephemeral containers. The local SQLite database resets if the container spins down. For production deployments with continuous multi-session persistence, `database/db_operations.py` can be upgraded to an external managed PostgreSQL instance (e.g., Supabase, Neon, AWS RDS).

---

## 15. User Interface & Visual Design
- **Theme Palette**: Deep dark navy (`#0B0F19`), rich dark slate navy cards (`#131B2E`), cyan accent (`#00D2FF`), purple highlight (`#9333EA`).
- **Severity Color Coding**:
  - `CRITICAL`: Vibrant Red (`#FF4B4B`)
  - `HIGH`: Amber Orange (`#FFA500`)
  - `MEDIUM`: Warning Yellow (`#F4D03F`)
  - `LOW`: Cyan Blue (`#00D2FF`)

---

## 16. Future Enhancements
The codebase is architected with modular interfaces to facilitate future extensions:
- **Machine Learning Anomaly Detection**: Isolation Forests or autoencoders for zero-day behavioral baseline deviation.
- **Threat Intelligence Feed Ingestion**: Direct integration with AlienVault OTX, AbuseIPDB, and VirusTotal APIs.
- **Real-Time Streaming Telemetry**: Ingestion via Apache Kafka or WebSockets.
- **PostgreSQL Database Driver**: Seamless migration from SQLite to PostgreSQL.
- **Automated Webhook Alerts**: Push notifications to Slack, Microsoft Teams, or PagerDuty.

---

## 17. Academic Scope & Limitations
- **Educational Simulation**: Built for undergraduate academic demonstration of cybersecurity concepts.
- **Heuristic Indicators**: Threat detections indicate suspicious activity for triage; they do not constitute definitive proof of breach without analyst verification.
- **Advisory Only**: Does not execute autonomous operating system firewall or iptables commands.

---

## 18. License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
