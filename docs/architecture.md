# ThreatGuard – System Architecture & Module Design

## 1. Architectural Overview
ThreatGuard adopts a decoupled, multi-layered architecture separating presentation, business logic, detection rules, and persistent storage.

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

## 2. Component Breakdown

### 2.1 Configuration Layer (`config/`)
- `settings.py`: Central repository for base file paths, upload boundaries (25MB limit, `.csv`, `.json`), detection thresholds, severity tiers, and environment variable/secrets loaders.

### 2.2 Security & Authentication (`authentication/`)
- `password_utils.py`: Password hashing with `bcrypt` (12 rounds) and cryptographic verification. Policy validator enforcing length, casing, digits, and special characters.
- `auth.py`: Session management, state initialization, login verification, user registration, and page access enforcement (`enforce_authentication()`, `enforce_admin()`).

### 2.3 Database Management (`database/`)
- `db_connection.py`: Thread-safe context manager enforcing SQLite foreign keys (`PRAGMA foreign_keys = ON;`) and `sqlite3.Row` dictionary mapping.
- `db_setup.py`: Schema DDL scripts for 5 tables (`users`, `security_logs`, `incidents`, `detection_events`, `incident_notes`), performance indexes, and initial admin user bootstrap.
- `db_operations.py`: Fully parameterized SQL queries covering CRUD operations, deduplication queries, and SOC analytical metric aggregations.

### 2.4 Log Ingestion & Validation (`log_processing/`)
- `log_validator.py`: Path traversal sanitization, file extension checking, file size verification, column alias normalization, and IP format audits.
- `log_parser.py`: Robust CSV reader with automatic delimiter sniffing and JSON/NDJSON object tree parser.
- `log_analyzer.py`: Telemetry aggregations, time-window evaluation, and client-side multi-parameter filtering.

### 2.5 Threat Detection Engine (`detection/`)
- `risk_scoring.py`: Mathematical heuristic risk calculation bounding scores to [0, 100].
- `threat_classifier.py`: Severity classification (CRITICAL, HIGH, MEDIUM, LOW) and MITRE ATT&CK mapping.
- `detection_rules.py`: Modular rule classes implementing the SIEM signature evaluation interface.
- `detection_engine.py`: Batch evaluation engine with incident deduplication logic.

### 2.6 Incident Response (`incident_response/`)
- `response_recommendations.py`: Structured defensive playbooks detailing immediate actions, hardening steps, and investigative questions.
- `incident_manager.py`: Workflow status updates, analyst assignments, and audit logging.
- `incident_history.py`: Resolution metrics and MTTR calculations.

### 2.7 Visualization & Reporting (`dashboard/`, `utils/`)
- `charts.py`: Plotly Express and Graph Objects styled with high-contrast SOC dark navy aesthetics.
- `export_utils.py`: CSV generation and ReportLab executive PDF compiler.
