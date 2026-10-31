# ThreatGuard – Installation & Deployment Guide

## 1. System Requirements
- **Python**: Version 3.11 or higher (Python 3.11 - 3.13 tested)
- **Operating System**: macOS, Linux (Ubuntu/Debian/CentOS), or Windows 10/11
- **Disk Space**: ~250MB for dependencies and local SQLite database
- **Web Browser**: Chrome, Firefox, Safari, or Edge

---

## 2. Local Installation Steps

### Step 1: Clone or Navigate to the Repository
```bash
git clone https://github.com/your-username/ThreatGuard.git
cd ThreatGuard
```

### Step 2: Create a Python Virtual Environment
```bash
# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate

# Windows (Command Prompt)
python -m venv .venv
.venv\Scripts\activate.bat

# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Step 3: Install Required Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Environment Variables (Optional)
Copy the example environment configuration:
```bash
cp .env.example .env
```
Default parameters are pre-configured, so manual `.env` creation is optional for local development.

---

## 3. Running the Application
Launch the Streamlit web application:
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## 4. Default Credentials
During the first launch, ThreatGuard automatically provisions an initial administrator account:
- **Username**: `admin`
- **Password**: `Admin@ThreatGuard2026!`

You can also register a new **Analyst** or **Admin** profile directly from the **Register Analyst** tab on the login screen.

---

## 5. Running Automated Test Suite
ThreatGuard includes an automated Pytest test suite covering authentication, database CRUD operations, log parsing, detection rules, and incident tracking:
```bash
pytest -v
```
To run tests with code coverage:
```bash
pytest -v --tb=short
```

---

## 6. Deployment to Streamlit Community Cloud

### Step 1: Push Project to GitHub
1. Create a public or private repository on GitHub.
2. Initialize and push your repository:
   ```bash
   git init
   git add .
   git commit -m "Initial commit of ThreatGuard"
   git branch -M main
   git remote add origin https://github.com/<your-username>/ThreatGuard.git
   git push -u origin main
   ```

### Step 2: Connect Streamlit Community Cloud
1. Log in to [share.streamlit.io](https://share.streamlit.io/).
2. Click **New App**.
3. Select your repository (`<your-username>/ThreatGuard`), Branch (`main`), and Main file path (`app.py`).

### Step 3: Configure Cloud Secrets
In the Streamlit Cloud dashboard, navigate to **Settings > Secrets** and paste:
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

### Step 4: Deploy
Click **Deploy**. Streamlit Cloud will install `requirements.txt` and launch ThreatGuard.

> **Cloud Persistence Note**: On Streamlit Community Cloud, instances run inside stateless containers. Database state persists while the container is alive, but will reset upon container redeploy. For permanent production cloud hosting, configure `database/db_operations.py` to connect to a managed cloud database such as PostgreSQL (Supabase, Neon, AWS RDS).
