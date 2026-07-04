<div align="center">

<img src="docs/screenshots/banner.png" alt="HISN Banner" width="100%"/>

<br/>

<img src="https://img.shields.io/badge/HISN-v1.0.0-7CFFB2?style=for-the-badge&labelColor=05070A&color=7CFFB2" />
<img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
<img src="https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask" />
<img src="https://img.shields.io/badge/Sigma-2527%20Rules-FF6B35?style=for-the-badge" />
<img src="https://img.shields.io/badge/Offline-100%25%20Local-7CFFB2?style=for-the-badge&labelColor=05070A" />
<img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" />

<h1>HISN — حصن</h1>
<h3>Unified Threat Investigation & Analytics Tool</h3>
<p><em>Everything your investigation needs. One workspace.</em></p>
<p><strong>100% local. Zero telemetry. No data leaves your machine.</strong></p>

</div>

---

## What is HISN?

**HISN** (Arabic: *حصن* — "fortress") is a professional-grade, offline-first
Security Operations Center platform for threat investigators, incident
responders, and blue teamers.

It ingests Windows Event Logs, runs **2,527 real Sigma rules** against them,
correlates alerts into prioritized cases, and presents everything in a
premium cyberpunk investigation dashboard — with a local AI analyst,
phishing email analysis, and document triage built in.

> **Designed for:** SOC analysts · Incident responders · DFIR professionals · Cybersecurity students · CTF competitors

---

## Screenshots

<table>
<tr>
<td><img src="docs/screenshots/dashboard.png" alt="Dashboard"/><br/><sub>Main Dashboard</sub></td>
<td><img src="docs/screenshots/incidents.png" alt="Incidents"/><br/><sub>Incident Investigation</sub></td>
</tr>
<tr>
<td><img src="docs/screenshots/phishing.png" alt="Phishing"/><br/><sub>Phishing Analysis</sub></td>
<td><img src="docs/screenshots/documents.png" alt="Documents"/><br/><sub>Document Triage</sub></td>
</tr>
<tr>
<td><img src="docs/screenshots/mitre.png" alt="MITRE ATT&CK"/><br/><sub>MITRE ATT&CK Heatmap</sub></td>
<td><img src="docs/screenshots/ai.png" alt="Hisn AI"/><br/><sub>Hisn AI Assistant</sub></td>
</tr>
</table>

---

## Features

### EVTX Investigation Engine
- Parse Windows Event Log files (`.evtx`)
- **2,527 Sigma rules** (SigmaHQ community ruleset) + 21 custom baseline rules
- Automatic alert correlation into prioritized incidents
- MITRE ATT&CK Enterprise matrix heatmap
- Per-incident kill chain, technique tagging, IOC extraction

### Hisn AI — Local Tier-3 Analyst
- Powered by **Ollama + Llama 3.2** (100% offline, no API keys required)
- Global case awareness — understands all loaded cases automatically
- KQL, Splunk SPL, Sigma rule generation
- Executive summaries, full analyst reports
- Draggable, resizable, session-persistent widget

### Email & Phishing Detection
- Analyze `.eml`, `.msg`, and screenshot files
- SPF / DKIM / DMARC authentication analysis
- Rule-based detection (15+ categories, compound scoring)
- Brand impersonation, URL analysis, attachment hashing
- MITRE ATT&CK mapping, IOC extraction, JSON export

### Document & File Triage
- PDF: `/JavaScript`, `/Launch`, `/AA` object detection
- Office: VBA macro analysis, dangerous API identification
- Compound scoring with minimum risk floors
- Hash reputation via VirusTotal (optional)

### Investigation Dashboard
- BLACK SITE cyberpunk terminal aesthetic
- Real-time threat level indicator (THREATCON)
- Severity heatmap by host
- Interactive shell (`~` key) with SOC-themed commands
- PDF incident report generation

---

## Architecture
┌─────────────────────────────────────────────────────┐
│                    Browser (HISN UI)                 │
│           Vanilla JS · CSS3 · No frameworks          │
└──────────────────────┬──────────────────────────────┘
│ HTTP
┌──────────────────────▼──────────────────────────────┐
│                  Flask Application                   │
│              src/dashboard/app.py                    │
├──────────────┬──────────────┬───────────────────────┤
│  Detection   │   Parsers    │    Enrichment          │
│  Engine      │   .evtx      │    AbuseIPDB           │
│  2527 Sigma  │   .eml/.msg  │    VirusTotal          │
│  + Baseline  │   Documents  │    (optional)          │
├──────────────┴──────────────┴───────────────────────┤
│          SQLite (local) · SQLAlchemy ORM             │
├─────────────────────────────────────────────────────┤
│         Ollama + Llama 3.2 (local AI engine)         │
│         Runs separately — optional for AI features   │
└─────────────────────────────────────────────────────┘
---

## Installation

### Prerequisites

| Tool | Version | Required | Notes |
|------|---------|----------|-------|
| Python | 3.10+ | ✅ Yes | Add to PATH during install |
| Ollama | Latest | Optional | For AI analyst features |
| Tesseract OCR | Latest | Optional | For screenshot email analysis |

### Windows (Quick Start)

```bash
git clone https://github.com/KareemCrafts/HISN.git
cd HISN
install.bat          # Sets up venv + installs deps + downloads Sigma rules
ollama pull llama3.2 # Optional: enables AI analyst features
dashboard.bat        # Launch → http://localhost:5000
```

### Linux / macOS

```bash
git clone https://github.com/KareemCrafts/HISN.git
cd HISN
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python setup_data.py          # Downloads Sigma rules + MITRE ATT&CK data
python -m src.dashboard.app   # → http://localhost:5000
```

---

## Configuration

All secrets and settings use environment variables. **No secrets are ever hardcoded.**

```bash
cp .env.example .env
# Edit .env with your values
```

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `FLASK_HOST` | `127.0.0.1` | No | Server host |
| `FLASK_PORT` | `5000` | No | Server port |
| `OLLAMA_URL` | `http://localhost:11434/api/generate` | No | Ollama endpoint |
| `OLLAMA_MODEL` | `llama3.2` | No | Ollama model |
| `ABUSEIPDB_API_KEY` | *(empty)* | No | Live IP reputation |
| `VIRUSTOTAL_API_KEY` | *(empty)* | No | Hash reputation |

> API keys can also be configured in the UI via the ⚙ button — stored in
> `user_keys.json` which is gitignored and never committed.

---

## Deployment

### Why HISN is Local-First

HISN is designed to keep your investigation data on your machine.
Uploading Windows event logs, memory dumps, or phishing emails to a
cloud server is a security risk. This is the same reason Wireshark,
Volatility, and Autopsy don't have public cloud versions.

### Option 1: Local Workstation (Recommended)
```bash
git clone https://github.com/KareemCrafts/HISN.git && cd HISN
install.bat && dashboard.bat
```

### Option 2: Team Server via Docker
```bash
docker-compose up -d
# Access at http://your-server:5000
# Only deploy on trusted internal networks
```

### Option 3: Railway.app (Cloud — without AI)
```bash
# 1. Fork this repository
# 2. Connect Railway to your fork: railway.app/new
# 3. Set environment variables in Railway dashboard
# 4. Deploy — Ollama AI unavailable in cloud, all other features work
```

### Option 4: Render.com (Cloud — without AI)
```bash
# render.yaml is included — connect Render to this repo
# Set ABUSEIPDB_API_KEY and VIRUSTOTAL_API_KEY as environment variables
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Web Framework | Python 3.11, Flask 3.x, Gunicorn |
| Detection | 2,527 Sigma rules, custom baseline engine |
| Threat Intel | MITRE ATT&CK Enterprise STIX/TAXII |
| AI Engine | Ollama + Llama 3.2 (local) |
| Database | SQLite via SQLAlchemy |
| Frontend | Vanilla JS, CSS3 (zero frameworks) |
| PDF Reports | ReportLab |
| Email Parsing | Python email stdlib, extract-msg |
| OCR | pytesseract (optional) |
| Env Management | python-dotenv |

---

## Project Structure
HISN/
├── src/
│   ├── dashboard/app.py        # Flask app, all routes, HTML template
│   ├── detection/
│   │   ├── engine.py           # Detection pipeline
│   │   ├── sigma_loader.py     # Sigma rule engine
│   │   └── hisn_engine.py      # Email/document detection engine
│   ├── parsers/email_parser.py # Email investigation
│   ├── correlation/            # Alert correlation
│   ├── triage/                 # AI + document triage
│   ├── enrichment/             # AbuseIPDB, VirusTotal
│   ├── reports/pdf_report.py   # Report generation
│   ├── database/models.py      # SQLAlchemy models
│   ├── ai_assistant.py         # Hisn AI backend
│   ├── key_store.py            # Secure key management
│   └── config.py               # Environment-variable config
├── rules/sigma/                # 2,527 Sigma rules (gitignored, downloaded)
├── data/                       # MITRE ATT&CK STIX (gitignored)
├── logs/samples/               # Sample .evtx attack files
├── docs/screenshots/           # Documentation images
├── .env.example                # Environment variable template
├── .gitignore                  # Comprehensive (secrets + data excluded)
├── Procfile                    # Railway/Render deployment
├── railway.toml                # Railway configuration
├── render.yaml                 # Render configuration
├── Dockerfile                  # Docker deployment
├── docker-compose.yml          # Docker Compose (HISN + Ollama)
├── requirements.txt            # Python dependencies
├── setup_data.py               # Download Sigma + MITRE data
├── install.bat                 # Windows quick installer
└── dashboard.bat               # Windows launcher
---

## Sample Data

| File | Attack Simulated | Key Detections |
|------|-----------------|----------------|
| `mimikatz.evtx` | Credential dumping | LSASS memory access (T1003.001) |
| `metasploit.evtx` | Framework exploitation | Multiple techniques |
| `brute-force.evtx` | SMB/RDP brute force | T1110, 10,000+ alerts |
| `UACME_59_Sysmon.evtx` | UAC bypass | T1548 |
| `new-user.evtx` | Account creation | T1136.001 |

---

## Security

- **Zero telemetry.** No tracking, analytics, or external calls except
  optional AbuseIPDB/VirusTotal requests you explicitly trigger.
- **API keys** stored in `user_keys.json` (gitignored) or environment variables.
- **Investigation data** (logs, emails, cases) never leaves your machine.
- Report vulnerabilities via [GitHub Security Advisories](https://github.com/KareemCrafts/HISN/security/advisories/new).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions welcome —
detection rules, parsers, UI polish, documentation.

## License

MIT License — see [LICENSE](LICENSE).

## Author

**Kareem Alshaer** — Cybersecurity student, Blue Team practitioner  
[GitHub](https://github.com/KareemCrafts) · [LinkedIn](https://linkedin.com/in/kareemalshaer)

---

<div align="center">
<sub>Built with precision for the Blue Team community · حصن — Fortress</sub>
</div>
