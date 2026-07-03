<div align="center">

<img src="https://img.shields.io/badge/HISN-v1.0.0-7CFFB2?style=for-the-badge&labelColor=05070A&color=7CFFB2" />
<img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" />
<img src="https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white" />
<img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" />
<img src="https://img.shields.io/badge/Offline-100%25%20Local-7CFFB2?style=for-the-badge&labelColor=05070A" />

<br/><br/>

# HISN — حصن
### Unified Threat Investigation & Analytics Tool

**Your entire investigation, all in one place.**

*Everything runs locally. No data ever leaves your machine.*

<br/>

![HISN Dashboard](docs/screenshots/dashboard.png)

</div>

---

## Overview

HISN (Arabic: حصن — *fortress*) is a professional-grade, offline-first Security Operations Center platform built for threat investigators, incident responders, and blue teamers.

It ingests raw Windows event logs (`.evtx`), runs **2,527 real Sigma detection rules** and a custom baseline engine against them, correlates alerts into prioritized incidents, and presents everything in a premium cyberpunk investigation dashboard — with a local AI analyst, phishing email analysis, and document triage built in.

> **Designed for:** SOC analysts, incident responders, DFIR professionals, cybersecurity students, and CTF competitors.

---

## Key Features

### 🔍 EVTX Investigation
- Parse and analyze Windows Event Log files (`.evtx`)
- **2,527 Sigma rules** (SigmaHQ community ruleset) + 21 custom baseline rules
- Automatic alert correlation into prioritized incident cases
- MITRE ATT&CK matrix heatmap with real-time coverage visualization
- Per-incident kill chain mapping, MITRE technique tagging, remediation playbook

### 🤖 Hisn AI — Local Tier-3 Analyst
- Powered by **Ollama + Llama 3.2** (fully offline, no API keys)
- Global case awareness — AI understands all loaded cases without manual selection
- Preset prompts: Summarize, Explain Alert, False Positive Analysis, Next Steps, KQL, Splunk SPL, Sigma Rule generation, Executive Summary, Full Analyst Report
- Persistent chat across sessions (sessionStorage)
- Draggable, resizable floating widget

### 📧 Email & Phishing Investigation
- Analyze `.eml`, `.msg`, and screenshot files
- Full SPF / DKIM / DMARC authentication analysis
- Rule-based detection engine (15+ detection categories)
- Brand impersonation detection, URL analysis, attachment hashing
- MITRE ATT&CK mapping, IOC extraction, JSON export
- Scored risk assessment with transparent formula

### 📄 Document & File Triage
- Static analysis of PDF, Word, Excel, PowerPoint files
- VBA macro detection with dangerous API identification
- PDF object scanning (`/JavaScript`, `/Launch`, `/AA`, etc.)
- Embedded URL/IP extraction, VirusTotal hash reputation (optional API key)
- Rule-based detection engine with compound scoring

### 🖥️ Investigation Dashboard
- BLACK SITE cyberpunk terminal aesthetic
- Matrix rain background, glitch text, radar dropzone
- Severity heatmap (top hosts by alert volume)
- Real-time threat level indicator (THREATCON)
- Interactive shell (`~` key) with SOC-themed commands
- Persistent AI callout and context awareness

---

## Screenshots

| Dashboard | Incident Investigation |
|-----------|----------------------|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Incidents](docs/screenshots/incidents.png) |

| Phishing Analysis | Document Triage |
|-------------------|----------------|
| ![Phishing](docs/screenshots/phishing.png) | ![Documents](docs/screenshots/documents.png) |

| HISN AI | MITRE ATT&CK |
|---------|--------------|
| ![AI](docs/screenshots/ai.png) | ![MITRE](docs/screenshots/mitre.png) |

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.10+, Flask 3.x |
| Detection Engine | 2,527 Sigma rules (SigmaHQ), custom baseline engine |
| Threat Intel | MITRE ATT&CK Enterprise (STIX/TAXII) |
| AI Engine | Ollama + Llama 3.2 (local, offline) |
| Database | SQLite (via SQLAlchemy) |
| Frontend | Vanilla JS, CSS3 (no framework) |
| PDF Reports | ReportLab |
| Email Parsing | Python email, extract-msg |
| OCR | pytesseract (optional, for screenshot analysis) |

---

## Installation

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | [python.org](https://python.org) — check "Add to PATH" |
| Ollama | Latest | [ollama.com](https://ollama.com/download) — for AI features |
| Tesseract OCR | Latest | Optional — for screenshot email analysis |

### Quick Start (Windows)

```bash
# 1. Clone the repository
git clone https://github.com/KareemCrafts/HISN.git
cd HISN

# 2. Install (creates venv, installs dependencies, downloads Sigma + MITRE data)
install.bat

# 3. Pull the AI model (one-time, ~2GB)
ollama pull llama3.2

# 4. Launch HISN
dashboard.bat
# Opens http://localhost:5000
```

### Manual Setup (all platforms)

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
.\venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt

# Download detection data (Sigma rules + MITRE ATT&CK)
python setup_data.py

# Launch
python -m src.dashboard.app
```

---

## Local Development

```bash
# Activate environment
.\venv\Scripts\activate

# Run with auto-reload (development)
python -m src.dashboard.app

# Run full analysis pipeline (CLI)
python run_all.py path\to\Security.evtx

# Reset database
python reset_incidents.py
```

### Project Structure
HISN/
├── src/
│   ├── dashboard/
│   │   └── app.py              # Flask app + all routes + TEMPLATE HTML
│   ├── detection/
│   │   ├── engine.py           # Detection pipeline (baseline + Sigma)
│   │   ├── sigma_loader.py     # Sigma rule parser & matcher
│   │   └── hisn_engine.py      # Rule-based email/document engine
│   ├── parsers/
│   │   └── email_parser.py     # .eml / .msg / screenshot parser
│   ├── correlation/
│   │   └── correlator.py       # Alert → incident correlation
│   ├── triage/
│   │   ├── llm_triage.py       # Ollama AI triage
│   │   └── document_scanner.py # Document static analysis
│   ├── enrichment/
│   │   ├── ip_lookup.py        # AbuseIPDB integration
│   │   └── hash_lookup.py      # VirusTotal integration
│   ├── reports/
│   │   └── pdf_report.py       # ReportLab PDF generation
│   ├── database/
│   │   └── models.py           # SQLAlchemy models
│   └── ai_assistant.py         # Hisn AI backend
├── rules/
│   └── sigma/                  # 2,527 Sigma detection rules
├── data/
│   └── enterprise-attack.json  # MITRE ATT&CK STIX data
├── logs/
│   └── samples/                # Sample .evtx files for demo
├── docs/
│   └── screenshots/            # Documentation screenshots
├── requirements.txt
├── setup_data.py               # Downloads Sigma + MITRE data
├── dashboard.bat               # Windows quick-launch
├── install.bat                 # Windows installer
├── Dockerfile                  # Docker deployment
├── docker-compose.yml          # Docker Compose (with Ollama)
└── README.md
---

## Self-Hosting with Docker

HISN includes full Docker support for team deployments on internal networks.

```bash
# Full stack with Ollama AI (recommended)
docker-compose up -d

# HISN only (no AI features)
docker build -t hisn .
docker run -p 5000:5000 hisn
```

> ⚠️ **Important:** Even when self-hosting, treat uploaded logs as sensitive. Deploy only on trusted internal networks. Never expose to the public internet without proper authentication.

### docker-compose.yml
```yaml
# See docker-compose.yml in the repository root
```

---

## Optional API Keys

HISN works fully without any API keys. Keys unlock live threat intelligence:

| Service | Feature | Get Key |
|---------|---------|---------|
| AbuseIPDB | Live IP reputation scores | [abuseipdb.com](https://abuseipdb.com) |
| VirusTotal | File hash reputation | [virustotal.com](https://virustotal.com) |

Configure via the ⚙ button in the top-right corner. Keys are stored locally in `user_keys.json` (gitignored).

---

## Roadmap

### v1.1
- [ ] Timeline view (chronological event sequence per incident)
- [ ] Process tree visualization (Sysmon EID 1 parent-child)
- [ ] Case management (status, assignee, priority fields)
- [ ] WHOIS/domain age in phishing module
- [ ] Typosquatting detection

### v1.2
- [ ] IOC pivoting (click IP/hash → all related cases)
- [ ] False positive suppression (mark noise, suppress future)
- [ ] Custom Sigma rule editor
- [ ] Event correlation graph (Sentinel-style node graph)

### v2.0
- [ ] Multi-user support with case assignment
- [ ] STIX/TAXII threat feed integration
- [ ] Elastic Stack / Splunk export
- [ ] Automated containment playbooks
- [ ] Plugin system for custom detection modules

---

## Sample Data

The `logs/samples/` directory includes real-world attack simulation logs:

| File | Simulates |
|------|-----------|
| `mimikatz.evtx` | Credential dumping (LSASS access) |
| `metasploit.evtx` | Metasploit framework exploitation |
| `brute-force.evtx` | SMB / RDP brute-force attack |
| `UACME_59_Sysmon.evtx` | UAC bypass technique |
| `new-user.evtx` | Unauthorized account creation |

Click **Load Demo Analysis** on the dashboard to analyze these instantly.

---

## Privacy & Security

- **100% offline by design.** No telemetry, no analytics, no external calls except optional AbuseIPDB/VirusTotal lookups you explicitly trigger.
- The AI model (Llama 3.2) runs entirely on your machine via Ollama.
- Logs, cases, and investigation data never leave your system.
- User API keys are stored in `user_keys.json` (excluded from git).

---

## Disclaimer

HISN is intended for **legitimate security research, incident response, and educational purposes only**.

- Only analyze logs and files you own or have explicit authorization to investigate.
- Do not use HISN to analyze data belonging to others without written permission.
- The authors are not responsible for misuse of this tool.
- All sample log files are from authorized penetration testing environments.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**Kareem Alshaer** — Cybersecurity student, Blue Team practitioner  
[GitHub](https://github.com/KareemCrafts) · [LinkedIn](https://linkedin.com/in/kareemalshaer)

---

<div align="center">
<sub>Built with ♥ for the Blue Team community</sub><br/>
<sub>حصن — Fortress</sub>
</div>
