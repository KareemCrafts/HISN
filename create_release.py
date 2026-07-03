import os, subprocess, sys

ROOT = os.getcwd()

def write(path, content):
    full = os.path.join(ROOT, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, 'w', encoding='utf-8', newline='\n') as f:
        f.write(content)
    print(f"  wrote: {path}")

# ══════════════════════════════════════════════════════════════════
# README.md
# ══════════════════════════════════════════════════════════════════
write('README.md', r'''<div align="center">

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
''')

# ══════════════════════════════════════════════════════════════════
# LICENSE
# ══════════════════════════════════════════════════════════════════
write('LICENSE', '''MIT License

Copyright (c) 2026 Kareem Alshaer

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
''')

# ══════════════════════════════════════════════════════════════════
# .gitignore
# ══════════════════════════════════════════════════════════════════
write('.gitignore', '''# ── Python ──────────────────────────────────────────
__pycache__/
*.py[cod]
*$py.class
*.so
*.egg
*.egg-info/
dist/
build/
.eggs/
.Python
env/
venv/
.venv/
pip-wheel-metadata/

# ── Virtual Environments ─────────────────────────────
venv/
.venv/
env/
.env/

# ── HISN Sensitive Data (NEVER commit) ──────────────
user_keys.json
soc_copilot.db
hisn.db
*.db
uploads_web/
uploads_docs/
uploads/

# ── HISN Detection Data (large, downloaded on setup) ─
data/enterprise-attack.json
rules/sigma/

# ── Reports & Investigation Output ──────────────────
reports/
*.pdf

# ── Logs (processed) ─────────────────────────────────
logs/*.evtx
!logs/samples/

# ── Environment & Secrets ────────────────────────────
.env
.env.local
.env.production
*.key
*.pem
secrets.json

# ── IDEs ─────────────────────────────────────────────
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store
Thumbs.db

# ── Testing ──────────────────────────────────────────
.pytest_cache/
.coverage
htmlcov/
.tox/

# ── Processed files ──────────────────────────────────
processed_files.json

# ── OS ───────────────────────────────────────────────
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# ── Node (if any tooling added later) ────────────────
node_modules/
npm-debug.log*
.npm

# ── Docker ───────────────────────────────────────────
.dockerignore
''')

# ══════════════════════════════════════════════════════════════════
# requirements.txt (clean, pinned for reproducibility)
# ══════════════════════════════════════════════════════════════════
write('requirements.txt', '''# HISN v1.0.0 — Python Dependencies
# Install: pip install -r requirements.txt

# ── Web Framework ─────────────────────────────────────
Flask==3.1.3
Werkzeug==3.1.3

# ── Database ──────────────────────────────────────────
SQLAlchemy==2.0.49

# ── Event Log Parsing ─────────────────────────────────
python-evtx==0.8.1

# ── Detection & Intelligence ──────────────────────────
PyYAML==6.0.3

# ── HTTP Client ───────────────────────────────────────
requests==2.34.2

# ── PDF Reports ───────────────────────────────────────
reportlab==4.2.5

# ── Email Analysis ────────────────────────────────────
extract-msg==0.52.0
Pillow==11.1.0

# ── OCR (optional — screenshot email analysis) ────────
# pytesseract==0.3.13
# Install Tesseract separately: winget install UB-Mannheim.TesseractOCR
''')

# ══════════════════════════════════════════════════════════════════
# Dockerfile
# ══════════════════════════════════════════════════════════════════
write('Dockerfile', '''# HISN v1.0.0 — Docker Image
# For self-hosting on internal networks only.
# Build: docker build -t hisn .
# Run:   docker run -p 5000:5000 -v $(pwd)/data:/app/data hisn

FROM python:3.11-slim

LABEL maintainer="Kareem Alshaer"
LABEL description="HISN — Unified Threat Investigation & Analytics Tool"
LABEL version="1.0.0"

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \\
    gcc \\
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY src/ ./src/
COPY setup_data.py .
COPY run_all.py .

# Download detection data
RUN python setup_data.py

# Create required directories
RUN mkdir -p uploads_web uploads_docs logs/samples data reports

# Non-root user for security
RUN useradd -m -u 1000 hisn && chown -R hisn:hisn /app
USER hisn

EXPOSE 5000

ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "src.dashboard.app"]
''')

# ══════════════════════════════════════════════════════════════════
# docker-compose.yml
# ══════════════════════════════════════════════════════════════════
write('docker-compose.yml', '''# HISN v1.0.0 — Docker Compose
# Full stack with Ollama AI
# Usage: docker-compose up -d

version: "3.9"

services:
  hisn:
    build: .
    container_name: hisn
    ports:
      - "5000:5000"
    volumes:
      - ./data:/app/data
      - ./logs/samples:/app/logs/samples:ro
      - hisn_db:/app
    environment:
      - OLLAMA_URL=http://ollama:11434/api/generate
      - FLASK_ENV=production
    depends_on:
      - ollama
    restart: unless-stopped
    networks:
      - hisn_network

  ollama:
    image: ollama/ollama:latest
    container_name: hisn_ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama_models:/root/.ollama
    restart: unless-stopped
    networks:
      - hisn_network
    # For GPU acceleration, add:
    # deploy:
    #   resources:
    #     reservations:
    #       devices:
    #         - driver: nvidia
    #           count: 1
    #           capabilities: [gpu]

volumes:
  hisn_db:
  ollama_models:

networks:
  hisn_network:
    driver: bridge
''')

# ══════════════════════════════════════════════════════════════════
# .env.example
# ══════════════════════════════════════════════════════════════════
write('.env.example', '''# HISN Environment Configuration
# Copy to .env and fill in values (never commit .env)

# Optional: Threat Intelligence API Keys
# Configure in the app via Settings (⚙ button) instead of here.
# ABUSEIPDB_API_KEY=your_key_here
# VIRUSTOTAL_API_KEY=your_key_here

# Ollama Configuration (default: local)
# OLLAMA_URL=http://localhost:11434/api/generate
# OLLAMA_MODEL=llama3.2

# Flask Configuration
# FLASK_ENV=production
# FLASK_PORT=5000
''')

# ══════════════════════════════════════════════════════════════════
# docs/screenshots placeholder
# ══════════════════════════════════════════════════════════════════
os.makedirs('docs/screenshots', exist_ok=True)
write('docs/screenshots/.gitkeep', '')
write('docs/DEPLOYMENT.md', '''# HISN Deployment Guide

## Why HISN is Local-First

HISN is a forensic investigation tool. Its security model depends on data staying
on the analyst's machine. Uploading Windows event logs, memory dumps, or phishing
emails to a cloud service is a security risk.

This is the same reason Wireshark, Volatility, Autopsy, and similar tools
don\'t have cloud-hosted versions.

## Deployment Options

### Option 1: Local Workstation (Recommended for Analysts)
```bash
git clone https://github.com/KareemCrafts/HISN.git
cd HISN
install.bat
dashboard.bat
```

### Option 2: Team Server (Internal Network)
```bash
# Docker Compose — brings up HISN + Ollama
docker-compose up -d
# Access via http://your-server-ip:5000
```
> Only expose on trusted internal networks. Add a reverse proxy (nginx) with
> authentication before exposing to a wider audience.

### Option 3: SOC Workstation Image
Include HISN in your standard analyst workstation build. The `install.bat`
is fully scripted for unattended setup.

## NOT Recommended

- Public cloud hosting (Vercel, Netlify, etc.) — serverless cannot run Ollama,
  maintain SQLite state, or process large files within timeout limits.
- Public internet exposure without authentication — investigation data is sensitive.
''')

# ══════════════════════════════════════════════════════════════════
# SECURITY.md
# ══════════════════════════════════════════════════════════════════
write('SECURITY.md', '''# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Yes    |

## Reporting a Vulnerability

If you discover a security vulnerability in HISN, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Contact: [Create a private security advisory on GitHub](https://github.com/KareemCrafts/HISN/security/advisories/new)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We aim to respond within 48 hours and release a patch within 7 days for critical issues.

## Scope

- HISN web interface (localhost:5000)
- Detection engine logic
- File parsing modules
- API integrations

## Out of Scope

- Ollama/LLM model vulnerabilities (report to Ollama project)
- Sigma rule logic (report to SigmaHQ)
- Issues requiring physical access to the machine
''')

# ══════════════════════════════════════════════════════════════════
# CONTRIBUTING.md
# ══════════════════════════════════════════════════════════════════
write('CONTRIBUTING.md', '''# Contributing to HISN

Thank you for your interest in contributing to HISN.

## Ways to Contribute

- 🐛 **Bug Reports** — Open an issue with reproduction steps
- 💡 **Feature Requests** — Open a discussion first
- 🔧 **Pull Requests** — See guidelines below
- 📖 **Documentation** — Always welcome
- 🎯 **Detection Rules** — New Sigma rules or baseline rules

## Pull Request Guidelines

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes with clear commit messages
4. Test locally with at least one sample .evtx file
5. Ensure no Python exceptions on startup
6. Open a PR with a clear description

## Detection Rule Contributions

New baseline rules go in `src/detection/engine.py` → `BASELINE_RULES`.
They need:
- `rule_name`: descriptive string
- `event_id`: Windows Event ID (integer or string)
- `mitre_technique_id`: MITRE technique (e.g., "T1059.001")
- `mitre_technique_name`: Full technique name
- `mitre_tactic`: MITRE tactic
- `severity`: critical/high/medium/low/informational
- `confidence`: 0.0–1.0

## Code Style

- Python: follow PEP 8, type hints where practical
- JS: vanilla only (no frameworks), preserve the BLACK SITE aesthetic
- No external CSS/JS CDNs (except Google Fonts)
''')

print("\nAll project files created.")
print("\n" + "=" * 56)
print("  NEXT STEPS — Manual actions required:")
print("=" * 56)
print("""
STEP 1: Take screenshots of HISN and save to docs/screenshots/
  - dashboard.png     (main dashboard with incidents loaded)
  - incidents.png     (incident case view)
  - phishing.png      (phishing analysis tab)
  - documents.png     (document triage tab)
  - ai.png            (AI assistant open)
  - mitre.png         (MITRE ATT&CK matrix)

STEP 2: Initialize Git and push to GitHub
  Run the commands below (or run push_to_github.py after
  setting your GitHub token):

  cd C:\\Projects\\SOC-Copilot
  git init
  git add .
  git commit -m "feat: HISN v1.0.0 — initial public release"

  # Create repo on GitHub first (github.com → New repository → HISN)
  # Then:
  git remote add origin https://github.com/YOUR_USERNAME/HISN.git
  git branch -M main
  git push -u origin main

STEP 3: On GitHub, set:
  - Description: "Unified Threat Investigation & Analytics Tool"
  - Topics: soc, blue-team, incident-response, sigma, mitre-attack,
            cybersecurity, dfir, python, flask, ollama
  - Add MIT license badge
  - Mark as public

STEP 4: Create a GitHub Release
  - Tag: v1.0.0
  - Title: "HISN v1.0.0 — Initial Public Release"
  - Include the key features in the release notes

WHY NOT VERCEL:
  HISN is a local-first security tool. Deploying to serverless cloud
  infrastructure would break Ollama AI, SQLite persistence, background
  processing, and most importantly the security model that keeps your
  investigation data on your own machine.
  
  The GitHub repo IS the deployment. Analysts clone it and run locally.
  For team use, use docker-compose on an internal server.
""")