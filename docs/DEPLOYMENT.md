# HISN Deployment Guide

## Why HISN is Local-First

HISN is a forensic investigation tool. Its security model depends on data staying
on the analyst's machine. Uploading Windows event logs, memory dumps, or phishing
emails to a cloud service is a security risk.

This is the same reason Wireshark, Volatility, Autopsy, and similar tools
don't have cloud-hosted versions.

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
