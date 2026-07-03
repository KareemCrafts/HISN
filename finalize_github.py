import webbrowser, time

YOUR_GITHUB_USERNAME = "KareemCrafts"  # ← change this if needed
REPO_NAME = "HISN"
BASE = f"https://github.com/{YOUR_GITHUB_USERNAME}/{REPO_NAME}"

print("=" * 56)
print("  HISN v1.0.0 — GitHub Release Checklist")
print("=" * 56)

steps = [
    ("Add topics to repo",
     f"{BASE}/topics"),
    ("Create v1.0.0 release",
     f"https://github.com/{YOUR_GITHUB_USERNAME}/{REPO_NAME}/releases/new"),
    ("View your repository",
     BASE),
]

topics_to_add = [
    "soc", "blue-team", "incident-response", "sigma", "mitre-attack",
    "cybersecurity", "dfir", "python", "flask", "ollama",
    "threat-intelligence", "malware-analysis", "phishing-detection"
]

print(f"\nYour repo: {BASE}")
print(f"\nTopics to add manually:")
print("  " + ", ".join(topics_to_add))
print("\nRelease notes to paste:")
print("""─────────────────────────────────────────────
## HISN v1.0.0 — Initial Public Release

HISN (Arabic: حصن — fortress) is a local-first SOC investigation platform.

### What's included
- 2,527 Sigma detection rules (SigmaHQ community ruleset)
- 21 custom baseline detection rules
- MITRE ATT&CK Enterprise matrix with real-time coverage heatmap
- Kill chain visualization per incident
- Hisn AI — Tier-3 analyst powered by Ollama + Llama 3.2 (fully offline)
- Email & phishing investigation (.eml, .msg, screenshot OCR)
- Document triage — PDF objects, VBA macro analysis, hash reputation
- Rule-based detection engine with compound scoring and minimum risk floors
- PDF incident reports and document analysis reports
- AbuseIPDB + VirusTotal optional live integrations
- BLACK SITE cyberpunk terminal UI

### Installation
```bash
git clone https://github.com/KareemCrafts/HISN.git
cd HISN
install.bat
dashboard.bat
```

### Requirements
- Python 3.10+
- Ollama (for AI features): `ollama pull llama3.2`

### Note
HISN is local-first by design. Your logs, emails, and investigation
data never leave your machine.
─────────────────────────────────────────────""")

print("\nOpening browser tabs in 3 seconds...")
time.sleep(3)

for label, url in steps:
    print(f"  Opening: {label}")
    webbrowser.open(url)
    time.sleep(1.5)

print("\nDone. Complete the steps in your browser.")
print(f"\nFinal URL: {BASE}")