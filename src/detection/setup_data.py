# setup_data.py
# Downloads real MITRE ATT&CK STIX data and Sigma detection rules

import requests, os, json, zipfile, io

# ─── 1. Download MITRE ATT&CK STIX Bundle ────────────────────────────────
print("[*] Downloading MITRE ATT&CK STIX data...")
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
r = requests.get(url)
os.makedirs("data", exist_ok=True)
with open("data/enterprise-attack.json", "w", encoding="utf-8") as f:
    f.write(r.text)
data = json.loads(r.text)
techniques = [obj for obj in data["objects"] if obj.get("type") == "attack-pattern"]
print(f"[+] Loaded {len(techniques)} ATT&CK techniques")

# ─── 2. Download Sigma Rules ─────────────────────────────────────────────
print("[*] Downloading Sigma rules...")
sigma_url = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
r = requests.get(sigma_url)
z = zipfile.ZipFile(io.BytesIO(r.content))

os.makedirs("rules/sigma", exist_ok=True)
count = 0
# Extract only Windows security rules
for name in z.namelist():
    if "/rules/windows/" in name and name.endswith(".yml"):
        # Flatten into rules/sigma/
        filename = name.split("/")[-1]
        target = f"rules/sigma/{filename}"
        if not os.path.exists(target):
            with open(target, "wb") as f:
                f.write(z.read(name))
            count += 1

print(f"[+] Extracted {count} Sigma rules to rules/sigma/")
print("[+] Setup complete.")