import os as _os, sys as _sys
_SIGMA = _os.path.join(_os.path.dirname(__file__), "rules", "sigma")
_MITRE = _os.path.join(_os.path.dirname(__file__), "data", "enterprise-attack.json")
_sigma_ok = _os.path.isdir(_SIGMA) and len(_os.listdir(_SIGMA)) > 100
_mitre_ok = _os.path.isfile(_MITRE) and _os.path.getsize(_MITRE) > 10000
def _already_setup(): return _sigma_ok and _mitre_ok
if _already_setup():
    print("[+] HISN: detection data already present, skipping download.")
    _sys.exit(0)

# setup_data.py
# Downloads real MITRE ATT&CK STIX data and Sigma detection rules

import requests, os, json, zipfile, io

def main():
    # ─── 1. Download MITRE ATT&CK STIX Bundle ────────────────────────────
    print("[*] Downloading MITRE ATT&CK STIX data...")
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    r = requests.get(url)
    r.raise_for_status()
    os.makedirs("data", exist_ok=True)
    with open("data/enterprise-attack.json", "w", encoding="utf-8") as f:
        f.write(r.text)
    data = json.loads(r.text)
    techniques = [obj for obj in data["objects"] if obj.get("type") == "attack-pattern"]
    print(f"[+] MITRE: Loaded {len(techniques)} ATT&CK techniques")

    # ─── 2. Download Sigma Rules ──────────────────────────────────────────
    print("[*] Downloading Sigma rules (this may take a minute)...")
    sigma_url = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
    r = requests.get(sigma_url, allow_redirects=True)
    r.raise_for_status()
    print(f"[+] Downloaded {len(r.content) / 1024 / 1024:.1f} MB")

    z = zipfile.ZipFile(io.BytesIO(r.content))
    all_names = z.namelist()
    print(f"[+] Zip contains {len(all_names)} files")

    os.makedirs("rules/sigma", exist_ok=True)
    count = 0
    seen_names = set()

    for name in all_names:
        # Only extract actual Windows detection rules (not deprecated, not regression data)
        if not name.endswith(".yml"):
            continue
        if "regression_data" in name:
            continue
        if "/deprecated/" in name:
            continue

        # Must be a Windows rule
        is_windows = (
            "rules/windows/" in name or
            "rules-threat-hunting/windows/" in name
        )
        if not is_windows:
            continue

        # Flatten filename — add parent dir to avoid collisions
        parts = name.split("/")
        filename = parts[-1]

        # Handle duplicate filenames by prepending parent folder
        if filename in seen_names:
            if len(parts) >= 2:
                filename = f"{parts[-2]}_{filename}"
        seen_names.add(filename)

        target = os.path.join("rules", "sigma", filename)
        try:
            with open(target, "wb") as f:
                f.write(z.read(name))
            count += 1
        except Exception as e:
            print(f"  [!] Failed to write {filename}: {e}")
            continue

    print(f"[+] Sigma: Extracted {count} detection rules to rules/sigma/")
    print("[+] Setup complete.")

if __name__ == "__main__":
    main()
