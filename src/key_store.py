# src/key_store.py
import json, os

KEYS_FILE = "user_keys.json"
DEFAULTS = {"ABUSEIPDB_API_KEY": "", "VIRUSTOTAL_API_KEY": ""}


def load_keys():
    keys = dict(DEFAULTS)
    try:
        import config
        keys["ABUSEIPDB_API_KEY"] = getattr(config, "ABUSEIPDB_API_KEY", "") or keys["ABUSEIPDB_API_KEY"]
        keys["VIRUSTOTAL_API_KEY"] = getattr(config, "VIRUSTOTAL_API_KEY", "") or keys["VIRUSTOTAL_API_KEY"]
    except ImportError:
        pass
    if os.path.exists(KEYS_FILE):
        try:
            with open(KEYS_FILE, "r") as f:
                saved = json.load(f)
            for k, v in saved.items():
                if v:
                    keys[k] = v
        except Exception:
            pass
    return keys


def save_keys(new_keys):
    current = {}
    if os.path.exists(KEYS_FILE):
        try:
            with open(KEYS_FILE, "r") as f:
                current = json.load(f)
        except Exception:
            current = {}
    current.update({k: v for k, v in new_keys.items() if v is not None})
    with open(KEYS_FILE, "w") as f:
        json.dump(current, f, indent=2)
    return current