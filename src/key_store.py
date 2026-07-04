# src/key_store.py
# Secure key management:
# Priority order: Environment Variables > user_keys.json > empty
# NEVER hardcode API keys. NEVER commit user_keys.json.
import os
import json

_KEY_FILE = os.path.join(os.path.dirname(__file__), '..', 'user_keys.json')
_KEY_FILE = os.path.normpath(_KEY_FILE)


def load_keys() -> dict:
    """
    Load API keys. Priority:
    1. OS environment variables (production/Docker/CI)
    2. user_keys.json (local development, gitignored)
    3. Empty strings (app runs without keys — links only)
    """
    keys = {
        "ABUSEIPDB_API_KEY": "",
        "VIRUSTOTAL_API_KEY": "",
    }
    # Try local key file first (development)
    try:
        if os.path.exists(_KEY_FILE):
            with open(_KEY_FILE, 'r', encoding='utf-8') as f:
                stored = json.load(f)
            keys.update({k: v for k, v in stored.items() if v})
    except Exception:
        pass
    # Environment variables always override (production)
    for key in keys:
        env_val = os.environ.get(key, '').strip()
        if env_val:
            keys[key] = env_val
    return keys


def save_keys(new_keys: dict) -> None:
    """Save keys to local file only. Never put keys in environment during runtime."""
    try:
        existing = {}
        if os.path.exists(_KEY_FILE):
            with open(_KEY_FILE, 'r', encoding='utf-8') as f:
                existing = json.load(f)
        existing.update({k: v for k, v in new_keys.items() if v is not None})
        with open(_KEY_FILE, 'w', encoding='utf-8') as f:
            json.dump(existing, f, indent=2)
    except Exception as e:
        print(f"[!] Could not save keys: {e}")
