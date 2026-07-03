# src/enrichment/hash_lookup.py
import requests
from src.key_store import load_keys

_cache = {}


def check_hash_reputation(file_hash):
    if not file_hash:
        return None
    if file_hash in _cache:
        return _cache[file_hash]

    result = {
        "hash": file_hash, "mode": "no_key",
        "malicious": None, "suspicious": None, "total_engines": None,
        "file_names": [], "link": f"https://www.virustotal.com/gui/file/{file_hash}",
        "message": None,
    }

    api_key = load_keys().get("VIRUSTOTAL_API_KEY")
    if not api_key:
        result["message"] = "No API key configured — click through to check manually, free, no signup required."
        _cache[file_hash] = result
        return result

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": api_key},
            timeout=8,
        )
        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            result["mode"] = "live"
            result["malicious"] = stats.get("malicious", 0)
            result["suspicious"] = stats.get("suspicious", 0)
            result["total_engines"] = sum(stats.values()) if stats else 0
            result["file_names"] = attrs.get("names", [])[:3]
        elif resp.status_code == 404:
            result["mode"] = "not_found"
            result["message"] = "Not seen on VirusTotal before (no detections on record)"
        elif resp.status_code == 429:
            result["mode"] = "error"
            result["message"] = "VirusTotal rate limit reached (free tier: 4/min, ~500/day)"
        else:
            result["mode"] = "error"
            result["message"] = f"VirusTotal returned status {resp.status_code}"
    except Exception as e:
        result["mode"] = "error"
        result["message"] = f"Lookup failed: {e}"

    _cache[file_hash] = result
    return result