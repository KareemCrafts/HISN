# src/enrichment/ip_lookup.py
import ipaddress
import requests

try:
    from config import ABUSEIPDB_API_KEY
except ImportError:
    ABUSEIPDB_API_KEY = None

_cache = {}


def check_ip_reputation(ip):
    if not ip:
        return None
    if ip in _cache:
        return _cache[ip]

    result = {
        "ip": ip, "internal": False, "mode": "no_key",
        "abuse_score": None, "country": None, "isp": None,
        "total_reports": None, "link": f"https://www.abuseipdb.com/check/{ip}",
        "message": None,
    }

    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            result["internal"] = True
            result["mode"] = "internal"
            _cache[ip] = result
            return result
    except ValueError:
        result["mode"] = "error"
        result["message"] = "Invalid IP format"
        _cache[ip] = result
        return result

    if not ABUSEIPDB_API_KEY:
        result["message"] = "No API key configured — click through to check manually, free, no signup required."
        _cache[ip] = result
        return result

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            result["mode"] = "live"
            result["abuse_score"] = data.get("abuseConfidenceScore")
            result["country"] = data.get("countryCode")
            result["isp"] = data.get("isp")
            result["total_reports"] = data.get("totalReports")
        elif resp.status_code == 429:
            result["mode"] = "error"
            result["message"] = "AbuseIPDB daily rate limit reached"
        else:
            result["mode"] = "error"
            result["message"] = f"AbuseIPDB returned status {resp.status_code}"
    except Exception as e:
        result["mode"] = "error"
        result["message"] = f"Lookup failed: {e}"

    _cache[ip] = result
    return result