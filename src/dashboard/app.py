# src/dashboard/app.py
import os, threading, time, json
try:
    from dotenv import load_dotenv
    load_dotenv()  # loads .env in development; no-op in production
except ImportError:
    pass
import yaml
from urllib.parse import quote
from flask import Flask, render_template_string, request, jsonify, Response
from werkzeug.utils import secure_filename
from sqlalchemy.orm import Session
from collections import defaultdict
from src.database.models import init_db, Alert, Incident
from src.enrichment.ip_lookup import check_ip_reputation
from src.triage.document_scanner import scan_document
from src.detection.sigma_loader import SigmaEngine
from src.detection.engine import BASELINE_RULES
from src.key_store import load_keys, save_keys
from src.ai_assistant import ask_ai, PRESET_PROMPTS

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024  # 512 MB max upload
UPLOAD_DIR = "uploads_web"
os.makedirs(UPLOAD_DIR, exist_ok=True)
DOC_UPLOAD_DIR = "uploads_docs"
os.makedirs(DOC_UPLOAD_DIR, exist_ok=True)

HISN_VERSION = "1.0.0"

JOB = {"running": False, "stage": "", "done": False, "error": None}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
SEVERITY_COLOR = {
    "critical": "#E0483E", "high": "#E2602E", "medium": "#D9B44A",
    "low": "#4C8BA8", "informational": "#6B7280",
}

STAGE_DEFS = [
    ("Initial Access", ["initial-access"]), ("Persistence", ["persistence"]),
    ("Priv Esc", ["privilege-escalation"]),
    ("Defense Evasion", ["defense-impairment", "defense-evasion", "stealth"]),
    ("Cred Access", ["credential-access"]), ("Discovery", ["discovery"]),
    ("Lateral Move", ["lateral-movement"]), ("Collection", ["collection"]),
    ("C2", ["command-and-control"]), ("Impact", ["impact"]),
]

MATRIX = [
    ("Initial Access", ["T1078", "T1190", "T1133", "T1566"]),
    ("Execution", ["T1059", "T1059.001", "T1047", "T1053", "T1204", "T1218", "T1569"]),
    ("Persistence", ["T1098", "T1136", "T1136.001", "T1543", "T1543.003", "T1547", "T1547.001", "T1053.005"]),
    ("Priv Esc", ["T1068", "T1134", "T1134.001", "T1484", "T1548"]),
    ("Defense Evasion", ["T1055", "T1070", "T1070.001", "T1070.006", "T1112", "T1562", "T1685", "T1685.005"]),
    ("Cred Access", ["T1003", "T1003.001", "T1003.002", "T1110", "T1558", "T1558.003", "T1552"]),
    ("Discovery", ["T1087", "T1018", "T1046", "T1082", "T1083", "T1135"]),
    ("Lateral Move", ["T1021", "T1021.002", "T1550", "T1550.002", "T1570"]),
    ("Collection", ["T1005", "T1039", "T1056", "T1113", "T1114"]),
    ("C2", ["T1071", "T1090", "T1095", "T1105", "T1219"]),
    ("Impact", ["T1486", "T1489", "T1490", "T1531", "T1485"]),
]

REMEDIATION = {
    "T1078": {"category": "Harden", "steps": ["Enforce MFA on all accounts, especially privileged ones.", "Regularly audit and disable unused or default accounts."]},
    "T1190": {"category": "Harden", "steps": ["Patch internet-facing applications and services promptly.", "Deploy a WAF in front of public web applications."]},
    "T1133": {"category": "Isolate", "steps": ["Require MFA on all VPN and remote access services.", "Restrict remote access to known IP ranges where possible."]},
    "T1566": {"category": "Harden", "steps": ["Enable email attachment/link sandboxing and filtering.", "Run regular phishing-awareness training for staff."]},
    "T1059": {"category": "Detect", "steps": ["Enable script-block logging; alert on encoded/obfuscated commands.", "Restrict script execution policy to signed scripts only."]},
    "T1059.001": {"category": "Detect", "steps": ["Enable PowerShell transcription and Script Block Logging.", "Constrain PowerShell to Constrained Language Mode where possible."]},
    "T1053": {"category": "Detect", "steps": ["Audit scheduled task creation events (Event ID 4698).", "Restrict who can create scheduled tasks via group policy."]},
    "T1204": {"category": "Harden", "steps": ["Block execution of untrusted macros and script files by policy.", "Use application allowlisting to stop unknown executables."]},
    "T1569": {"category": "Detect", "steps": ["Monitor for unexpected new service creation (Event ID 7045).", "Restrict service creation rights to administrators only."]},
    "T1098": {"category": "Detect", "steps": ["Alert on changes to group membership or account permissions.", "Review privileged group membership changes regularly."]},
    "T1136": {"category": "Detect", "steps": ["Alert on new account creation outside change windows.", "Require an approval workflow for new account provisioning."]},
    "T1136.001": {"category": "Detect", "steps": ["Alert on new local account creation outside change windows.", "Require an approval workflow for new account provisioning."]},
    "T1543": {"category": "Detect", "steps": ["Monitor for new or modified services and unusual binaries.", "Apply least-privilege so only admins can install services."]},
    "T1547": {"category": "Detect", "steps": ["Monitor registry Run keys and startup folders for changes.", "Use application allowlisting to block unauthorized autostart entries."]},
    "T1053.005": {"category": "Detect", "steps": ["Audit scheduled task creation (Event ID 4698) for anomalies.", "Limit task creation rights to administrators."]},
    "T1068": {"category": "Harden", "steps": ["Patch promptly, prioritizing known-exploited privilege-escalation CVEs.", "Run vulnerability scans against common privilege-escalation paths."]},
    "T1134": {"category": "Detect", "steps": ["Monitor for token impersonation/duplication anomalies.", "Restrict 'Debug Programs' and 'Impersonate a client' rights."]},
    "T1134.001": {"category": "Detect", "steps": ["Monitor for token duplication anomalies.", "Restrict 'Debug Programs' and 'Impersonate a client' rights."]},
    "T1484": {"category": "Detect", "steps": ["Alert on GPO changes outside change-management windows.", "Restrict GPO edit rights to a small, audited admin group."]},
    "T1548": {"category": "Harden", "steps": ["Enable UAC at the highest enforcement level.", "Monitor for unsigned binaries requesting elevation."]},
    "T1070": {"category": "Detect", "steps": ["Forward logs to a SIEM in near-real-time so local clearing can't hide them.", "Alert immediately on log-clear events (1102 / 104)."]},
    "T1070.001": {"category": "Detect", "steps": ["Alert immediately on Security log clear (Event ID 1102).", "Forward logs off-host in real time."]},
    "T1070.006": {"category": "Detect", "steps": ["Monitor for system time changes (Event ID 4616).", "Use an external time source (NTP) and alert on drift/tampering."]},
    "T1112": {"category": "Detect", "steps": ["Monitor sensitive registry keys for unauthorized changes.", "Apply registry ACLs restricting write access to admins."]},
    "T1562": {"category": "Detect", "steps": ["Alert when AV/EDR/Defender is disabled or tampered with.", "Use tamper-protection features to block stopping security tooling."]},
    "T1685": {"category": "Detect", "steps": ["Treat audit-policy or logging changes as high-priority alerts.", "Forward logs off-host immediately so local tampering is preserved elsewhere."]},
    "T1685.005": {"category": "Detect", "steps": ["Alert immediately on any security/audit log clear event.", "Forward logs off-host in real time so clearing can't erase evidence."]},
    "T1003": {"category": "Harden", "steps": ["Enable Credential Guard and restrict LSASS access (RunAsPPL).", "Restrict and monitor use of debug privileges and dumping tools."]},
    "T1003.002": {"category": "Harden", "steps": ["Restrict and monitor SAM database access.", "Enable Credential Guard to prevent credential extraction."]},
    "T1110": {"category": "Harden", "steps": ["Enforce account lockout policy and strong password requirements.", "Require MFA so password guesses alone can't succeed."]},
    "T1558": {"category": "Harden", "steps": ["Use long, randomized service account passwords or gMSAs.", "Monitor for abnormal volumes of Kerberos ticket requests."]},
    "T1558.003": {"category": "Harden", "steps": ["Use long, randomized service account passwords or gMSAs.", "Monitor for abnormal TGS request volume (Event ID 4769)."]},
    "T1552": {"category": "Harden", "steps": ["Scan repositories/shares for hardcoded credentials or secrets.", "Move secrets into a managed vault instead of config files."]},
    "T1087": {"category": "Detect", "steps": ["Baseline normal enumeration tools/accounts; alert on deviations.", "Monitor for high-volume account queries in short windows."]},
    "T1018": {"category": "Detect", "steps": ["Alert on unusual network sweeps or AD computer enumeration.", "Segment networks to limit visibility of unrelated systems."]},
    "T1046": {"category": "Detect", "steps": ["Monitor for port-scanning behavior from internal hosts.", "Restrict unnecessary internal network visibility via segmentation."]},
    "T1082": {"category": "Detect", "steps": ["Baseline normal use of recon commands; alert on scripted bursts.", "Limit local recon utilities via application control where feasible."]},
    "T1083": {"category": "Detect", "steps": ["Alert on rapid, broad directory enumeration consistent with scripted recon.", "Apply least-privilege shares so discovery yields little of value."]},
    "T1135": {"category": "Detect", "steps": ["Monitor for network share enumeration (Event ID 5140).", "Limit share visibility/permissions to only users who need them."]},
    "T1021": {"category": "Isolate", "steps": ["Restrict and monitor use of admin shares (C$, ADMIN$).", "Require MFA and logging for all remote logon protocols."]},
    "T1021.002": {"category": "Isolate", "steps": ["Restrict and monitor SMB admin share usage.", "Require MFA and logging on remote authentication."]},
    "T1550": {"category": "Harden", "steps": ["Enable Credential Guard and restrict NTLM where possible.", "Use unique local admin passwords per host (LAPS) to stop hash reuse."]},
    "T1550.002": {"category": "Harden", "steps": ["Use unique local admin passwords per host (LAPS) to stop pass-the-hash.", "Restrict NTLM authentication where Kerberos is viable."]},
    "T1570": {"category": "Detect", "steps": ["Alert on executable transfers between hosts via SMB/admin shares.", "Restrict write access to admin shares between workstations."]},
    "T1005": {"category": "Detect", "steps": ["Monitor for bulk file access/staging on sensitive systems.", "Apply DLP policies on sensitive file types."]},
    "T1039": {"category": "Detect", "steps": ["Monitor for bulk reads from sensitive network shares.", "Apply least-privilege share permissions and audit access."]},
    "T1056": {"category": "Detect", "steps": ["Scan endpoints for keylogging software or drivers.", "Use EDR behavioral detection for input-hooking processes."]},
    "T1113": {"category": "Detect", "steps": ["Monitor for screen-capture API calls from non-standard processes.", "Use EDR to flag screen-capture behavior on sensitive hosts."]},
    "T1114": {"category": "Detect", "steps": ["Monitor for mailbox export/forwarding rule changes.", "Alert on bulk mailbox access or unusual export activity."]},
    "T1071": {"category": "Detect", "steps": ["Inspect outbound HTTPS/DNS traffic for beaconing patterns.", "Use TLS inspection or proxy logging to spot anomalous traffic."]},
    "T1090": {"category": "Isolate", "steps": ["Monitor for unauthorized proxy/relay software on endpoints.", "Restrict outbound connections to approved proxies only."]},
    "T1095": {"category": "Isolate", "steps": ["Alert on raw/unusual protocol traffic on the network.", "Restrict outbound traffic with egress filtering by default."]},
    "T1105": {"category": "Detect", "steps": ["Alert on unexpected binary downloads via script interpreters.", "Restrict outbound traffic to known-good destinations (egress filtering)."]},
    "T1219": {"category": "Isolate", "steps": ["Inventory and alert on unauthorized remote-access tools.", "Block unapproved remote-access software via application control."]},
    "T1486": {"category": "Restore", "steps": ["Maintain offline, tested backups isolated from the network.", "Deploy EDR with ransomware behavior blocking enabled."]},
    "T1489": {"category": "Detect", "steps": ["Alert on critical service stoppage (backup agents, AV, etc).", "Restrict service-control rights to administrators only."]},
    "T1490": {"category": "Restore", "steps": ["Alert on shadow-copy deletion or vssadmin usage.", "Store backups offline/immutable so they can't be deleted by an attacker."]},
    "T1531": {"category": "Detect", "steps": ["Alert immediately on bulk password resets or account disabling.", "Maintain out-of-band admin access not dependent on the affected domain."]},
    "T1485": {"category": "Restore", "steps": ["Maintain immutable, offline backups for critical data.", "Alert on mass file deletion or wiping-utility usage."]},
    "T1003.001": {"category": "Harden", "steps": ["Enable LSASS Protected Process Light (RunAsPPL) and Credential Guard.", "Alert on any non-system process accessing lsass.exe (Sysmon Event ID 10)."]},
    "T1047": {"category": "Detect", "steps": ["Monitor for 'wmic process call create' and remote WMI execution.", "Restrict WMI remote access to administrators only."]},
    "T1055": {"category": "Detect", "steps": ["Monitor for CreateRemoteThread into unrelated processes (Sysmon Event ID 8).", "Use EDR with behavioral injection detection enabled."]},
    "T1218": {"category": "Detect", "steps": ["Monitor for mshta/regsvr32/rundll32 spawning network connections or loading remote scripts.", "Restrict or block these LOLBins via application control where not business-required."]},
    "T1547.001": {"category": "Detect", "steps": ["Monitor Run/RunOnce registry keys and Winlogon Shell/Userinit values for changes.", "Use application allowlisting to block unauthorized autostart entries."]},
    "T1543.003": {"category": "Detect", "steps": ["Monitor service ImagePath registry changes (Sysmon Event ID 13).", "Restrict who can create or modify services."]},
}

BASELINE_RULE_DESCRIPTIONS = {
    "Failed Logon Attempt": "Fires on a failed authentication attempt (Event ID 4625) — flags possible password guessing or mistyped credentials.",
    "Explicit Credential Use Over Network": "Fires when credentials are explicitly supplied for a network connection (Event ID 4648) — common in lateral movement.",
    "Network/Remote Logon": "Fires on a network or RDP-type logon from an external-looking source (Event ID 4624, types 3/10).",
    "Audit Log Cleared": "Fires when the Security or System event log is cleared (Event ID 1102) — a classic anti-forensics move.",
    "Sensitive Privilege Use": "Fires when a high-privilege right (e.g. SeDebugPrivilege) is used (Event ID 4673) — often precedes credential dumping.",
    "Kerberos Service Ticket Request": "Fires on a Kerberos TGS request (Event ID 4769) — high volume can indicate Kerberoasting.",
    "Scheduled Task Created": "Fires when a new scheduled task is created (Event ID 4698) — a common persistence mechanism.",
    "New Service Installed": "Fires when a new Windows service is installed (Event ID 7045) — can indicate persistence or lateral tooling.",
    "New User Account Created": "Fires when a new local or domain account is created (Event ID 4720).",
    "User Added to Privileged Group": "Fires when an account is added to a privileged group (Event ID 4732) — possible privilege escalation.",
    "Account Enumeration Detected": "Fires on account enumeration activity (Event ID 4798) — often benign background noise, but worth a baseline check.",
    "Group Enumeration Detected": "Fires on group enumeration activity (Event ID 4799) — usually benign, occasionally reconnaissance.",
    "Suspicious PowerShell Execution (Encoded Command)": "Fires when PowerShell is launched with an encoded/base64 command — a common obfuscation technique for malicious scripts.",
    "LOLBin Proxy Execution (mshta/regsvr32/rundll32)": "Fires when a trusted Windows binary (mshta, regsvr32, rundll32) is used to fetch or run remote/script content — a defense-evasion technique.",
    "Shadow Copy / Recovery Deletion": "Fires on commands that delete shadow copies or disable recovery — a strong ransomware indicator.",
    "Suspicious WMI Process Execution": "Fires when WMI is used to remotely launch a process — common in lateral movement.",
    "Process Injection (CreateRemoteThread)": "Fires when one process creates a thread inside another (Sysmon Event ID 8) — a classic code-injection technique.",
    "LSASS Memory Access (Possible Credential Dumping)": "Fires when a process accesses lsass.exe's memory (Sysmon Event ID 10) — the primary way attackers dump credentials.",
    "Registry Run Key Persistence": "Fires on changes to Run/RunOnce or Winlogon registry keys (Sysmon Event ID 13) — a common persistence mechanism.",
    "Service Registry Modification (Persistence)": "Fires when a service's ImagePath is modified in the registry (Sysmon Event ID 13) — can hijack an existing service for persistence.",
    "Suspicious File Drop (Temp/Downloads)": "Fires when an executable/script is written to a Temp or Downloads folder (Sysmon Event ID 11) — common malware staging behavior.",
}

# Single shared Sigma engine — avoids loading 2527 rules twice on first request
_sigma_engine_singleton = None
_sigma_descriptions_cache = None
_sigma_full_cache = None


def _get_sigma_engine():
    global _sigma_engine_singleton
    if _sigma_engine_singleton is None:
        try:
            _sigma_engine_singleton = SigmaEngine()
        except Exception:
            pass
    return _sigma_engine_singleton


def get_sigma_descriptions():
    global _sigma_descriptions_cache
    if _sigma_descriptions_cache is None:
        eng = _get_sigma_engine()
        _sigma_descriptions_cache = (
            {r.title: r.description for r in eng.rules if r.description}
            if eng else {}
        )
    return _sigma_descriptions_cache


_baseline_event_id_map = {r["rule_name"]: r["event_id"] for r in BASELINE_RULES}


def get_sigma_full_rules():
    global _sigma_full_cache
    if _sigma_full_cache is None:
        eng = _get_sigma_engine()
        _sigma_full_cache = (
            {r.title: r.detection for r in eng.rules}
            if eng else {}
        )
    return _sigma_full_cache


def get_rule_explanations(rule_names_str):
    names = [n.strip() for n in (rule_names_str or "").split(",") if n.strip()]
    sigma_desc = get_sigma_descriptions()
    sigma_logic = get_sigma_full_rules()
    out = []
    for name in names:
        desc = BASELINE_RULE_DESCRIPTIONS.get(name) or sigma_desc.get(name)
        logic = None
        if name in sigma_logic:
            try:
                logic = yaml.dump(sigma_logic[name], default_flow_style=False, sort_keys=False).strip()
            except Exception:
                logic = None
        elif name in _baseline_event_id_map:
            logic = f"Windows Event ID {_baseline_event_id_map[name]} (custom baseline rule)"
        sigmahq_link = f"https://github.com/search?q=repo%3ASigmaHQ%2Fsigma+%22{quote(name)}%22&type=code"
        out.append({"name": name, "description": desc or "No description available for this rule.",
                    "logic": logic, "sigmahq_link": sigmahq_link})
    return out


def build_chain(tactics_str):
    present = set(t.strip() for t in (tactics_str or "").split(",") if t.strip())
    return [(label, any(s in present for s in slugs)) for label, slugs in STAGE_DEFS]


def mitre_link(tech_id):
    if "." in tech_id:
        base, sub = tech_id.split(".", 1)
        return f"https://attack.mitre.org/techniques/{base}/{sub}/"
    return f"https://attack.mitre.org/techniques/{tech_id}/"


def d3fend_link(tech_id):
    return f"https://d3fend.mitre.org/offensive-technique/attack/{tech_id}/"


def atomic_link(tech_id):
    return f"https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/{tech_id}/{tech_id}.md"


def get_remediation(tech_str):
    techs = [t.strip() for t in (tech_str or "").split(",") if t.strip()]
    out = []
    for t in techs:
        info = REMEDIATION.get(t)
        steps = info["steps"] if info else [f"Consult MITRE ATT&CK's mitigation guidance for {t}."]
        category = info["category"] if info else "General"
        out.append({
            "id": t, "category": category, "steps": steps,
            "mitre_link": mitre_link(t), "d3fend_link": d3fend_link(t),
            "atomic_link": atomic_link(t),
        })
    return out


def get_incident_iocs(incident_alerts):
    ips, hashes, files = set(), set(), set()
    for a in incident_alerts:
        if a.source_ip:
            ips.add(a.source_ip)
        try:
            data = json.loads(a.raw_event) if a.raw_event else {}
        except Exception:
            data = {}
        for ip_field in ("IpAddress", "DestinationIp", "SourceIp"):
            v = data.get(ip_field)
            if v and v not in ("-", "::1", "127.0.0.1", ""):
                ips.add(v)
        hash_field = data.get("Hashes")
        if hash_field:
            for part in str(hash_field).split(","):
                if "=" in part:
                    algo, val = part.split("=", 1)
                    if algo.strip().upper() == "SHA256":
                        hashes.add(val.strip())
        for file_field in ("TargetFilename", "Image"):
            v = data.get(file_field)
            if v:
                files.add(v)
    return {"ips": sorted(ips), "hashes": sorted(hashes), "files": sorted(files)}


def get_raw_events(incident_alerts, limit=5):
    total = len(incident_alerts)
    events = []
    for a in incident_alerts[:limit]:
        try:
            parsed = json.loads(a.raw_event) if a.raw_event else {}
            pretty = json.dumps(parsed, indent=2)
        except Exception:
            pretty = a.raw_event or "{}"
        events.append({
            "event_id": a.event_id, "timestamp": str(a.timestamp),
            "rule": a.rule_name, "raw": pretty,
        })
    return {"events": events, "total": total, "shown": len(events)}


def get_host_stats(alerts):
    counts = defaultdict(int)
    for a in alerts:
        counts[a.host or "UNKNOWN"] += 1
    if not counts:
        return []
    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:8]
    max_count = ranked[0][1] if ranked else 1
    return [{"host": h, "count": c, "pct": round((c / max_count) * 100)} for h, c in ranked]


def run_pipeline_job(filepath, demo_mode=False):
    global JOB
    try:
        from src.parsers.evtx_parser import parse_evtx
        from src.detection.engine import run_engine
        from src.correlation.correlator import correlate

        JOB.update(stage="Parsing log file...", running=True, done=False, error=None)
        events = parse_evtx(filepath)

        # Fast demo mode: cap at 1500 events (still shows all technique patterns)
        if demo_mode and len(events) > 500:
            events = events[:500]
            JOB.update(stage=f"Demo mode: analyzing 500 events (fast)...")
        else:
            JOB.update(stage=f"Running detection on {len(events)} events...")
        alerts = run_engine(events)

        JOB.update(stage=f"Saving {len(alerts)} alerts...")
        from datetime import datetime
        def parse_ts(ts):
            try: return datetime.fromisoformat(str(ts))
            except Exception: return datetime.utcnow()
        def extract_ip(raw):
            try: d = json.loads(raw) if raw else {}
            except Exception: return None
            ip = d.get("IpAddress")
            return ip if ip and ip not in ("-", "::1", "127.0.0.1", "") else None
        engine = init_db()
        with Session(engine) as s:
            for a in alerts:
                s.add(Alert(
                    id=a.get("alert_id"), timestamp=parse_ts(a.get("timestamp")),
                    host=a.get("host", "UNKNOWN"), user=a.get("user", "UNKNOWN"),
                    source_ip=extract_ip(a.get("raw_event")), event_id=a.get("event_id", ""),
                    rule_name=a.get("rule_name", "Unknown"),
                    mitre_technique_id=a.get("mitre_technique_id", "UNKNOWN"),
                    mitre_technique_name=a.get("mitre_technique_name", "Unknown"),
                    mitre_tactic=a.get("mitre_tactic", "Unknown"),
                    severity=a.get("severity", "medium"), confidence=a.get("confidence", 0.5),
                    raw_event=a.get("raw_event", "{}"),
                ))
            s.commit()

        JOB.update(stage="Correlating into incidents...")
        correlate()

        try:
            import requests
            requests.get("http://localhost:11434/api/tags", timeout=2)
            JOB.update(stage="AI triage (writing case notes)...")
            from src.triage.llm_triage import triage_incidents
            triage_incidents()
        except Exception:
            JOB.update(stage="AI engine offline - skipping case notes")
            time.sleep(1)

        JOB.update(stage="Done", running=False, done=True)
    except Exception as e:
        JOB.update(running=False, done=True, error=str(e))



@app.route('/favicon.ico')
def favicon():
    # Serve HISN SVG favicon — eliminates 404 console noise
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
        '<rect width="32" height="32" rx="4" fill="#05070A"/>'
        '<rect x="0" y="0" width="4" height="32" fill="#7CFFB2"/>'
        '<text x="9" y="23" font-family="monospace" font-size="16" '
        'font-weight="bold" fill="#7CFFB2">H</text>'
        '</svg>'
    )
    from flask import Response as _R
    r = _R(svg, mimetype='image/svg+xml')
    r.headers['Cache-Control'] = 'public, max-age=86400'
    return r



@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error. Check server logs."}), 500


@app.errorhandler(413)
def file_too_large(e):
    return jsonify({"error": "File too large. Please use a smaller file."}), 413



@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


@app.route("/upload", methods=["POST"])
def upload():
    if JOB["running"]:
        return jsonify({"error": "A job is already running"}), 409
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "No file selected."}), 400
    if not f.filename.lower().endswith(".evtx"):
        return jsonify({"error": "Invalid file type. Please upload a .evtx Windows event log."}), 400
    path = os.path.join(UPLOAD_DIR, secure_filename(f.filename))
    f.save(path)
    JOB.update(running=True, done=False, error=None, stage="Starting...")
    threading.Thread(target=run_pipeline_job, args=(path,), daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/status")
def status():
    return jsonify({**JOB, "version": HISN_VERSION})


@app.route("/clear", methods=["POST"])
def clear():
    engine = init_db()
    with Session(engine) as s:
        s.query(Alert).delete()
        s.query(Incident).delete()
        s.commit()
    return jsonify({"status": "cleared"})


@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    if request.method == "POST":
        data = request.get_json() or {}
        save_keys({
            "ABUSEIPDB_API_KEY": data.get("abuseipdb", "").strip(),
            "VIRUSTOTAL_API_KEY": data.get("virustotal", "").strip(),
        })
        from src.enrichment import ip_lookup, hash_lookup
        ip_lookup._cache.clear()
        hash_lookup._cache.clear()
        return jsonify({"status": "saved"})
    keys = load_keys()
    return jsonify({
        "abuseipdb": keys.get("ABUSEIPDB_API_KEY", ""),
        "virustotal": keys.get("VIRUSTOTAL_API_KEY", ""),
    })


@app.route("/ai-chat", methods=["POST"])
def ai_chat():
    data = request.get_json() or {}
    context_type = data.get("context_type") or "none"
    context_data = data.get("context") or {}
    question = (data.get("question") or "").strip()
    preset = data.get("preset")
    if preset and preset in PRESET_PROMPTS:
        question = PRESET_PROMPTS[preset]
    if not question:
        return jsonify({"error": "Please enter a question."}), 400
    global_context = data.get("global_context") or ""
    # Hard token cap for summarize to enforce brevity
    _max_tok = 220 if preset == "summarize" else None
    result = ask_ai(context_type, context_data, question, global_context, max_tokens=_max_tok)
    return jsonify(result)



@app.route("/scan-email", methods=["POST"])
def scan_email_route():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "Please choose a file."}), 400
    allowed_exts = ('.eml', '.msg', '.png', '.jpg', '.jpeg', '.webp', '.bmp', '.gif', '.tiff', '.tif')
    if not f.filename.lower().endswith(allowed_exts):
        return jsonify({"error": "Unsupported file type. Upload .eml, .msg, or a screenshot (.png, .jpg, etc)."}), 400
    path = os.path.join(DOC_UPLOAD_DIR, secure_filename(f.filename))
    f.save(path)
    try:
        from src.parsers.email_parser import parse_file
        result = parse_file(path)
        if not result:
            return jsonify({"error": "Parser returned no result."}), 500
        return jsonify(result)
    except Exception as _e:
        return jsonify({"error": f"Parser error: {str(_e)}"}), 500


@app.route("/demo", methods=["POST"])
def demo():
    import glob
    # Get the project root (where app.py lives, two levels up from src/dashboard/)
    here = os.path.dirname(os.path.abspath(__file__))          # src/dashboard/
    root = os.path.abspath(os.path.join(here, '..', '..'))     # project root

    search_dirs = [
        os.path.join(root, 'logs', 'samples'),
        os.path.join(root, 'uploads_web'),
        os.path.join(root, 'logs'),
        root,
    ]
    candidates = []
    for d in search_dirs:
        if os.path.isdir(d):
            for fname in os.listdir(d):
                if fname.lower().endswith('.evtx'):
                    candidates.append(os.path.join(d, fname))

    # Prefer brute-force or metasploit samples as they produce good results
    preferred = [c for c in candidates if any(x in c.lower() for x in ['metasploit','mimikatz','brute','security','uacme'])]
    if preferred:
        candidates = preferred

    if not candidates:
        return jsonify({"error": f"No .evtx files found under {root}"}), 404

    if JOB["running"]:
        return jsonify({"error": "A job is already running."}), 409

    # Prefer files known to produce rich detection results
    PREF = ['mimikatz', 'metasploit', 'uacme', 'brute', 'security']
    chosen = None
    for _pref in PREF:
        for _c in candidates:
            if _pref in os.path.basename(_c).lower():
                chosen = _c; break
        if chosen: break
    if not chosen: chosen = candidates[0]
    engine = init_db()
    with Session(engine) as s:
        s.query(Alert).delete(); s.query(Incident).delete(); s.commit()
    JOB.update(running=True, done=False, error=None, stage=f"Loading demo: {os.path.basename(chosen)}...")
    threading.Thread(target=run_pipeline_job, args=(chosen,), kwargs={"demo_mode": True}, daemon=True).start()
    return jsonify({"status": "started", "file": os.path.basename(chosen)})


@app.route("/report/incidents")
def report_incidents():
    engine = init_db()
    with Session(engine) as session:
        incidents = session.query(Incident).all()
        alerts = session.query(Alert).all()
        total_alerts = len(alerts)
        total_incidents = len(incidents)
        reduction = round((1 - total_incidents / total_alerts) * 100, 1) if total_alerts else 0
        tech_sev = {}
        for a in alerts:
            cur = tech_sev.get(a.mitre_technique_id)
            if cur is None or SEVERITY_RANK.get(a.severity, 0) > SEVERITY_RANK.get(cur, 0):
                tech_sev[a.mitre_technique_id] = a.severity
        techniques_seen = len(tech_sev)

        chrono = sorted(incidents, key=lambda i: i.start_time)
        nums = {inc.id: idx + 1 for idx, inc in enumerate(chrono)}
        incidents_sorted = sorted(incidents, key=lambda i: SEVERITY_RANK.get(i.max_severity, 0), reverse=True)

        global_context_str = ""
        gc_lines = []
        for inc in incidents_sorted:
            cn = f"CASE-{nums[inc.id]:03d}"
            gc_lines.append(
                f"[{cn}] Host:{inc.host} | IP:{inc.source_ip or 'internal'} | "
                f"Sev:{inc.max_severity} | Alerts:{inc.alert_count} | "
                f"Techniques:{inc.mitre_techniques} | Rules:{inc.rule_names} | "
                f"Window:{str(inc.start_time)[:16]} to {str(inc.end_time)[:16]}"
            )
        global_context_str = (
            "ALL CURRENTLY LOADED CASES (use these to answer questions about specific cases by number):\n"
            + "\n".join(gc_lines)
        ) if gc_lines else ""

        incidents_data = []
        for inc in incidents_sorted:
            incidents_data.append({
                "case_number": nums[inc.id],
                "max_severity": inc.max_severity,
                "host": inc.host,
                "source_ip": inc.source_ip,
                "start_time": str(inc.start_time),
                "end_time": str(inc.end_time),
                "alert_count": inc.alert_count,
                "mitre_techniques": inc.mitre_techniques,
                "rule_names": inc.rule_names,
                "ai_summary": inc.ai_summary,
                "remediation": get_remediation(inc.mitre_techniques),
            })

        stats = {"total_alerts": total_alerts, "total_incidents": total_incidents,
                  "reduction": reduction, "techniques_seen": techniques_seen}

    from src.reports.pdf_report import generate_incident_report
    buf = generate_incident_report(incidents_data, stats)
    return Response(buf.getvalue(), mimetype="application/pdf",
                     headers={"Content-Disposition": "attachment; filename=HISN_Incident_Report.pdf"})


@app.route("/report/document", methods=["POST"])
def report_document():
    result = request.get_json()
    from src.reports.pdf_report import generate_document_report
    buf = generate_document_report(result)
    return Response(buf.getvalue(), mimetype="application/pdf",
                     headers={"Content-Disposition": "attachment; filename=HISN_Document_Report.pdf"})


@app.route("/scan-document", methods=["POST"])
def scan_document_route():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "Please choose a file."}), 400
    allowed = (".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm")
    if not f.filename.lower().endswith(allowed):
        return jsonify({"error": "Unsupported file type. Use PDF, Word, Excel, or PowerPoint files."}), 400
    path = os.path.join(DOC_UPLOAD_DIR, secure_filename(f.filename))
    f.save(path)
    result = scan_document(path)
    return jsonify(result)



# Pre-warm detection engine caches on startup (avoids cold-start delay on first use)
import threading as _prewarm_thread
def _prewarm_caches():
    try:
        get_sigma_descriptions()   # loads 2527 rules once, caches them
        get_sigma_full_rules()
        print('[+] HISN: detection caches pre-warmed')
    except Exception:
        pass
_prewarm_thread.Thread(target=_prewarm_caches, daemon=True).start()


TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="HISN — Unified Threat Investigation &amp; Analytics Tool">
<meta name="author" content="Kareem Alshaer">
<meta name="application-name" content="HISN">
<meta name="version" content="1.0.0">
<meta name="theme-color" content="#05070A">
<meta name="robots" content="noindex, nofollow">
<link rel="icon" type="image/svg+xml" href="/favicon.ico">
<title>HISN</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&family=Major+Mono+Display&family=Space+Grotesk:wght@400;500;700&display=swap" rel="stylesheet">
<style>
  @property --angle { syntax: '<angle>'; initial-value: 0deg; inherits: false; }
  @property --sweep { syntax: '<angle>'; initial-value: 0deg; inherits: false; }

  :root{
    --bg:#05070A; --bg-2:#070B11; --ink:#D6E8DC; --meta:#5B7A75;
    --grid:rgba(0,255,170,0.06); --rule:rgba(0,255,170,0.12);
    --acid:#7CFFB2; --acid-2:#00E0A4; --amber:#FFB347; --crimson:#FF3B5C;
    --cyan:#7BE6FF; --gold:#D9B44A; --red:#E0483E;
    --shadow: 0 10px 40px rgba(0,0,0,.6);
    --ease: cubic-bezier(.2,.7,.3,1);
  }
  *{ box-sizing:border-box }
  html,body{ background:var(--bg); }
  body{
    margin:0; color:var(--ink);
    font-family:'JetBrains Mono', ui-monospace, monospace;
    font-size:14px; line-height:1.55;
    min-height:100vh;
    padding:28px 28px 100px;
    background:
      radial-gradient(1200px 600px at 80% -10%, rgba(0,224,164,0.10), transparent 60%),
      radial-gradient(900px 500px at -10% 20%, rgba(123,230,255,0.06), transparent 60%),
      linear-gradient(180deg, #05070A 0%, #03060A 100%);
    overflow-x:hidden; position:relative;
    cursor: crosshair;
  }
  body::before{
    content:''; position:fixed; inset:0; pointer-events:none; z-index:1;
    background-image:
      linear-gradient(var(--grid) 1px, transparent 1px),
      linear-gradient(90deg, var(--grid) 1px, transparent 1px);
    background-size: 48px 48px;
    mask-image: radial-gradient(ellipse 1200px 700px at 50% 30%, #000 35%, transparent 80%);
    opacity:.6;
  }
  body::after{
    content:''; position:fixed; inset:0; pointer-events:none; z-index:2;
    background: repeating-linear-gradient(0deg, rgba(0,0,0,0.18) 0 1px, transparent 1px 3px);
    mix-blend-mode:multiply; opacity:.55;
    animation: scanmove 6s linear infinite;
  }
  @keyframes scanmove { to { background-position: 0 120px; } }

  .vignette{ position:fixed; inset:0; pointer-events:none; z-index:3;
    background: radial-gradient(ellipse at center, transparent 55%, rgba(0,0,0,0.65) 100%);
    animation: flicker 7s infinite;
  }
  @keyframes flicker { 0%,97%,100%{opacity:1} 98%{opacity:.85} 99%{opacity:.92} }

  #rain{ position:fixed; inset:0; z-index:0; opacity:.18; pointer-events:none; }

  main, header, .hud { position:relative; z-index:5; }

  .hud{
    display:grid; grid-template-columns: 1fr auto; gap:16px;
    align-items:end; padding-bottom:18px;
    border-bottom:1px dashed var(--rule); margin-bottom:22px;
  }
  .brand{ display:flex; align-items:center; gap:14px; }
  .sigil{
    width:54px; height:54px; flex:0 0 54px; position:relative;
    border:1px solid var(--acid); border-radius:50%;
    box-shadow: 0 0 24px rgba(124,255,178,.35), inset 0 0 18px rgba(124,255,178,.15);
  }
  .sigil::before, .sigil::after{
    content:''; position:absolute; inset:6px; border-radius:50%;
    border:1px dashed rgba(124,255,178,.45);
    animation: sigilSpin 18s linear infinite;
  }
  .sigil::after{ inset:14px; border-style:solid; border-color: rgba(123,230,255,.4); animation-duration: 11s; animation-direction:reverse; }
  @keyframes sigilSpin { to { transform: rotate(360deg);} }
  .sigil .dot{ position:absolute; top:50%; left:50%; width:6px; height:6px; margin:-3px 0 0 -3px; border-radius:50%; background:var(--acid); box-shadow:0 0 10px var(--acid); }

  .title-wrap h1{
    font-family:'Major Mono Display', monospace; font-weight:400;
    font-size: clamp(28px, 4vw, 44px); letter-spacing:.04em;
    margin:0; color:#EAFFF2; line-height:1;
    text-shadow: 0 0 18px rgba(124,255,178,.25);
    position:relative; display:inline-block;
  }
  .title-wrap h1::before, .title-wrap h1::after{
    content: attr(data-text); position:absolute; left:0; top:0; width:100%; overflow:hidden;
    mix-blend-mode:screen; pointer-events:none;
  }
  .title-wrap h1::before{ color:#FF3B5C; transform:translate(2px,0); clip-path: inset(0 0 60% 0); animation: glitchA 4.6s infinite steps(1); opacity:.65; }
  .title-wrap h1::after { color:#7BE6FF; transform:translate(-2px,0); clip-path: inset(60% 0 0 0); animation: glitchB 5.2s infinite steps(1); opacity:.65; }
  @keyframes glitchA { 0%,92%,100%{clip-path:inset(0 0 100% 0)} 93%{clip-path:inset(10% 0 60% 0); transform:translate(3px,-1px)} 96%{clip-path:inset(30% 0 30% 0); transform:translate(-2px,1px)} }
  @keyframes glitchB { 0%,90%,100%{clip-path:inset(100% 0 0 0)} 92%{clip-path:inset(70% 0 5% 0); transform:translate(-3px,1px)} 95%{clip-path:inset(40% 0 25% 0); transform:translate(2px,-1px)} }

  .subline{ color:var(--meta); font-size:11px; letter-spacing:.28em; text-transform:uppercase; margin-top:8px; display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
  .ai-dot{ width:8px; height:8px; border-radius:50%; background:var(--acid); box-shadow:0 0 12px var(--acid); animation: pulse 1.6s ease-in-out infinite; }
  @keyframes pulse { 50%{ transform:scale(1.35); opacity:.7 } }

  .hud-right{ text-align:right; font-size:11px; color:var(--meta); letter-spacing:.22em; text-transform:uppercase; }
  .hud-right .clock{ color:var(--acid); font-size:18px; letter-spacing:.18em; text-shadow:0 0 12px rgba(124,255,178,.4); }
  .threatcon{ display:inline-flex; align-items:center; gap:8px; padding:4px 10px; border:1px solid var(--crimson); color:var(--crimson); border-radius:2px; margin-top:6px; font-weight:700; }
  .threatcon::before{ content:''; width:6px; height:6px; background:var(--crimson); border-radius:50%; box-shadow:0 0 10px var(--crimson); animation:pulse 1s infinite; }

  .tab-bar{ display:flex; gap:0; margin-bottom:20px; border-bottom:1px solid var(--rule); position:relative; }
  .tab-btn{
    font-family:inherit; font-size:11px; letter-spacing:.28em; text-transform:uppercase;
    background:transparent; color:var(--meta); border:1px solid transparent; border-bottom:none;
    padding:12px 18px; cursor:pointer; position:relative;
    transition:color .2s var(--ease), background .2s var(--ease);
  }
  .tab-btn::before{ content:'▎'; color:var(--acid); margin-right:8px; opacity:.3; transition:opacity .2s; }
  .tab-btn:hover{ color:var(--ink); }
  .tab-btn.active{ color:var(--acid); background:linear-gradient(180deg, rgba(124,255,178,.07), transparent); border-color:var(--rule); }
  .tab-btn.active::before{ opacity:1; }
  .tab-btn.active::after{ content:''; position:absolute; left:0; right:0; bottom:-1px; height:2px; background:linear-gradient(90deg, transparent, var(--acid), transparent); box-shadow:0 0 12px var(--acid);}
  .tab-panel{ display:none; animation: fadeIn .4s var(--ease); }
  .tab-panel.active{ display:block; }
  @keyframes fadeIn { from{opacity:0; transform:translateY(6px)} to{opacity:1; transform:translateY(0)} }

  .dropzone-wrap{ position:relative; padding:1px; margin-bottom:26px; border-radius:4px;
    background: linear-gradient(135deg, rgba(124,255,178,.4), rgba(123,230,255,.2) 40%, rgba(255,59,92,.3));
  }
  .dropzone{
    position:relative; overflow:hidden;
    background: linear-gradient(180deg, #08100D, #05080C);
    padding: 46px 32px; text-align:center; border-radius:3px;
    transition: background .2s var(--ease);
  }
  .dropzone::before{
    content:''; position:absolute; inset:0;
    background:
      radial-gradient(circle at 50% 50%, transparent 0, transparent 60px, rgba(124,255,178,.05) 60px, rgba(124,255,178,.05) 61px, transparent 61px),
      radial-gradient(circle at 50% 50%, transparent 0, transparent 120px, rgba(124,255,178,.04) 120px, rgba(124,255,178,.04) 121px, transparent 121px),
      radial-gradient(circle at 50% 50%, transparent 0, transparent 180px, rgba(124,255,178,.03) 180px, rgba(124,255,178,.03) 181px, transparent 181px);
    pointer-events:none;
  }
  .dropzone::after{
    content:''; position:absolute; inset:0; pointer-events:none;
    background: conic-gradient(from var(--sweep), rgba(124,255,178,.25) 0deg, transparent 60deg);
    animation: radar 4s linear infinite;
    mix-blend-mode:screen;
  }
  @keyframes radar { to { --sweep: 360deg; } }
  .dropzone.drag{ background: linear-gradient(180deg, #0B1814, #07100C); }
  .dropzone.drag::after{ animation-duration: 1.2s; }
  .upload-icon{ color:var(--acid); margin-bottom:14px; filter: drop-shadow(0 0 10px rgba(124,255,178,.5)); transition:transform .25s var(--ease); position:relative; z-index:1;}
  .dropzone:hover .upload-icon{ transform: translateY(-4px) scale(1.08); }
  .dropzone h3{ font-family:'Major Mono Display', monospace; font-weight:400; margin:0 0 8px; font-size:22px; letter-spacing:.06em; color:#EAFFF2; position:relative; z-index:1;}
  .dropzone p{ color:var(--meta); font-size:12px; letter-spacing:.05em; margin:4px 0; position:relative; z-index:1;}

  .browse-btn{
    position:relative; overflow:hidden; display:inline-block; margin-top:16px;
    background: transparent; color:var(--acid); font-family:inherit;
    font-size:11px; letter-spacing:.3em; text-transform:uppercase; font-weight:700;
    border:1px solid var(--acid); padding:12px 28px; cursor:pointer;
    transition: color .2s, background .2s, box-shadow .2s, transform .15s;
    clip-path: polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px);
    z-index:1;
  }
  .browse-btn::before{ content:''; position:absolute; inset:0; background:var(--acid); transform:translateY(100%); transition:transform .25s var(--ease); z-index:-1; }
  .browse-btn:hover{ color:#03130C; box-shadow:0 0 24px rgba(124,255,178,.5); }
  .browse-btn:hover::before{ transform:translateY(0); }
  .browse-btn:active{ transform:scale(.97); }
  #fileInput{ display:none; }

  .progress{ display:none; margin-bottom:24px; background:rgba(7,12,16,.7); border:1px solid var(--rule); border-left:3px solid var(--acid); padding:16px 20px; font-size:12px; letter-spacing:.1em; backdrop-filter:blur(6px); position:relative; overflow:hidden;}
  .progress.show{ display:block; animation: slideIn .35s var(--ease);}
  @keyframes slideIn { from{opacity:0; transform:translateX(-10px)} to{opacity:1; transform:translateX(0)} }
  .progress::after{ content:''; position:absolute; left:0; bottom:0; height:2px; width:30%; background:linear-gradient(90deg, transparent, var(--acid), transparent); animation: scan 1.5s linear infinite;}
  @keyframes scan { from{transform:translateX(-100%)} to{transform:translateX(400%)} }
  .spinner{ display:inline-block; width:10px; height:10px; border:1.5px solid var(--rule); border-top-color:var(--acid); border-radius:50%; animation:spin .7s linear infinite; margin-right:12px; vertical-align:middle; box-shadow:0 0 8px rgba(124,255,178,.4);}
  @keyframes spin { to { transform: rotate(360deg);} }

  .stats{ display:grid; grid-template-columns: repeat(auto-fit, minmax(180px,1fr)); gap:14px; margin-bottom:28px; }
  .stat-box{
    position:relative; padding:20px 22px;
    background: linear-gradient(160deg, rgba(10,18,15,.85), rgba(5,8,12,.85));
    border:1px solid var(--rule);
    clip-path: polygon(12px 0, 100% 0, 100% calc(100% - 12px), calc(100% - 12px) 100%, 0 100%, 0 12px);
    transition: transform .25s var(--ease), border-color .25s;
    overflow:hidden;
  }
  .stat-box::before{
    content:''; position:absolute; top:-1px; left:-1px; right:-1px; height:2px;
    background:linear-gradient(90deg, transparent, var(--acid), transparent);
    transform:translateX(-100%); transition: transform .6s;
  }
  .stat-box:hover{ transform:translateY(-4px); border-color: var(--acid); }
  .stat-box:hover::before{ transform:translateX(100%); }
  .stat-box .num{
    font-family:'JetBrains Mono', monospace; font-size:36px; font-weight:800;
    letter-spacing:-.02em; line-height:1;
    background: linear-gradient(135deg, #EAFFF2, var(--acid) 60%, var(--acid-2));
    -webkit-background-clip:text; background-clip:text; color:transparent;
    text-shadow: 0 0 30px rgba(124,255,178,.25);
  }
  .stat-box .label{ font-size:10px; color:var(--meta); margin-top:8px; letter-spacing:.25em; text-transform:uppercase;}
  .stat-box .corner{ position:absolute; top:6px; right:8px; font-size:9px; color:var(--acid); opacity:.5; letter-spacing:.2em;}

  .section-label{
    font-size:10px; letter-spacing:.32em; color:var(--meta); text-transform:uppercase;
    margin:24px 0 12px; padding:8px 0 8px 14px; position:relative;
    border-left:2px solid var(--acid); border-bottom:1px dashed var(--rule);
    display:flex; align-items:center; gap:10px;
  }
  .section-label::before{ content:'◢'; color:var(--acid); }
  .section-label::after{ content:''; flex:1; height:1px; background:linear-gradient(90deg, var(--rule), transparent); }

  .heatmap-row{ display:flex; align-items:center; gap:14px; margin-bottom:10px; }
  .heatmap-host{ width:170px; flex:0 0 170px; font-size:11px; color:var(--ink); letter-spacing:.05em; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .heatmap-bar-wrap{ flex:1; background:rgba(7,12,16,.6); border:1px solid var(--rule); height:18px; position:relative; }
  .heatmap-bar{ height:100%; background:linear-gradient(90deg, var(--acid-2), var(--acid)); box-shadow:0 0 10px rgba(124,255,178,.4); transition:width .6s var(--ease); }
  .heatmap-count{ width:60px; flex:0 0 60px; text-align:right; font-size:11px; color:var(--acid); font-weight:700; }

  .matrix{ display:flex; gap:8px; overflow-x:auto; padding:8px 4px 16px; margin-bottom:36px;
    scrollbar-color: var(--acid) transparent; scrollbar-width: thin;}
  .matrix::-webkit-scrollbar{ height:6px; } .matrix::-webkit-scrollbar-thumb{ background:var(--acid); border-radius:3px;}
  .col{ min-width:140px; flex:1;}
  .col-head{
    font-size:10px; color:var(--ink); text-align:center; padding:10px 6px;
    border:1px solid var(--rule); background:linear-gradient(180deg, rgba(124,255,178,.05), transparent);
    margin-bottom:6px; min-height:46px; display:flex; align-items:center; justify-content:center;
    letter-spacing:.15em; text-transform:uppercase; font-weight:500;
    transition: border-color .2s, color .2s;
  }
  .col:hover .col-head{ border-color:var(--acid); color:var(--acid); }
  .cell{
    font-size:10px; padding:8px 6px; margin-bottom:5px; text-align:center;
    background: rgba(7,12,16,.6); color: #36473F; border:1px solid rgba(124,255,178,.05);
    position:relative; cursor:default;
    transition: transform .15s var(--ease), border-color .15s, color .15s, background .15s;
    letter-spacing:.05em;
  }
  .cell:hover{ border-color: rgba(123,230,255,.4); color:var(--cyan); }
  .cell.hit{ color:#03130C; font-weight:700; border-color: transparent; box-shadow: 0 0 14px rgba(0,0,0,.4); }
  .cell.hit:hover{ transform: scale(1.08) translateY(-2px); filter: brightness(1.15); z-index:5; }
  .cell.glow{ animation: glowCrit 1.6s ease-in-out infinite; }
  @keyframes glowCrit { 50%{ box-shadow: 0 0 22px 4px rgba(224,72,62,.7);} }
  .cell .count{ display:block; font-size:9px; opacity:.8; margin-top:2px; }

  .controls{ display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:22px; padding:10px 14px; background:rgba(7,12,16,.5); border:1px solid var(--rule); border-radius:2px;}
  .pill{
    font-family:inherit; font-size:10px; letter-spacing:.22em; text-transform:uppercase; font-weight:600;
    background:transparent; border:1px solid var(--rule); color:var(--meta);
    padding:6px 14px; cursor:pointer;
    clip-path: polygon(6px 0, 100% 0, 100% calc(100% - 6px), calc(100% - 6px) 100%, 0 100%, 0 6px);
    transition: all .18s var(--ease);
  }
  .pill:hover{ border-color:var(--ink); color:var(--ink); transform:translateY(-1px); }
  .pill.active{ border-color: currentColor; background: color-mix(in oklab, currentColor 12%, transparent); box-shadow: 0 0 12px color-mix(in oklab, currentColor 35%, transparent);}
  .pill:focus-visible, .search:focus-visible, .browse-btn:focus-visible { outline:1px dashed var(--acid); outline-offset:3px;}
  .search{
    background:rgba(5,8,12,.85); border:1px solid var(--rule); color:var(--acid);
    padding:8px 14px 8px 28px; font-family:inherit; font-size:12px; min-width:240px;
    letter-spacing:.05em;
    background-image: radial-gradient(circle at 12px 50%, var(--acid) 2px, transparent 2.5px);
    transition: border-color .18s, box-shadow .18s;
  }
  .search::placeholder{ color:var(--meta); letter-spacing:.12em;}
  .search:focus{ border-color:var(--acid); box-shadow:0 0 18px rgba(124,255,178,.25); }

  .case{
    position:relative; background: linear-gradient(170deg, #0B1410 0%, #070B0E 100%);
    border:1px solid var(--rule); padding:24px 24px 22px; margin-bottom:20px;
    box-shadow: var(--shadow);
    --i: 0;
    animation: caseIn .55s var(--ease) both;
    animation-delay: calc(var(--i,0) * .06s);
    clip-path: polygon(0 0, calc(100% - 24px) 0, 100% 24px, 100% 100%, 24px 100%, 0 calc(100% - 24px));
    transition: transform .25s var(--ease), border-color .25s;
  }
  .case::before{
    content:''; position:absolute; top:0; right:0; width:24px; height:24px;
    background: linear-gradient(225deg, var(--rule) 50%, transparent 50%);
  }
  .case::after{
    content:'CLASSIFIED'; position:absolute; top:14px; right:38px;
    font-size:8px; letter-spacing:.4em; color:rgba(124,255,178,.25); transform:rotate(0deg);
  }
  @keyframes caseIn { from{opacity:0; transform:translateY(14px)} to{opacity:1; transform:translateY(0)} }
  .case:hover{ transform:translateY(-3px); border-color: var(--acid);}
  .case-head{ display:flex; justify-content:space-between; align-items:flex-start; gap:14px; flex-wrap:wrap; }
  .stamp{
    display:inline-block; font-weight:800; font-size:12px; letter-spacing:.28em; text-transform:uppercase;
    border:2.5px solid currentColor; padding:5px 12px; transform:rotate(-4deg);
    background: rgba(0,0,0,.2); position:relative;
    text-shadow: 0 0 1px currentColor;
  }
  .stamp::before{
    content:''; position:absolute; inset:0; opacity:.18; pointer-events:none; mix-blend-mode:overlay;
    background-image: radial-gradient(circle at 30% 40%, transparent 1px, currentColor 1.4px, transparent 2px);
    background-size: 4px 4px;
  }
  .stamp-critical{ animation: glowCrit 1.6s ease-in-out infinite; }
  .stamp-high{ animation: glowHigh 2s ease-in-out infinite; }
  @keyframes glowHigh { 50%{ box-shadow: 0 0 16px 2px rgba(255,179,71,.45);} }
  .host-line{ font-size:16px; margin-top:10px; font-family:'Space Grotesk', sans-serif; font-weight:500; letter-spacing:.01em; color:#EAFFF2;}
  .host-line strong{ color:var(--acid); }
  .case-id{ font-size:11px; color:var(--meta); letter-spacing:.22em; padding:4px 10px; border:1px dashed var(--rule); }
  .meta-row{ font-size:11px; color:var(--meta); margin:10px 0 6px; letter-spacing:.08em;}
  .tags{ font-size:12px; color:var(--meta); line-height:1.7; margin-bottom:14px; word-break:break-word;}
  .tags b{ color:var(--ink); font-weight:600;}

  .ioc-box{
    background: rgba(5,8,12,.7); border:1px solid var(--rule); border-left:3px solid var(--cyan);
    padding:12px 16px; margin-bottom:12px; font-size:12px;
  }
  .ioc-label{ font-size:9px; letter-spacing:.3em; color:var(--cyan); text-transform:uppercase; display:block; margin-bottom:8px;}
  .ioc-muted{ color:var(--meta); font-style:italic; font-size:11px;}
  .ioc-score{ font-weight:700; font-size:13px;}
  .ioc-meta{ color:var(--meta); margin-left:10px; font-size:11px;}
  .ioc-link{ display:inline-block; margin-top:6px; color:var(--acid); font-size:11px; text-decoration:none; letter-spacing:.05em;
    position:relative; transition:color .15s;}
  .ioc-link::after{ content:''; position:absolute; left:0; bottom:-2px; width:0; height:1px; background:var(--acid); transition:width .25s;}
  .ioc-link:hover{ color:#EAFFF2; }
  .ioc-link:hover::after{ width:100%; }

  .kv{ font-size:12px; color:var(--ink); margin:4px 0;}
  .kv b{ color:var(--meta); font-weight:500; }
  .tag-ok{
    display:inline-block; background: rgba(123,230,255,.08); color:var(--cyan);
    border:1px solid rgba(123,230,255,.25); padding:3px 10px; margin:3px 4px 0 0; font-size:11px;
    transition: all .15s;
  }
  .tag-ok:hover{ background: rgba(123,230,255,.18); transform:translateY(-1px);}
  .tag-flag{
    display:inline-block; background: rgba(255,59,92,.1); color:var(--crimson);
    border:1px solid rgba(255,59,92,.4); padding:3px 10px; margin:3px 4px 0 0; font-size:11px;
    animation: jitter 3s ease-in-out infinite;
  }
  @keyframes jitter { 0%,90%,100%{transform:translate(0,0)} 92%{transform:translate(1px,-1px)} 94%{transform:translate(-1px,1px)} }

  .chain{
    display:flex; gap:2px; overflow-x:auto; margin:16px 0;
    padding:10px 0 6px; border-top:1px dashed var(--rule); border-bottom:1px dashed var(--rule);
  }
  .stage{ flex:1; min-width:80px; text-align:center; font-size:9px; color:var(--meta); padding:8px 4px; white-space:nowrap; letter-spacing:.1em; text-transform:uppercase; position:relative;
    border-top:3px solid var(--rule); transition: all .2s; }
  .stage.active{ border-top-color:var(--acid); color:var(--acid); text-shadow:0 0 8px rgba(124,255,178,.4);}
  .stage.active::before{ content:'●'; position:absolute; top:-9px; left:50%; transform:translateX(-50%); color:var(--acid); font-size:8px;}

  .note{
    background: linear-gradient(135deg, rgba(255,179,71,.08), rgba(5,8,12,.7));
    border:1px solid rgba(255,179,71,.25); border-left:3px solid var(--amber);
    padding:14px 18px; font-size:13px; line-height:1.7; margin-bottom:12px; color:#F4E9D6;
    font-family:'Space Grotesk', sans-serif;
  }
  .note-label{ font-family:'JetBrains Mono', monospace; font-size:9px; letter-spacing:.3em; color:var(--amber); text-transform:uppercase; display:block; margin-bottom:8px;}

  details.remediation{
    background: rgba(5,8,12,.5); border:1px solid var(--rule); padding:12px 16px; margin-bottom:12px;
    transition: border-color .2s;
  }
  details.remediation[open]{ border-color: var(--acid); box-shadow: inset 0 0 30px rgba(124,255,178,.04);}
  details.remediation summary{ cursor:pointer; font-size:10px; letter-spacing:.3em; color:var(--acid); text-transform:uppercase; padding:4px 0; list-style:none; display:flex; align-items:center; gap:10px;}
  details.remediation summary::-webkit-details-marker{ display:none;}
  details.remediation summary::before{ content:'▸'; transition: transform .2s; color:var(--acid);}
  details.remediation[open] summary::before{ transform: rotate(90deg);}
  .rem-item{ margin:12px 0; padding-left:14px; border-left:2px solid var(--rule);}
  .rem-tech{ font-size:12px; font-weight:700; color:var(--ink); letter-spacing:.08em;}
  .rem-cat{ font-size:9px; color:var(--bg); margin-left:10px; text-transform:uppercase; letter-spacing:.22em; background:var(--acid); padding:2px 10px; font-weight:700;}
  .rem-item ul{ margin:8px 0 0; padding-left:20px; font-size:12px; color:var(--meta); line-height:1.7; font-family:'Space Grotesk', sans-serif;}
  .rem-item ul li::marker{ color:var(--acid);}

  .hidden{ display:none !important;}
  .empty{ text-align:center; color:var(--meta); padding:36px 20px; font-size:12px; letter-spacing:.18em; text-transform:uppercase; border:1px dashed var(--rule); background: rgba(5,8,12,.4);}

  .card{ background:rgba(7,12,16,.85); border:1px solid var(--rule); padding:22px 24px; margin-top:22px;
    clip-path: polygon(0 0, calc(100% - 16px) 0, 100% 16px, 100% 100%, 16px 100%, 0 calc(100% - 16px));}
  .excerpt{ background:rgba(5,8,12,.8); border-left:3px solid var(--cyan); padding:14px 18px; font-size:12px; line-height:1.7; white-space:pre-wrap; color:var(--meta); margin-top:8px; font-family:'JetBrains Mono', monospace;}
  .error-text{ color:var(--crimson); font-size:12px; margin:12px 0; letter-spacing:.05em;}

  .dropzone.simple{ border:1px dashed var(--rule); padding:28px; background: rgba(5,8,12,.6);}
  .dropzone.simple::before, .dropzone.simple::after{ display:none;}
  input[type=file]{ color:var(--meta); font-family:inherit; font-size:12px;}

  #term{ position:fixed; left:0; right:0; bottom:0; height:0; background:rgba(3,6,8,.96);
    border-top:1px solid var(--acid); box-shadow: 0 -10px 50px rgba(124,255,178,.2);
    z-index:50; transition: height .3s var(--ease); overflow:hidden; backdrop-filter:blur(10px);}
  #term.open{ height: 280px;}
  #term .bar{ display:flex; align-items:center; gap:10px; padding:8px 14px; border-bottom:1px solid var(--rule); font-size:10px; letter-spacing:.25em; color:var(--meta); text-transform:uppercase;}
  #term .bar .dots{ display:flex; gap:6px;} #term .bar .dots span{ width:9px; height:9px; border-radius:50%; background:var(--rule);} #term .bar .dots span:first-child{ background:var(--crimson);} #term .bar .dots span:nth-child(2){ background:var(--amber);} #term .bar .dots span:nth-child(3){ background:var(--acid);}
  #term .body{ padding:12px 16px; height: calc(100% - 36px); overflow:auto; font-size:12px; color:var(--ink);}
  #term .prompt{ color:var(--acid);}
  #term input{ background:transparent; border:none; outline:none; color:var(--ink); font-family:inherit; font-size:12px; width:80%;}

  #toasts{ position:fixed; top:24px; right:24px; z-index:60; display:flex; flex-direction:column; gap:10px;}
  .toast{ background:rgba(7,12,16,.95); border:1px solid var(--acid); border-left:3px solid var(--acid); padding:12px 18px; font-size:12px; min-width:240px; backdrop-filter:blur(8px); box-shadow: 0 8px 30px rgba(0,0,0,.5); animation: toastIn .3s var(--ease);}
  .toast.crit{ border-color:var(--crimson); border-left-color:var(--crimson); color:#FFD6DD;}
  @keyframes toastIn { from{opacity:0; transform:translateX(20px)} to{opacity:1; transform:translateX(0)} }

  body.declassified .stamp::after{
    content:'DECLASSIFIED'; position:absolute; top:-20px; left:50%; transform: translateX(-50%) rotate(-8deg);
    color:var(--acid); border:2.5px solid var(--acid); padding:4px 10px; font-size:10px; letter-spacing:.3em;
    background:rgba(124,255,178,.08); white-space:nowrap;
    animation: stampDrop .5s cubic-bezier(.34,1.56,.64,1);
  }
  @keyframes stampDrop { from{ transform: translateX(-50%) rotate(-20deg) scale(2); opacity:0;} to{ transform: translateX(-50%) rotate(-8deg) scale(1); opacity:1;}}

  .cursor-dot{ position:fixed; width:6px; height:6px; border-radius:50%; background:var(--acid); pointer-events:none; z-index:55; mix-blend-mode:screen; box-shadow:0 0 12px var(--acid); transition: width .2s, height .2s, opacity .6s;}

  #settingsPanel{ display:none; }
  #settingsPanel .panel-close{ position:absolute; top:14px; right:16px; background:transparent; border:1px solid var(--rule); color:var(--meta); font-family:inherit; font-size:11px; padding:2px 8px; cursor:pointer; }
  #settingsPanel .panel-close:hover{ color:var(--crimson); border-color:var(--crimson); }

  .ai-callout{ position:fixed; right:90px; bottom:28px; z-index:92; display:flex; align-items:center; gap:10px; animation: calloutPulse 2s ease-in-out infinite; pointer-events:auto; }
  .ai-callout-inner{ background:rgba(7,12,16,.95); border:1px solid var(--acid); padding:10px 14px; font-size:11px; letter-spacing:.1em; color:var(--acid); white-space:nowrap; box-shadow:0 0 20px rgba(124,255,178,.3); }
  .ai-callout-inner span{ display:block; font-size:9px; color:var(--meta); margin-top:3px; letter-spacing:.05em; }
  .ai-callout-arrow{ color:var(--acid); font-size:20px; animation: arrowBounce .8s ease-in-out infinite; }
  @keyframes calloutPulse { 0%,100%{ opacity:1; } 50%{ opacity:.75; } }
  @keyframes arrowBounce { 0%,100%{ transform:translateX(0); } 50%{ transform:translateX(6px); } }
  .ai-callout.hidden{ display:none !important; }

  .ai-widget-toggle{ width:54px; height:54px; border-radius:50%; background:var(--acid); color:#03130C; border:none; cursor:pointer; box-shadow:0 0 20px rgba(124,255,178,.5); font-size:20px; position:fixed; right:24px; bottom:24px; z-index:91; display:flex; align-items:center; justify-content:center; font-family:'Major Mono Display', monospace; }
  .ai-widget.expanded .ai-widget-toggle{ display:none; }
  .ai-widget-panel{ display:none; position:fixed; right:24px; bottom:90px; width:360px; height:500px; background:rgba(7,12,16,.97); border:1px solid var(--acid); box-shadow:0 10px 50px rgba(0,0,0,.6); backdrop-filter:blur(10px); flex-direction:column; z-index:90; min-width:300px; min-height:360px; }
  .ai-widget.expanded .ai-widget-panel{ display:flex; }
  .ai-widget-header{ display:flex; justify-content:space-between; align-items:center; padding:10px 14px; border-bottom:1px solid var(--rule); cursor:move; flex:0 0 auto; user-select:none; }
  .ai-widget-title{ font-size:10px; letter-spacing:.25em; color:var(--acid); text-transform:uppercase; }
  .ai-context-label{ color:var(--cyan); margin-left:4px; font-size:9px; }
  .ai-context-banner{ font-size:10px; padding:8px 14px; border-bottom:1px solid var(--rule); color:var(--amber); background:rgba(255,179,71,.06); flex:0 0 auto; }
  .ai-context-banner.has-context{ color:var(--acid); background:rgba(124,255,178,.06); }
  .ai-widget-actions button{ background:transparent; border:1px solid var(--rule); color:var(--meta); font-family:inherit; font-size:9px; padding:3px 8px; cursor:pointer; margin-left:6px; }
  .ai-widget-actions button:hover{ color:var(--ink); border-color:var(--ink); }
  .ai-messages{ flex:1; overflow-y:auto; padding:14px; font-size:12px; line-height:1.6; }
  .ai-msg{ margin-bottom:14px; }
  .ai-msg.user{ text-align:right; }
  .ai-msg.user .ai-bubble{ background:rgba(123,230,255,.1); border:1px solid rgba(123,230,255,.25); display:inline-block; padding:8px 12px; border-radius:2px; text-align:left; max-width:90%; }
  .ai-msg.assistant .ai-bubble{ background:rgba(124,255,178,.06); border:1px solid var(--rule); padding:10px 14px; border-radius:2px; }
  .ai-msg-label{ font-size:9px; letter-spacing:.2em; color:var(--meta); text-transform:uppercase; margin-bottom:4px; display:block; }
  .ai-copy-btn{ font-size:9px; color:var(--meta); background:none; border:1px solid var(--rule); padding:2px 6px; cursor:pointer; margin-top:6px; }
  .ai-copy-btn:hover{ color:var(--acid); border-color:var(--acid); }
  .ai-typing{ display:inline-flex; gap:4px; padding:4px 0; }
  .ai-typing span{ width:6px; height:6px; border-radius:50%; background:var(--acid); animation:aiTypingBounce 1s infinite; }
  .ai-typing span:nth-child(2){ animation-delay:.15s;} .ai-typing span:nth-child(3){ animation-delay:.3s;}
  @keyframes aiTypingBounce { 0%,80%,100%{ transform:translateY(0); opacity:.4;} 40%{ transform:translateY(-4px); opacity:1;} }
  .ai-chips{ display:flex; gap:6px; flex-wrap:wrap; padding:0 14px 10px; flex:0 0 auto; max-height:80px; overflow-y:auto; }
  .ai-chips button{ font-size:9px; letter-spacing:.05em; background:transparent; border:1px solid var(--rule); color:var(--meta); padding:5px 10px; cursor:pointer; }
  .ai-chips button:hover{ color:var(--acid); border-color:var(--acid); }
  .ai-input-row{ display:flex; gap:8px; padding:12px 14px; border-top:1px solid var(--rule); flex:0 0 auto; }
  .ai-input-row input{ flex:1; background:rgba(5,8,12,.85); border:1px solid var(--rule); color:var(--ink); padding:8px; font-family:inherit; font-size:12px; }
  .ai-input-row button{ background:var(--acid); color:#03130C; border:none; padding:8px 14px; font-family:inherit; font-size:11px; font-weight:700; cursor:pointer; }
  .ai-resize-handle{ position:absolute; top:0; left:0; width:14px; height:14px; cursor:nwse-resize; }
  pre.ai-code{ background:#03060A; border:1px solid var(--rule); padding:10px; overflow-x:auto; font-size:11px; margin:8px 0; white-space:pre; }
  .ai-context-btn{ margin-bottom:10px; }

  @media (prefers-reduced-motion: reduce){
    *, *::before, *::after { animation-duration: .01ms !important; animation-iteration-count: 1 !important; transition-duration: .01ms !important;}
    #rain, body::after{ display:none;}
  }
  @media (max-width: 760px){
    body{ padding:18px 14px 60px; font-size:13px;}
    .hud{ grid-template-columns: 1fr; }
    .hud-right{ text-align:left;}
    .dropzone{ padding:30px 18px;}
    .stat-box .num{ font-size:28px;}
    #settingsPanel{ left:14px; right:14px; width:auto !important; }
    .ai-widget-panel{ left:10px !important; right:10px !important; width:auto !important; }
  }

  /* ═══════════════════ NEW CASE CARD GRID (override old .case) ═══════ */
  .case{
    --rail:var(--meta); --rail-soft:color-mix(in oklab,var(--meta) 22%,transparent);
    position:relative; display:grid;
    grid-template-columns:56px minmax(0,1.55fr) minmax(280px,.95fr);
    grid-template-rows:auto auto auto;
    grid-template-areas:"ledger header header" "ledger briefing evidence" "ledger footer footer";
    background:linear-gradient(180deg,rgba(9,14,19,.94) 0%,rgba(6,10,14,.94) 100%);
    border:1px solid var(--rule); border-left:none; margin:0 0 18px;
    --i:0; animation:caseIn .45s var(--ease) both;
    animation-delay:calc(var(--i,0)*.04s); clip-path:none; padding:0;
    transition:border-color .25s var(--ease); box-shadow:none;
  }
  .case[data-sev="critical"]{--rail:var(--crimson);--rail-soft:color-mix(in oklab,var(--crimson) 22%,transparent);}
  .case[data-sev="high"]{--rail:var(--amber);--rail-soft:color-mix(in oklab,var(--amber) 22%,transparent);}
  .case[data-sev="medium"]{--rail:var(--cyan);--rail-soft:color-mix(in oklab,var(--cyan) 22%,transparent);}
  .case[data-sev="low"]{--rail:var(--meta);--rail-soft:color-mix(in oklab,var(--meta) 35%,transparent);}
  .case:hover{border-color:color-mix(in oklab,var(--rail) 45%,var(--rule));transform:none;}
  .case::before,.case::after{display:none!important;}
  .case-ledger{
    grid-area:ledger; position:relative;
    background:linear-gradient(180deg,color-mix(in oklab,var(--rail) 18%,transparent),transparent 65%),linear-gradient(180deg,rgba(0,0,0,.35),rgba(0,0,0,.55));
    border-left:3px solid var(--rail); box-shadow:inset -1px 0 0 var(--rule),0 0 28px -8px var(--rail-soft);
    display:flex; flex-direction:column; align-items:center; padding:18px 0 14px; gap:14px;
  }
  .ledger-sev{writing-mode:vertical-rl;transform:rotate(180deg);font-family:'JetBrains Mono',monospace;font-weight:800;font-size:10px;letter-spacing:.6em;text-transform:uppercase;color:var(--rail);text-shadow:0 0 14px color-mix(in oklab,var(--rail) 55%,transparent);padding:6px 0;}
  .ledger-tick{width:14px;height:1px;background:var(--rule);}
  .ledger-num{font-family:'Major Mono Display',monospace;font-size:22px;color:#EAFFF2;line-height:1;text-align:center;}
  .ledger-num small{display:block;font-family:'JetBrains Mono',monospace;font-size:8px;letter-spacing:.32em;color:var(--meta);margin-top:6px;text-transform:uppercase;}
  .ledger-status{margin-top:auto;font-family:'JetBrains Mono',monospace;font-size:8px;letter-spacing:.32em;color:var(--rail);display:flex;flex-direction:column;align-items:center;gap:6px;}
  .ledger-status::before{content:'';width:6px;height:6px;border-radius:50%;background:var(--rail);box-shadow:0 0 10px var(--rail);animation:pulse 1.8s ease-in-out infinite;}
  .case-header{grid-area:header;display:flex;align-items:center;justify-content:space-between;gap:18px;flex-wrap:wrap;padding:16px 24px 14px;border-bottom:1px solid var(--rule);background:linear-gradient(180deg,rgba(255,255,255,.015),transparent);}
  .case-asset{min-width:0;}
  .case-asset .host{font-family:'Major Mono Display',monospace;font-weight:400;font-size:19px;letter-spacing:.04em;color:#EAFFF2;line-height:1.1;text-shadow:0 0 14px rgba(124,255,178,.18);word-break:break-all;}
  .case-asset .id-line{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-top:6px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--meta);letter-spacing:.06em;}
  .case-asset .id-line .ip{color:#B8CFC7;}.case-asset .id-line .sep{opacity:.35;}
  .case-meta{text-align:right;display:flex;flex-direction:column;gap:6px;align-items:flex-end;}
  .case-window{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--meta);letter-spacing:.08em;display:flex;align-items:center;gap:8px;}
  .case-window::before{content:'';width:6px;height:6px;border:1px solid var(--meta);border-radius:50%;}
  .case-briefing{grid-area:briefing;padding:22px 26px 20px;border-right:1px solid var(--rule);min-width:0;}
  .briefing-eyebrow{display:flex;align-items:center;gap:10px;font-family:'JetBrains Mono',monospace;font-size:9px;letter-spacing:.4em;text-transform:uppercase;color:var(--acid);font-weight:700;margin-bottom:14px;}
  .briefing-eyebrow::before{content:'';width:14px;height:1px;background:var(--acid);box-shadow:0 0 8px var(--acid);}
  .briefing-eyebrow .ai-chip{margin-left:auto;font-size:8px;letter-spacing:.3em;color:var(--meta);border:1px solid var(--rule);padding:2px 7px;border-radius:2px;display:inline-flex;align-items:center;gap:6px;}
  .briefing-eyebrow .ai-chip::before{content:'';width:5px;height:5px;border-radius:50%;background:var(--acid);box-shadow:0 0 6px var(--acid);}
  .briefing-body{font-family:'Space Grotesk',sans-serif;font-size:14.5px;line-height:1.72;color:#E5EFE9;letter-spacing:.005em;padding-left:14px;border-left:1px solid color-mix(in oklab,var(--acid) 35%,var(--rule));}
  .briefing-empty{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--meta);letter-spacing:.18em;text-transform:uppercase;padding:12px 0;opacity:.7;}
  .chain-block{margin-top:24px;padding-top:18px;border-top:1px dashed var(--rule);}
  .chain-label{font-family:'JetBrains Mono',monospace;font-size:9px;letter-spacing:.4em;text-transform:uppercase;color:var(--meta);margin-bottom:14px;font-weight:600;}
  .chain{display:grid;grid-auto-flow:column;grid-auto-columns:1fr;align-items:start;gap:0;position:relative;padding:8px 4px 0;border-top:none;border-bottom:none;margin:0;overflow-x:auto;}
  .chain::before{content:'';position:absolute;left:6%;right:6%;top:14px;height:1px;background:repeating-linear-gradient(90deg,var(--rule) 0 4px,transparent 4px 8px);}
  .stage{text-align:center;font-family:'JetBrains Mono',monospace;font-size:9px;letter-spacing:.18em;text-transform:uppercase;color:color-mix(in oklab,var(--meta) 80%,transparent);padding-top:24px;position:relative;transition:color .2s;border-top:none;min-width:auto;}
  .stage::before{content:'';position:absolute;top:8px;left:50%;transform:translateX(-50%);width:11px;height:11px;border-radius:50%;background:#06090C;border:1px solid var(--rule);z-index:1;}
  .stage.active{color:#EAFFF2;font-weight:700;}
  .stage.active::before{background:var(--rail);border-color:var(--rail);box-shadow:0 0 12px var(--rail),0 0 0 3px color-mix(in oklab,var(--rail) 18%,transparent);}
  .case-evidence{grid-area:evidence;padding:22px 22px 20px;background:linear-gradient(180deg,rgba(0,0,0,.18),transparent 30%);display:flex;flex-direction:column;gap:18px;min-width:0;}
  .ev-block{display:flex;flex-direction:column;gap:8px;}
  .ev-head{font-family:'JetBrains Mono',monospace;font-size:9px;letter-spacing:.36em;text-transform:uppercase;color:var(--meta);font-weight:600;display:flex;align-items:center;gap:10px;}
  .ev-head::after{content:'';flex:1;height:1px;background:var(--rule);}
  .ev-row{font-family:'JetBrains Mono',monospace;font-size:11.5px;color:#D6E8DC;line-height:1.55;word-break:break-word;}
  .ev-row .k{display:inline-block;min-width:46px;color:var(--meta);font-size:9px;letter-spacing:.22em;text-transform:uppercase;margin-right:8px;}
  .ev-rule{font-family:'Space Grotesk',sans-serif;font-size:12px;color:#CFE0D8;line-height:1.55;padding-left:10px;border-left:1px solid var(--rule);}
  .repu{display:flex;align-items:flex-start;gap:12px;padding:10px 12px;background:rgba(5,8,12,.55);border:1px solid var(--rule);border-radius:2px;}
  .repu-score{font-family:'Major Mono Display',monospace;font-size:22px;line-height:1;color:#EAFFF2;min-width:54px;}
  .repu-score small{display:block;font-family:'JetBrains Mono',monospace;font-size:8px;letter-spacing:.28em;color:var(--meta);margin-top:6px;text-transform:uppercase;}
  .repu-meta{font-family:'JetBrains Mono',monospace;font-size:11px;color:#CFE0D8;line-height:1.5;flex:1;min-width:0;}
  .repu-meta .muted{color:var(--meta);font-size:10px;}
  .repu-links{display:flex;flex-wrap:wrap;gap:10px;margin-top:6px;}
  .hash-row{display:flex;flex-direction:column;gap:3px;margin-bottom:8px;}
  .hash-row .hash-links{display:flex;flex-wrap:wrap;gap:10px;padding-left:2px;}
  .case-footer{grid-area:footer;border-top:1px solid var(--rule);background:linear-gradient(180deg,rgba(0,0,0,.25),rgba(0,0,0,.4));display:flex;flex-direction:column;}
  .case-footer-bar{display:flex;align-items:stretch;flex-wrap:wrap;}
  details.drawer{flex:1 1 auto;min-width:220px;border-right:1px solid var(--rule);background:transparent;border-top:none;padding:0;margin:0;}
  details.drawer:last-child{border-right:none;}
  details.drawer summary{cursor:pointer;list-style:none;padding:12px 22px;font-family:'JetBrains Mono',monospace;font-size:9.5px;letter-spacing:.32em;text-transform:uppercase;color:var(--meta);font-weight:600;display:flex;align-items:center;gap:12px;transition:color .15s,background .15s;}
  details.drawer summary::-webkit-details-marker{display:none;}
  details.drawer summary:hover{color:var(--acid);background:rgba(124,255,178,.03);}
  details.drawer summary::before{content:'▸';color:var(--acid);font-size:9px;transition:transform .2s;display:inline-block;}
  details.drawer[open] summary{color:var(--acid);background:linear-gradient(180deg,rgba(124,255,178,.06),transparent);border-bottom:1px solid color-mix(in oklab,var(--acid) 25%,var(--rule));}
  details.drawer[open] summary::before{transform:rotate(90deg);}
  details.drawer summary .count-chip{margin-left:auto;font-size:9px;letter-spacing:.2em;color:#EAFFF2;padding:1px 7px;border:1px solid var(--rule);border-radius:2px;background:rgba(0,0,0,.35);}
  .drawer-body{padding:16px 22px 18px;}
  @media(max-width:1080px){
    .case{grid-template-columns:48px 1fr;grid-template-areas:"ledger header" "ledger briefing" "ledger evidence" "ledger footer";}
    .case-briefing{border-right:none;border-bottom:1px solid var(--rule);}
    .case-evidence{background:transparent;}
  }
  @media(max-width:600px){
    .case{grid-template-columns:40px 1fr;}
    .case-briefing,.case-evidence,.case-header{padding-left:16px;padding-right:16px;}
    details.drawer{border-right:none;border-bottom:1px solid var(--rule);}
  }


  .title-sub{
    color:#C8D6CF; font-size:11px; letter-spacing:.28em; text-transform:uppercase;
    margin-top:6px; font-family:'JetBrains Mono',monospace; font-weight:500;
    opacity:.9;
  }


  /* ── UX POLISH: micro-interactions & spacing improvements ─── */

  /* Smoother tab transitions */
  .tab-panel{ transition: opacity .25s var(--ease); }
  .tab-panel.active{ display:block; }

  /* Tab button: tighter focus ring, better hover */
  .tab-btn:hover::before{ opacity:.65; }
  .tab-btn:focus-visible{ outline:1px dashed var(--acid); outline-offset:3px; }

  /* Case card: longer, smoother hover transition */
  .case{ transition: border-color .3s var(--ease), box-shadow .3s var(--ease); }
  .case:hover{ box-shadow: 0 0 30px -8px var(--rail-soft), var(--shadow); }

  /* Drawer: smoother open/close */
  details.drawer summary{ transition: color .2s, background .2s; }

  /* Empty state: centered, breathing room */
  .empty{ border-radius:4px; }

  /* Browse button: tighter active feel */
  .browse-btn{ transition: color .18s, background .18s, box-shadow .2s, transform .12s; }
  .browse-btn:active{ transform: scale(.96) translateY(1px); }

  /* AI widget: smooth slide-in */
  .ai-widget-panel{
    transition: opacity .2s var(--ease);
    animation: aiPanelIn .2s var(--ease);
  }
  @keyframes aiPanelIn{
    from{ opacity:0; transform:translateY(8px); }
    to  { opacity:1; transform:translateY(0); }
  }

  /* AI messages: smooth appear */
  .ai-msg{ animation: msgIn .2s var(--ease); }
  @keyframes msgIn{ from{opacity:0;transform:translateY(4px)} to{opacity:1;transform:translateY(0)} }

  /* Context banner: transition on state change */
  .ai-context-banner{ transition: background .3s var(--ease), color .3s var(--ease); }

  /* Chip buttons: better hover feedback */
  .ai-chips button{
    transition: color .15s, border-color .15s, background .15s;
    border-radius:2px;
  }
  .ai-chips button:hover{
    background: rgba(124,255,178,.06);
    border-color: var(--acid);
  }
  .ai-chips button:active{ transform: scale(.97); }

  /* Progress bar: cleaner */
  .progress.show{ border-radius:2px; }

  /* Pill filter: active state punch */
  .pill{ transition: color .15s, background .15s, border-color .15s, transform .1s; }
  .pill:active{ transform: scale(.95); }

  /* IOC links: underline on hover instead of color-only */
  .ioc-link{ transition: color .15s; }

  /* Stat boxes: lift effect */
  .stat-box{ transition: transform .25s var(--ease), border-color .25s, box-shadow .25s; }
  .stat-box:hover{ box-shadow: 0 0 24px -6px rgba(124,255,178,.25); }

  /* Settings panel: smooth show/hide */
  #settingsPanel{
    animation: settingsIn .2s var(--ease);
    transform-origin: top right;
  }
  @keyframes settingsIn{ from{opacity:0;transform:scale(.97)} to{opacity:1;transform:scale(1)} }

  /* Callout arrow: slightly subtler */
  .ai-callout-inner{ transition: background .2s, border-color .2s; border-radius:2px; }
  .ai-callout-inner:hover{ background: rgba(7,18,14,.98); border-color: #EAFFF2; }

  /* Search input: smooth glow */
  .search{ transition: border-color .2s, box-shadow .25s; }

  /* Heatmap bars: smooth fill */
  .heatmap-bar{ transition: width .8s cubic-bezier(.22,.68,0,1.2); }

  /* Section labels: consistent spacing */
  .section-label{ margin-top:28px; margin-bottom:14px; }

  /* MITRE cells: smooth color transition */
  .cell{ transition: transform .15s var(--ease), border-color .15s, color .15s, background .15s, filter .15s; }

  /* Raw event viewer: readable code blocks */
  .excerpt{ border-radius:2px; }
  pre.ai-code{ border-radius:2px; }

  /* Drawer body: padding refinement */
  .drawer-body{ line-height:1.6; }

  /* Toast: smooth dismiss */
  .toast{ border-radius:2px; }

  /* Scanline overlay: slightly less aggressive */
  body::after{ opacity:.42; }

  /* Phishing dropzone tip text */
  .phishing-tip{
    font-size:10px; color:var(--acid); letter-spacing:.06em;
    margin-top:6px; opacity:.8;
    padding:4px 10px; border:1px solid rgba(124,255,178,.15);
    border-radius:2px; display:inline-block;
    background:rgba(124,255,178,.04);
  }


  /* ── PERFORMANCE HINTS — no visual change ─────────────────────── */
  /* GPU layer promotion for compositor-animated elements */
  .ai-widget-panel{ will-change: transform; }
  .ai-callout{ will-change: transform, opacity; }
  .stat-box{ will-change: transform; }
  .heatmap-bar{ will-change: width; }
  body::after{ will-change: background-position; }

  /* Layout containment — hover on one card never reflows siblings */
  .case{ contain: layout style; }
  .cell{ contain: layout style; }
  .matrix{ contain: layout; }

  /* Cursor dot — compositor-only movement, no layout */
  .cursor-dot{
    left:0 !important; top:0 !important;
    transition: transform .18s var(--ease), opacity .55s;
    will-change: transform, opacity;
  }


  /* Upload heading: cleaner, enterprise-grade — same feel, more legible */
  .dropzone h3{
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 700;
    font-size: 16px;
    letter-spacing: 0.14em;
    color: #EAFFF2;
    margin: 0 0 8px;
    text-transform: uppercase;
    text-rendering: optimizeLegibility;
    -webkit-font-smoothing: antialiased;
  }
  .dropzone-eyebrow{
    display: block;
    font-family: 'JetBrains Mono', monospace;
    font-size: 9px;
    letter-spacing: 0.42em;
    color: var(--meta);
    text-transform: uppercase;
    margin-bottom: 10px;
    opacity: .75;
    position: relative;
    z-index: 1;
  }


  /* LEDGER OVERFLOW FIX: hard containment regardless of signal count */
  .case-ledger{ overflow:hidden; }
  .ledger-num{
    font-family:'JetBrains Mono',monospace !important;
    font-size:13px !important;
    font-weight:700; color:#EAFFF2; line-height:1.15;
    text-align:center; width:100%;
    word-break:break-all; overflow:hidden;
    padding:0 2px; letter-spacing:-.01em;
  }
  .ledger-num small{
    display:block; font-family:'JetBrains Mono',monospace;
    font-size:7px; letter-spacing:.28em; color:var(--meta);
    margin-top:5px; text-transform:uppercase; white-space:nowrap;
  }


  /* MOBILE NOTICE */
  .mobile-notice{
    display:none;
    position:fixed; top:0; left:0; right:0; z-index:200;
    background:rgba(5,8,12,.96); border-bottom:1px solid var(--rule);
    padding:10px 16px;
    font-family:'JetBrains Mono',monospace; font-size:10px;
    letter-spacing:.12em; color:var(--meta);
    text-align:center; backdrop-filter:blur(8px);
  }
  .mobile-notice span{ color:var(--acid); }
  @media(max-width:768px){ .mobile-notice{ display:block; } }

  /* FOOTER */
  .hisn-footer{
    margin-top:60px; padding:18px 0; text-align:center;
    border-top:1px solid rgba(0,255,170,.07);
    font-family:'JetBrains Mono',monospace;
    font-size:9px; letter-spacing:.2em; text-transform:uppercase;
    color:rgba(91,122,117,.5);
    position:relative; z-index:5;
  }
  .hisn-footer a{
    color:rgba(124,255,178,.3); text-decoration:none;
    transition:color .2s;
  }
  .hisn-footer a:hover{ color:rgba(124,255,178,.7); }

</style>
</head>
<body>

<div class="mobile-notice"><span>&#9651; Desktop recommended</span> &mdash; HISN is optimised for 1280px+ screens. Some investigation panels may be limited on mobile.</div>

<canvas id="rain"></canvas>
<div class="vignette"></div>
<div id="toasts"></div>

<header class="hud">
  <div class="brand">
    <div class="sigil"><span class="dot"></span></div>
    <div class="title-wrap">
      <h1 data-text="HISN">HISN</h1>
      <div class="title-sub">UNIFIED THREAT INVESTIGATION &amp; ANALYTICS TOOL</div>
      <div class="subline"><span class="ai-dot"></span>Everything your investigation needs. One workspace.</div>
    </div>
  </div>
  <div class="hud-right">
    <div>UTC <span id="utc">--:--:--</span></div>
    <div class="clock" id="clock">--:--:--</div>
    <div class="threatcon" id="threatcon">THREATCON · MONITOR</div>
    <div style="margin-top:6px; font-size:9px; opacity:.6;">press <kbd style="border:1px solid var(--rule); padding:1px 5px;">~</kbd> for shell</div>
    <button id="settingsBtn" type="button" style="margin-top:8px; background:transparent; border:1px solid var(--rule); color:var(--meta); font-family:inherit; font-size:9px; letter-spacing:.15em; text-transform:uppercase; padding:4px 10px; cursor:pointer;">&#9881; API Keys (optional)</button>
  </div>
</header>

<div id="settingsPanel" class="card" style="position:fixed; top:90px; right:28px; width:320px; z-index:70;">
  <button class="panel-close" type="button" id="settingsCloseBtn">&times; close</button>
  <div class="section-label" style="margin-top:0;">API Keys &mdash; Optional, Stored Locally</div>
  <div class="ioc-muted" style="margin-bottom:12px;">Everything works without these &mdash; you'll just get a "check manually" link instead. Keys are saved to a file on this machine only, and sent only directly to the service you're querying. Nothing passes through any third party.</div>
  <div class="kv">AbuseIPDB Key</div>
  <input id="keyAbuseIPDB" type="text" style="width:100%; background:rgba(5,8,12,.85); border:1px solid var(--rule); color:var(--acid); padding:8px; font-family:inherit; font-size:12px; margin-bottom:10px;" placeholder="optional">
  <div class="kv">VirusTotal Key</div>
  <input id="keyVirusTotal" type="text" style="width:100%; background:rgba(5,8,12,.85); border:1px solid var(--rule); color:var(--acid); padding:8px; font-family:inherit; font-size:12px; margin-bottom:14px;" placeholder="optional">
  <button id="settingsSaveBtn" class="browse-btn" type="button" style="width:100%;">Save</button>
  <div id="settingsMsg" class="ioc-muted" style="margin-top:10px;"></div>
</div>

<div id="aiCallout" class="ai-callout">
  <div class="ai-callout-inner" style="cursor:pointer;" id="aiCalloutOpenBtn">HISN AI ASSISTANT<span>Click for AI investigation support</span></div>
  <div class="ai-callout-arrow">&#9658;</div>
  <button id="aiCalloutClose" type="button" style="position:absolute;top:-8px;right:-8px;background:var(--crimson);border:none;color:#fff;width:18px;height:18px;border-radius:50%;font-size:11px;cursor:pointer;line-height:1;padding:0;font-family:inherit;">&times;</button>
</div>

<div id="aiWidget" class="ai-widget">
  <button id="aiWidgetToggle" class="ai-widget-toggle" type="button" title="AI Assistant">AI</button>
  <div id="aiWidgetPanel" class="ai-widget-panel">
    <div id="aiResizeHandle" class="ai-resize-handle"></div>
    <div id="aiWidgetHeader" class="ai-widget-header">
      <span class="ai-widget-title">HISN AI<span id="aiContextLabel" class="ai-context-label"></span></span>
      <div class="ai-widget-actions">
        <button id="aiClearBtn" type="button" title="Clear chat">CLEAR</button>
        <button id="aiMinimizeBtn" type="button" title="Minimize">_</button>
      </div>
    </div>
    <div id="aiContextBanner" class="ai-context-banner">No case or document selected — click "Ask AI About This Case" on a case, or ask a general question below.</div>
    <div id="aiMessages" class="ai-messages"></div>
    <div id="aiChips" class="ai-chips"></div>
    <div class="ai-input-row">
      <input id="aiInput" type="text" placeholder="Ask a question...">
      <button id="aiSendBtn" type="button">Send</button>
    </div>
  </div>
</div>

<main>

  <div class="tab-bar">
    <button class="tab-btn active" data-tab="tab-cases">Incident Case Log</button>
    <button class="tab-btn" data-tab="tab-docs">Document &amp; File Triage</button>
    <button class="tab-btn" data-tab="tab-phishing">Email &amp; Phishing</button>
  </div>

  <div id="tab-cases" class="tab-panel active">

  <div class="dropzone-wrap">
  <div class="dropzone" id="dropzone">
    <svg class="upload-icon" width="38" height="38" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4M12 4l-4 4M12 4l4 4"/><path d="M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/></svg>
    <span class="dropzone-eyebrow">WINDOWS EVENT LOG &middot; EVTX</span>
    <h3>Drop File to Analyze</h3>
    <p>or click to browse &mdash; analysis is local. nothing leaves this machine.</p>
    <button class="browse-btn" type="button" id="browseBtn">Choose File</button>
    <input type="file" id="fileInput" accept=".evtx">
    {% if total_alerts > 0 %}
    <div style="margin-top:18px; display:flex; gap:10px; justify-content:center; flex-wrap:wrap; position:relative; z-index:1;">
      <a href="/report/incidents" class="pill" style="text-decoration:none; color:var(--amber); border-color:var(--amber);">↓ Download PDF Report</a>
      <button class="pill" type="button" id="clearBtn" style="color:var(--crimson); border-color:var(--crimson);">⨯ Purge &amp; Restart</button>
    </div>
    {% endif %}
  </div>
  </div>

  <div class="progress" id="progress"><span class="spinner"></span><span id="stageText">Working...</span></div>

  {% if total_alerts == 0 %}
  <div class="empty" style="padding:48px 28px; text-align:center;">
    <div style="font-size:13px; color:var(--ink); margin-bottom:10px; letter-spacing:.15em;">no telemetry ingested · awaiting .evtx</div>
    <div class="ioc-muted" style="margin-bottom:20px; max-width:520px; margin-left:auto; margin-right:auto;">Upload any Windows event log (.evtx) to begin investigation. All analysis runs locally — nothing leaves this machine.</div>
    <button type="button" class="browse-btn" id="demoBtn" style="margin-top:0;">Load Demo Analysis</button>
    <div id="demoMsg" class="ioc-muted" style="margin-top:10px;"></div>
  </div>
  {% else %}
  <div class="stats">
    <div class="stat-box"><span class="corner">01</span><div class="num" data-value="{{ total_alerts }}" data-suffix="">0</div><div class="label">Raw Signals</div></div>
    <div class="stat-box"><span class="corner">02</span><div class="num" data-value="{{ total_incidents }}" data-suffix="">0</div><div class="label">Case Files Opened</div></div>
    <div class="stat-box"><span class="corner">03</span><div class="num" data-value="{{ reduction }}" data-suffix="%">0%</div><div class="label">Noise Filtered</div></div>
    <div class="stat-box"><span class="corner">04</span><div class="num" data-value="{{ techniques_seen }}" data-suffix="">0</div><div class="label">ATT&CK Techniques Hit</div></div>
  </div>

  <div class="section-label">MITRE ATT&amp;CK Coverage &mdash; lit cells = detected · color = max severity</div>
  <div class="matrix">
    {% for col in matrix %}
    <div class="col">
      <div class="col-head">{{ col.tactic }}</div>{% for tech in col.techniques %}
      <div class="cell {{ 'hit' if tech.hit else '' }} {{ 'glow' if tech.hit and tech.color == colors['critical'] else '' }}" {% if tech.hit %}style="background:{{ tech.color }};" title="{{ tech.id }} — {{ tech.count }} alert(s)"{% endif %}>
        {{ tech.id }}{% if tech.hit %}<span class="count">{{ tech.count }}</span>{% endif %}
      </div>
      {% endfor %}
    </div>
    {% endfor %}
  </div>


  {% if host_stats %}
  <div class="section-label">Severity Heatmap &mdash; Top Hosts by Alert Volume</div>
  {% for hs in host_stats %}
  <div class="heatmap-row">
    <div class="heatmap-host">{{ hs.host }}</div>
    <div class="heatmap-bar-wrap"><div class="heatmap-bar" style="width:{{ hs.pct }}%;"></div></div>
    <div class="heatmap-count">{{ hs.count }}</div>
  </div>
  {% endfor %}
  {% endif %}
  <div class="section-label">Incident Case Files</div>
  <div class="controls">
    <button class="pill active" data-sev="all" style="color:var(--acid); border-color:var(--acid);">All</button>
    {% for s in severities %}
    <button class="pill" data-sev="{{ s }}" style="color:{{ colors[s] }}; border-color:{{ colors[s] }}55;">{{ s }}</button>
    {% endfor %}
    <input class="search" id="search" placeholder="grep host or ip...">
  </div>

  <div id="cases">
  {% for inc in incidents %}
  <div class="case" style="--i:{{ loop.index }};" data-sev="{{ inc.max_severity }}" data-host="{{ (inc.host ~ ' ' ~ (inc.source_ip or '')) | lower }}">

    {# ── LEDGER: vertical severity rail ── #}
    <aside class="case-ledger" aria-hidden="true">
      <div class="ledger-sev">{{ inc.max_severity }}</div>
      <div class="ledger-tick"></div>
      <div class="ledger-num">{{ inc.alert_count }}<small>signals</small></div>
      <div class="ledger-status">OPEN</div>
    </aside>

    {# ── HEADER STRIP ── #}
    <div class="case-header">
      <div class="case-asset">
        <div class="host">{{ inc.host }}</div>
        <div class="id-line">
          <span class="ip">{{ inc.source_ip or 'no external IP' }}</span>
          <span class="sep">│</span>
          <span>{{ inc.alert_count }} alerts</span>
        </div>
      </div>
      <div class="case-meta">
        <span class="case-id">CASE-{{ "%03d"|format(inc.case_number) }}</span>
        <span class="case-window">{{ inc.start_time }} &rarr; {{ inc.end_time }}</span>
        <button type="button" class="pill ai-context-btn" data-context='{{ inc.context_json | tojson | e }}' data-label="CASE-{{ "%03d"|format(inc.case_number) }}" style="border-color:var(--cyan);color:var(--cyan);font-size:9px;padding:4px 10px;margin-top:4px;">Ask Hisn AI</button>
      </div>
    </div>

    {# ── BRIEFING + KILL CHAIN ── #}
    <div class="case-briefing">
      <div class="briefing-eyebrow">
        Intelligence Briefing
        <span class="ai-chip">AI-DRAFTED · VERIFY</span>
      </div>
      {% if inc.ai_summary %}
        <div class="briefing-body">{{ inc.ai_summary }}</div>
      {% else %}
        <div class="briefing-empty">// no analyst note generated for this case</div>
      {% endif %}
      <div class="chain-block">
        <div class="chain-label">Attack Progression · Kill Chain</div>
        <div class="chain">
          {% for label, active in inc.chain %}<div class="stage {{ 'active' if active else '' }}">{{ label }}</div>{% endfor %}
        </div>
      </div>
    </div>

    {# ── EVIDENCE LEDGER (right column) ── #}
    <aside class="case-evidence">
      <div class="ev-block">
        <div class="ev-head">MITRE Techniques</div>
        <div class="ev-row">{{ inc.mitre_techniques }}</div>
      </div>
      <div class="ev-block">
        <div class="ev-head">Detection Rules</div>
        <div class="ev-rule">{{ inc.rule_names }}</div>
      </div>
      {% if inc.ip_intel %}
      <div class="ev-block">
        <div class="ev-head">IP Reputation</div>
        {% if inc.ip_intel.mode == 'internal' %}
          <div class="ioc-muted">Internal address — not externally routable.</div>
        {% else %}
          {% if inc.ip_intel.mode == 'live' %}
          <div class="repu">
            <div class="repu-score" style="color:{{ '#E0483E' if inc.ip_intel.abuse_score >= 50 else ('#D9B44A' if inc.ip_intel.abuse_score >= 20 else '#7BE6FF') }};">
              {{ inc.ip_intel.abuse_score }}<small>% abuse</small>
            </div>
            <div class="repu-meta">
              {{ inc.ip_intel.country or 'Unknown' }} · {{ inc.ip_intel.isp or 'Unknown ISP' }}<br>
              <span class="muted">{{ inc.ip_intel.total_reports }} report(s)</span>
              <div class="repu-links">
                <a href="{{ inc.ip_intel.link }}" target="_blank" class="ioc-link">AbuseIPDB &rarr;</a>
                <a href="https://viz.greynoise.io/ip/{{ inc.source_ip }}" target="_blank" class="ioc-link">GreyNoise &rarr;</a>
                <a href="https://www.shodan.io/host/{{ inc.source_ip }}" target="_blank" class="ioc-link">Shodan &rarr;</a>
              </div>
            </div>
          </div>
          {% else %}
          <div class="ioc-muted">{{ inc.ip_intel.message }}</div>
          <div class="repu-links" style="margin-top:6px;">
            <a href="{{ inc.ip_intel.link }}" target="_blank" class="ioc-link">AbuseIPDB &rarr;</a>
            <a href="https://viz.greynoise.io/ip/{{ inc.source_ip }}" target="_blank" class="ioc-link">GreyNoise &rarr;</a>
          </div>
          {% endif %}
        {% endif %}
      </div>
      {% endif %}
      {% if inc.iocs and (inc.iocs.ips or inc.iocs.hashes or inc.iocs.files) %}
      <div class="ev-block">
        <div class="ev-head">Indicators of Compromise</div>
        {% if inc.iocs.ips %}
        <div class="ev-row">
          <span class="k">IPs</span>
          {% for ip in inc.iocs.ips %}
          <div style="margin:3px 0;">
            <span class="tag-ok">{{ ip }}</span>
            <a href="https://www.abuseipdb.com/check/{{ ip }}" target="_blank" class="ioc-link" style="font-size:9px;">AbuseIPDB</a>
            <a href="https://viz.greynoise.io/ip/{{ ip }}" target="_blank" class="ioc-link" style="font-size:9px;margin-left:6px;">GreyNoise</a>
          </div>
          {% endfor %}
        </div>
        {% endif %}
        {% if inc.iocs.files %}<div class="ev-row"><span class="k">Files</span>{% for f in inc.iocs.files %}<span class="tag-ok">{{ f }}</span>{% endfor %}</div>{% endif %}
        {% if inc.iocs.hashes %}
        <div style="margin-top:8px;"><span class="k" style="display:block;margin-bottom:4px;font-size:9px;letter-spacing:.22em;text-transform:uppercase;color:var(--meta);">Hashes (SHA256)</span></div>
        {% for h in inc.iocs.hashes %}
        <div class="hash-row">
          <span class="tag-ok" style="font-size:9px;">{{ h }}</span>
          <span class="hash-links">
            <a href="https://www.virustotal.com/gui/file/{{ h }}" target="_blank" class="ioc-link">VirusTotal &rarr;</a>
            <a href="https://www.hybrid-analysis.com/search?query={{ h }}" target="_blank" class="ioc-link">Hybrid &rarr;</a>
            <a href="https://bazaar.abuse.ch/browse.php?search=sha256%3A{{ h }}" target="_blank" class="ioc-link">MalwareBazaar &rarr;</a>
            <a href="https://tria.ge/s?q={{ h }}" target="_blank" class="ioc-link">Triage &rarr;</a>
          </span>
        </div>
        {% endfor %}
        {% endif %}
      </div>
      {% endif %}
    </aside>

    {# ── FOOTER: drawers for Detection Logic, Remediation, Raw Events ── #}
    <div class="case-footer">
      <div class="case-footer-bar">
        <details class="drawer">
          <summary>Detection Logic <span class="count-chip">{{ inc.rule_explanations|length }}</span></summary>
          <div class="drawer-body">
            {% for r in inc.rule_explanations %}
            <div class="rem-item">
              <span class="rem-tech">{{ r.name }}</span>
              <a href="{{ r.sigmahq_link }}" target="_blank" class="ioc-link" style="margin-left:10px;font-size:9px;">SigmaHQ &rarr;</a>
              <ul><li>{{ r.description }}</li></ul>
              {% if r.logic %}<div class="excerpt" style="margin-top:6px;font-size:10px;">{{ r.logic }}</div>{% endif %}
            </div>
            {% endfor %}
          </div>
        </details>
        <details class="drawer">
          <summary>Remediation Playbook <span class="count-chip">{{ inc.remediation|length }}</span></summary>
          <div class="drawer-body">
            {% for r in inc.remediation %}
            <div class="rem-item">
              <span class="rem-tech">{{ r.id }}</span><span class="rem-cat">{{ r.category }}</span>
              <a href="{{ r.mitre_link }}" target="_blank" class="ioc-link" style="margin-left:10px;font-size:9px;">MITRE ATT&amp;CK &rarr;</a>
              <a href="{{ r.d3fend_link }}" target="_blank" class="ioc-link" style="font-size:9px;">D3FEND &rarr;</a>
              <ul>{% for step in r.steps %}<li>{{ step }}</li>{% endfor %}</ul>
            </div>
            {% endfor %}
          </div>
        </details>
        {% if inc.raw_events and inc.raw_events.events %}
        <details class="drawer">
          <summary>Raw Events <span class="count-chip">{{ inc.raw_events.shown }}/{{ inc.raw_events.total }}</span></summary>
          <div class="drawer-body">
            {% for ev in inc.raw_events.events %}
            <div class="rem-item">
              <span class="rem-tech">{{ ev.rule }}</span>
              <span class="rem-cat" style="background:var(--cyan);color:var(--bg);">EID {{ ev.event_id }}</span>
              <div style="color:var(--meta);font-size:10px;margin-top:4px;">{{ ev.timestamp }}</div>
              <div class="excerpt">{{ ev.raw }}</div>
            </div>
            {% endfor %}
          </div>
        </details>
        {% endif %}
      </div>
    </div>

  </div>
  {% endfor %}
  </div>
  {% endif %}

  </div>

  <div id="tab-docs" class="tab-panel">
    <div class="subline" style="margin:0 0 18px;"><span class="ai-dot" style="background:var(--cyan); box-shadow:0 0 10px var(--cyan);"></span>STATIC ANALYSIS ONLY &mdash; NOTHING IS EXECUTED &mdash; PDF / WORD / EXCEL / POWERPOINT</div>
    <form class="dropzone simple" id="docForm">
      <p style="color:var(--meta);">Choose a document to statically inspect for macros, embedded URLs/IPs, dangerous PDF objects, and VirusTotal hash reputation.</p>
      <input type="file" name="file" id="docFileInput" accept=".pdf,.doc,.docx,.docm,.xls,.xlsx,.xlsm,.ppt,.pptx,.pptm" required>
      <br>
      <button class="browse-btn" type="submit" style="margin-top:14px;">Scan File</button>
    </form>
    <div class="error-text" id="docError"></div>
    <div id="docResults"></div>
  </div>
  <div id="tab-phishing" class="tab-panel">
    <div class="subline" style="margin:0 0 18px;"><span class="ai-dot" style="background:var(--amber);box-shadow:0 0 10px var(--amber);"></span>EMAIL &amp; PHISHING INVESTIGATION &mdash; .EML &middot; .MSG &middot; SCREENSHOTS</div>
    <div class="dropzone simple" id="phishingDropzone" style="text-align:center;">
      <svg class="upload-icon" width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
      <p style="color:var(--meta);margin-top:8px;">Drop an .eml, .msg, or screenshot to begin investigation</p>
      <p style="color:var(--acid);font-size:10px;letter-spacing:.08em;margin-top:6px;opacity:.8;">&#9650; For the most complete analysis, use an .eml or .msg file. Screenshots can extract visible text only — headers and auth data will be unavailable.</p>
      <button class="browse-btn" type="button" id="phishingBrowseBtn">Choose Email or Screenshot</button>
      <input type="file" id="phishingFileInput" accept=".eml,.msg,.png,.jpg,.jpeg,.webp,.bmp,.gif,.tiff" style="display:none;">
    </div>
    <div class="error-text" id="phishingError"></div>
    <div id="phishingResults"></div>
  </div>



</main>

<div id="term">
  <div class="bar"><div class="dots"><span></span><span></span><span></span></div><span>// hisn · terminal · type 'help'</span></div>
  <div class="body" id="termBody">
    <div><span class="prompt">root@hisn</span>:~$ <span style="color:var(--meta);">welcome. try: help, whoami, scan, joke, matrix, declassify, clear</span></div>
    <div style="margin-top:6px;"><span class="prompt">root@hisn</span>:~$ <input id="termIn" autocomplete="off" spellcheck="false"></div>
  </div>
</div>

<script>
  window.AI_GLOBAL_CONTEXT = {{ global_context_str | tojson }};

  function escapeHtml(s) {
    if (s == null) return '';
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  const dz = document.getElementById('dropzone');
  const input = document.getElementById('fileInput');
  const browseBtn = document.getElementById('browseBtn');
  const progress = document.getElementById('progress');
  const stageText = document.getElementById('stageText');
  browseBtn.addEventListener('click', () => input.click());
  dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag'));
  dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('drag'); if (e.dataTransfer.files.length) sendFile(e.dataTransfer.files[0]); });
  input.addEventListener('change', () => { if (input.files.length) sendFile(input.files[0]); });
  function sendFile(file) {
    if (!file.name.toLowerCase().endsWith('.evtx')) { alert('Please choose a .evtx file'); return; }
    const fd = new FormData(); fd.append('file', file);
    progress.classList.add('show'); stageText.textContent = 'Uploading ' + file.name + '...';
    fetch('/upload', { method:'POST', body:fd }).then(r => r.json())
      .then(d => { if (d.error) { stageText.textContent = 'Error: ' + d.error; } else { poll(); } })
      .catch(() => stageText.textContent = 'Upload failed');
  }
  function poll() {
    fetch('/status').then(r => r.json()).then(j => {
      stageText.textContent = j.stage || 'Working...';
      if (j.done) {
        if (j.error) { stageText.textContent = 'Error: ' + j.error; }
        else { stageText.textContent = 'Analysis complete — loading...'; setTimeout(() => location.reload(), 600); }
      } else { setTimeout(poll, 1000); }
    });
  }
  const clearBtn = document.getElementById('clearBtn');
  if (clearBtn) clearBtn.addEventListener('click', () => {
    if (confirm('Clear all current results and start fresh?')) {
      fetch('/clear', { method: 'POST' }).then(() => location.reload());
    }
  });
  const pills = document.querySelectorAll('.controls .pill');
  const search = document.getElementById('search');
  let activeSev = 'all';
  function applyFilters() {
    const q = (search && search.value || '').toLowerCase();
    document.querySelectorAll('.case').forEach(c => {
      const sevOk = activeSev === 'all' || c.dataset.sev === activeSev;
      const hostOk = c.dataset.host.includes(q);
      c.classList.toggle('hidden', !(sevOk && hostOk));
    });
  }
  pills.forEach(p => p.addEventListener('click', () => {
    pills.forEach(x => x.classList.remove('active')); p.classList.add('active');
    activeSev = p.dataset.sev; applyFilters();
  }));
  var _sT;
  if (search) search.addEventListener('input', () => {
    clearTimeout(_sT); _sT = setTimeout(applyFilters, 150);
  });

  function animateCount(el) {
    const target = parseFloat(el.dataset.value);
    if (isNaN(target)) return;
    const suffix = el.dataset.suffix || '';
    const isFloat = el.dataset.value.indexOf('.') !== -1;
    const duration = 700;
    const start = performance.now();
    function step(ts) {
      const p = Math.min((ts - start) / duration, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      const current = target * eased;
      el.textContent = (isFloat ? current.toFixed(1) : Math.round(current)) + suffix;
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }
  document.querySelectorAll('.stat-box .num[data-value]').forEach(animateCount);

  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabPanels = document.querySelectorAll('.tab-panel');
  tabBtns.forEach(btn => btn.addEventListener('click', () => {
    tabBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    tabPanels.forEach(p => { if(p) p.classList.remove('active'); });
    var _tp = document.getElementById(btn.dataset.tab);
    if (_tp) _tp.classList.add('active');
  }));

  (function settingsPanel(){
    const btn = document.getElementById('settingsBtn');
    const panel = document.getElementById('settingsPanel');
    const closeBtn = document.getElementById('settingsCloseBtn');
    const abuseInput = document.getElementById('keyAbuseIPDB');
    const vtInput = document.getElementById('keyVirusTotal');
    const saveBtn = document.getElementById('settingsSaveBtn');
    const msg = document.getElementById('settingsMsg');
    if (!btn) return;
    function openPanel() {
      panel.style.display = 'block';
      fetch('/api/settings').then(r => r.json()).then(d => {
        abuseInput.value = d.abuseipdb || '';
        vtInput.value = d.virustotal || '';
      });
    }
    function closePanel() { panel.style.display = 'none'; }
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (panel.style.display === 'block') closePanel(); else openPanel();
    });
    closeBtn.addEventListener('click', closePanel);
    document.addEventListener('click', (e) => {
      if (panel.style.display === 'block' && !panel.contains(e.target) && e.target !== btn) closePanel();
    });
    saveBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      fetch('/api/settings', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ abuseipdb: abuseInput.value.trim(), virustotal: vtInput.value.trim() })
      }).then(r => r.json()).then(() => {
        msg.textContent = 'Saved. Next analysis uses these automatically.';
        toast('◉ API keys saved locally');
      });
    });
  })();

  (function aiWidget(){
    const widget = document.getElementById('aiWidget');
    const toggleBtn = document.getElementById('aiWidgetToggle');
    const panel = document.getElementById('aiWidgetPanel');
    const header = document.getElementById('aiWidgetHeader');
    const minimizeBtn = document.getElementById('aiMinimizeBtn');
    const clearBtn2 = document.getElementById('aiClearBtn');
    const messagesEl = document.getElementById('aiMessages');
    const chipsEl = document.getElementById('aiChips');
    const aiInput = document.getElementById('aiInput');
    const sendBtn = document.getElementById('aiSendBtn');
    const resizeHandle = document.getElementById('aiResizeHandle');
    const contextLabel = document.getElementById('aiContextLabel');

    let state = {};
    try { state = JSON.parse(sessionStorage.getItem('aiWidgetState') || '{}'); } catch(e) { state = {}; }
    state.messages = state.messages || [];
    state.context = state.context || { type: 'none', data: null, label: '' };
    state.expanded = state.expanded || false;
    state.pos = state.pos || null;

    function saveState() { sessionStorage.setItem('aiWidgetState', JSON.stringify(state)); }

    const PRESETS = [
      {key:'summarize', label:'Summarize Investigation', contexts:['incident','document','email']},
      {key:'explain_alert', label:'Explain Selected Alert', contexts:['incident']},
      {key:'false_positive', label:'Is This a False Positive?', contexts:['incident','document','email']},
      {key:'next_steps', label:'What Should I Investigate Next?', contexts:['incident','document','email']},
      {key:'containment', label:'Containment Recommendations', contexts:['incident']},
      {key:'exec_summary', label:'Generate Executive Summary', contexts:['incident','document','email']},
      {key:'analyst_report', label:'Generate Analyst Report', contexts:['incident']},
      {key:'kql', label:'Generate KQL', contexts:['incident']},
      {key:'splunk', label:'Generate SPL', contexts:['incident']},
      {key:'sigma', label:'Generate Sigma Rule', contexts:['incident']},
      {key:'junior', label:'Explain to a Junior Analyst', contexts:['incident','document','email']},
    ];

    function renderChips() {
      const applicable = PRESETS.filter(p => p.contexts.includes(state.context.type));
      chipsEl.innerHTML = '';
      if (!applicable.length) {
        chipsEl.innerHTML = '<span class="ioc-muted" style="font-size:10px;">Select a case or scanned document for suggestions, or just ask below.</span>';
        return;
      }
      applicable.forEach(p => {
        const b = document.createElement('button');
        b.type = 'button'; b.textContent = p.label; b.dataset.preset = p.key;
        b.addEventListener('click', () => sendMessage('', p.key));
        chipsEl.appendChild(b);
      });
    }

    function renderCode(text) {
      const parts = String(text).split('```');
      let html = '';
      parts.forEach((part, i) => {
        if (i % 2 === 1) {
          const firstNl = part.indexOf('\\n');
          const body = firstNl >= 0 ? part.slice(firstNl + 1) : part;
          html += '<pre class="ai-code"><code>' + escapeHtml(body) + '</code></pre>';
        } else {
          html += escapeHtml(part).replace(/\\n/g, '<br>');
        }
      });
      return html;
    }

    function renderMessages() {
      messagesEl.innerHTML = '';
      state.messages.forEach(m => {
        const div = document.createElement('div');
        div.className = 'ai-msg ' + m.role;
        const label = m.role === 'user' ? 'YOU' : 'AI ASSISTANT';
        div.innerHTML = '<span class="ai-msg-label">' + label + '</span><div class="ai-bubble">' + renderCode(m.text) + '</div>';
        if (m.role === 'assistant') {
          const copyBtn = document.createElement('button');
          copyBtn.className = 'ai-copy-btn'; copyBtn.type = 'button'; copyBtn.textContent = 'Copy';
          copyBtn.addEventListener('click', () => navigator.clipboard.writeText(m.text));
          div.appendChild(copyBtn);
        }
        messagesEl.appendChild(div);
      });
      messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    function updateContextBanner() {
      const banner = document.getElementById('aiContextBanner');
      if (!banner) return;
      if (state.context.type === 'none') {
        banner.textContent = 'No case or document selected — click "Ask AI About This Case" on a case, or ask a general question below.';
        banner.classList.remove('has-context');
      } else {
        const kind = state.context.type === 'incident' ? 'Case' :
                     state.context.type === 'email' ? 'Email' : 'Document';
        banner.textContent = 'Currently referencing: ' + kind + ' — ' + (state.context.label || 'unnamed');
        banner.classList.add('has-context');
      }
    }
    function setContext(type, data, label) {
      state.context = { type: type, data: data, label: label };
      contextLabel.textContent = label ? (' · ' + label) : '';
      updateContextBanner();
      renderChips();
      saveState();
    }
    window.aiSetContext = setContext;

    function sendMessage(question, preset) {
      let displayText = question;
      if (preset) {
        const p = PRESETS.find(x => x.key === preset);
        displayText = p ? p.label : preset;
      }
      if (!displayText) return;
      state.messages.push({ role: 'user', text: displayText });
      renderMessages();
      const typingDiv = document.createElement('div');
      typingDiv.className = 'ai-msg assistant';
      typingDiv.innerHTML = '<span class="ai-msg-label">AI ASSISTANT</span><div class="ai-bubble"><div class="ai-typing"><span></span><span></span><span></span></div></div>';
      messagesEl.appendChild(typingDiv);
      messagesEl.scrollTop = messagesEl.scrollHeight;
      sendBtn.disabled = true; sendBtn.style.opacity = '0.6';

      fetch('/ai-chat', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ context_type: state.context.type, context: state.context.data, question: question, preset: preset, global_context: window.AI_GLOBAL_CONTEXT || '' })
      }).then(r => r.json()).then(d => {
        typingDiv.remove();
        const answer = d.error ? ('Error: ' + d.error) : d.answer;
        state.messages.push({ role: 'assistant', text: answer });
        renderMessages();
        saveState();
        sendBtn.disabled = false; sendBtn.style.opacity = '1';
      }).catch(() => {
        typingDiv.remove();
        state.messages.push({ role: 'assistant', text: 'Request failed. Check that Ollama is running.' });
        renderMessages();
        saveState();
        sendBtn.disabled = false; sendBtn.style.opacity = '1';
      });
    }

    sendBtn.addEventListener('click', () => { const q = aiInput.value.trim(); if (q) { sendMessage(q, null); aiInput.value = ''; } });
    aiInput.addEventListener('keydown', e => { if (e.key === 'Enter') sendBtn.click(); });
    clearBtn2.addEventListener('click', () => { state.messages = []; renderMessages(); saveState(); });

    function applyPos() {
      if (state.pos) {
        panel.style.left = state.pos.left + 'px';
        panel.style.top = state.pos.top + 'px';
        panel.style.right = 'auto'; panel.style.bottom = 'auto';
        panel.style.width = state.pos.width + 'px';
        panel.style.height = state.pos.height + 'px';
      }
    }
    function ensurePosInitialized() {
      if (!state.pos) {
        const rect = panel.getBoundingClientRect();
        state.pos = { left: rect.left, top: rect.top, width: rect.width, height: rect.height };
        applyPos(); saveState();
      }
    }
    function expand() {
      widget.classList.add('expanded'); state.expanded = true;
      applyPos();
      requestAnimationFrame(ensurePosInitialized);
      saveState();
    }
    function collapse() { widget.classList.remove('expanded'); state.expanded = false; saveState(); }
    const callout = document.getElementById('aiCallout');
    function hideCallout() { if (callout) { callout.classList.add('hidden'); sessionStorage.setItem('aiCalloutSeen', '1'); } }
    if (callout && sessionStorage.getItem('aiCalloutSeen')) callout.classList.add('hidden');
    const calloutClose = document.getElementById('aiCalloutClose');
    if (calloutClose) calloutClose.addEventListener('click', e => { e.stopPropagation(); hideCallout(); });
    const calloutOpen = document.getElementById('aiCalloutOpenBtn');
    if (calloutOpen) calloutOpen.addEventListener('click', () => { expand(); });
    toggleBtn.addEventListener('click', expand);
    minimizeBtn.addEventListener('click', collapse);

    let dragging = false, dragOffX = 0, dragOffY = 0;
    header.addEventListener('mousedown', e => {
      if (e.target.closest('button')) return;
      ensurePosInitialized();
      dragging = true;
      const rect = panel.getBoundingClientRect();
      dragOffX = e.clientX - rect.left; dragOffY = e.clientY - rect.top;
      e.preventDefault();
    });
    let resizing = false, resizeStartX, resizeStartY, resizeStartW, resizeStartH, resizeStartLeft, resizeStartTop;
    resizeHandle.addEventListener('mousedown', e => {
      ensurePosInitialized();
      resizing = true;
      resizeStartX = e.clientX; resizeStartY = e.clientY;
      resizeStartW = state.pos.width; resizeStartH = state.pos.height;
      resizeStartLeft = state.pos.left; resizeStartTop = state.pos.top;
      e.preventDefault(); e.stopPropagation();
    });
    document.addEventListener('mousemove', e => {
      if (dragging) {
        state.pos.left = e.clientX - dragOffX; state.pos.top = e.clientY - dragOffY;
        panel.style.left = state.pos.left + 'px'; panel.style.top = state.pos.top + 'px';
      }
      if (resizing) {
        const dx = resizeStartX - e.clientX, dy = resizeStartY - e.clientY;
        const newW = Math.max(300, resizeStartW + dx), newH = Math.max(320, resizeStartH + dy);
        state.pos.width = newW; state.pos.height = newH;
        state.pos.left = resizeStartLeft - dx; state.pos.top = resizeStartTop - dy;
        panel.style.width = newW + 'px'; panel.style.height = newH + 'px';
        panel.style.left = state.pos.left + 'px'; panel.style.top = state.pos.top + 'px';
      }
    });
    document.addEventListener('mouseup', () => {
      if (dragging) { dragging = false; saveState(); }
      if (resizing) { resizing = false; saveState(); }
    });

    if (state.expanded) { widget.classList.add('expanded'); applyPos(); }
    contextLabel.textContent = state.context.label ? (' · ' + state.context.label) : '';
    updateContextBanner();
    renderChips();
    renderMessages();

    document.querySelectorAll('.ai-context-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        let data = {};
        try { data = JSON.parse(btn.dataset.context); } catch(e) {}
        setContext('incident', data, btn.dataset.label);
        if (!state.expanded) toggleBtn.click();
      });
    });
  })();

  function escapeHtmlDoc(s) { return escapeHtml(s); }
  function renderDocResult(result) {
    let html = '<div class="card">';
    html += `<div class="kv"><b>File:</b> ${escapeHtml(result.filename)}</div>`;
    html += `<div class="kv"><b>Type:</b> ${escapeHtml(result.file_type)}</div>`;

    if (result.file_type === 'office') {
      html += '<div class="section-label">Macro Analysis</div>';
      if (result.macros_found) {
        html += `<div class="kv"><b>Macros found in:</b> ${escapeHtml((result.macro_streams||[]).join(', '))}</div>`;
        if (result.suspicious_keywords && result.suspicious_keywords.length) {
          html += '<div style="margin-top:6px;">' + result.suspicious_keywords.map(k => `<span class="tag-flag">${escapeHtml(k)}</span>`).join('') + '</div>';
        } else {
          html += '<div class="empty">Macros present, but none of the watched suspicious keywords were found.</div>';
        }
      } else {
        html += '<div class="empty">No VBA macros detected in this file.</div>';
      }
    }

    if (result.file_type === 'pdf') {
      html += '<div class="section-label">PDF Object Scan</div>';
      if (result.dangerous_tags && result.dangerous_tags.length) {
        html += '<div>' + result.dangerous_tags.map(t => `<span class="tag-flag">${escapeHtml(t.tag)} &times;${t.count}</span>`).join('') + '</div>';
        html += '<div class="empty">These tags alone are not proof of malice (e.g. /OpenAction is common for setting an initial page view) — context and combination matter. /JavaScript or /Launch alongside /OpenAction is the higher-signal pattern.</div>';
      } else {
        html += '<div class="empty">No flagged PDF object tags found.</div>';
      }
    }

    html += '<div class="section-label">Extracted Indicators</div>';
    const ind = result.text_indicators || {urls:[], ips:[], flags:[]};
    let anyInd = false;
    if (ind.urls && ind.urls.length) {
      anyInd = true;
      html += '<div class="kv"><b>URLs:</b></div>' + ind.urls.map(u => `<span class="tag-ok">${escapeHtml(u)}</span> <a href="https://urlscan.io/search/#${encodeURIComponent(u)}" target="_blank" class="ioc-link" style="font-size:10px;">(check on urlscan.io &rarr;)</a>`).join('<br>');
    }
    if (ind.ips && ind.ips.length) { anyInd = true; html += '<div class="kv" style="margin-top:8px;"><b>IPs:</b></div>' + ind.ips.map(ip => `<span class="tag-ok">${escapeHtml(ip)}</span>`).join(''); }
    if (ind.flags && ind.flags.length) { anyInd = true; html += '<div class="kv" style="margin-top:8px;"><b>Other notable strings:</b></div>' + ind.flags.map(fl => `<span class="tag-ok">${escapeHtml(fl)}</span>`).join(''); }
    if (!anyInd) html += '<div class="empty">No URLs, IPs, or notable embedded strings found.</div>';

    html += '<div class="section-label">VirusTotal Hash Reputation</div>';
    if (result.sha256) html += `<div class="kv"><b>SHA256:</b> ${escapeHtml(result.sha256)}</div>`;
    const vt = result.vt_intel;
    if (vt) {
      if (vt.mode === 'live') {
        const mal = vt.malicious || 0;
        const total = vt.total_engines || 0;
        const color = mal > 0 ? '#E0483E' : '#4C8BA8';
        html += `<div><span class="ioc-score" style="color:${color};">${mal} / ${total} engines flagged malicious</span></div>`;
        if (vt.file_names && vt.file_names.length) html += `<div class="ioc-meta">Also seen as: ${escapeHtml(vt.file_names.join(', '))}</div>`;
      } else {
        html += `<div class="ioc-muted">${escapeHtml(vt.message || '')}</div>`;
      }
      if (vt.link) html += `<a href="${vt.link}" target="_blank" class="ioc-link">Check VirusTotal &rarr;</a>`;
      if (result.sha256) {
        html += ` <a href="https://www.hybrid-analysis.com/search?query=${escapeHtml(result.sha256)}" target="_blank" class="ioc-link">Check Hybrid Analysis &rarr;</a>`;
        html += ` <a href="https://bazaar.abuse.ch/browse.php?search=sha256%3A${escapeHtml(result.sha256)}" target="_blank" class="ioc-link">Check MalwareBazaar &rarr;</a>`;
        html += ` <a href="https://tria.ge/s?q=${escapeHtml(result.sha256)}" target="_blank" class="ioc-link">Check Triage &rarr;</a>`;
        html += ` <a href="https://otx.alienvault.com/indicator/file/${escapeHtml(result.sha256)}" target="_blank" class="ioc-link">Check AlienVault OTX &rarr;</a>`;
      }
      html += '<div class="ioc-muted" style="margin-top:6px;">If any of these report this hash as malicious, do not open or run this file.</div>';
    }

    if (result.body_text_excerpt) {
      html += `<div class="section-label">Text Excerpt</div><div class="excerpt">${escapeHtml(result.body_text_excerpt)}</div>`;
    }
    if (result.errors && result.errors.length) {
      html += '<div class="section-label">Notes</div>' + result.errors.map(e => `<div class="empty">${escapeHtml(e)}</div>`).join('');
    }
    html += '<div style="margin-top:16px; display:flex; gap:10px; flex-wrap:wrap;">';
    html += '<button class="browse-btn" type="button" id="docReportBtn">Download PDF Report</button>';
    html += '<button class="pill" type="button" id="docAiContextBtn" style="border-color:var(--cyan); color:var(--cyan);">Ask AI About This Document</button>';
    html += '</div>';
    html += '</div>';
    return html;
  }

  let lastDocResult = null;

  const docForm = document.getElementById('docForm');
  const docResults = document.getElementById('docResults');
  const docError = document.getElementById('docError');
  docForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const fd = new FormData(docForm);
    docError.textContent = '';
    docResults.innerHTML = '<div class="empty">Scanning...</div>';
    fetch('/scan-document', { method: 'POST', body: fd })
      .then(r => r.json())
      .then(data => {
        if (data.error) { docError.textContent = data.error; docResults.innerHTML = ''; }
        else {
          lastDocResult = data;
          docResults.innerHTML = renderDocResult(data);
          const btn = document.getElementById('docReportBtn');
          if (btn) btn.addEventListener('click', () => {
            fetch('/report/document', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(lastDocResult) })
              .then(r => r.blob())
              .then(blob => {
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url; a.download = 'hisn_document_report.pdf';
                document.body.appendChild(a); a.click(); a.remove();
                URL.revokeObjectURL(url);
              });
          });
          const aiBtn = document.getElementById('docAiContextBtn');
          if (aiBtn) aiBtn.addEventListener('click', () => {
            window.aiSetContext('document', lastDocResult, lastDocResult.filename || 'Document');
            document.getElementById('aiWidgetToggle').click();
          });
        }
      })
      .catch(() => { docError.textContent = 'Scan failed.'; docResults.innerHTML = ''; });
  });

  (function clocks(){
    const c = document.getElementById('clock'), u = document.getElementById('utc'), tc = document.getElementById('threatcon');
    const critCount = document.querySelectorAll('.case[data-sev="critical"]').length;
    const highCount = document.querySelectorAll('.case[data-sev="high"]').length;
    let level = 'MONITOR', color = 'var(--acid)';
    if (critCount > 0) { level = 'DELTA · ACTIVE BREACH'; color = 'var(--crimson)'; }
    else if (highCount > 0) { level = 'BRAVO · ELEVATED'; color = 'var(--amber)'; }
    if (tc) { tc.textContent = 'THREATCON · ' + level; tc.style.borderColor = color; tc.style.color = color; tc.querySelector && (tc.style.color = color);}
    function tick(){
      const d = new Date();
      const z = n => String(n).padStart(2,'0');
      if (c) c.textContent = z(d.getHours())+':'+z(d.getMinutes())+':'+z(d.getSeconds());
      if (u) u.textContent = z(d.getUTCHours())+':'+z(d.getUTCMinutes())+':'+z(d.getUTCSeconds());
    }
    tick(); setInterval(tick, 1000);
  })();

  (function rain(){
    const cv = document.getElementById('rain'); if (!cv) return;
    const ctx = cv.getContext('2d', { alpha: false }); // alpha:false skips compositing overhead
    let w, h, cols, drops, paused = false, lastTs = 0;
    const FPS_INTERVAL = 1000 / 30; // 30fps — imperceptible vs 60fps for slow-falling chars
    const chars = 'アァカサタナハマヤラワ0123456789ABCDEF<>/\\|+-*=#$%@'.split('');
    function size(){
      w = cv.width = innerWidth; h = cv.height = innerHeight;
      cols = Math.floor(w / 14);
      drops = new Array(cols).fill(0).map(() => Math.random() * h);
    }
    size();
    let _resizeT;
    addEventListener('resize', () => { clearTimeout(_resizeT); _resizeT = setTimeout(size, 150); });
    // Zero GPU cost when tab is not visible
    document.addEventListener('visibilitychange', () => { paused = document.hidden; });
    function frame(ts){
      requestAnimationFrame(frame);
      if (paused) return;
      if (ts - lastTs < FPS_INTERVAL) return;
      lastTs = ts;
      ctx.fillStyle = 'rgba(3,6,8,0.08)'; ctx.fillRect(0, 0, w, h);
      ctx.fillStyle = '#7CFFB2'; ctx.font = '13px JetBrains Mono';
      for (let i = 0; i < cols; i++) {
        const ch = chars[Math.floor(Math.random() * chars.length)];
        const x = i * 14, y = drops[i];
        ctx.fillText(ch, x, y);
        drops[i] = y > h + Math.random() * 200 ? 0 : y + 6;
      }
    }
    requestAnimationFrame(frame);
  })();

  function toast(msg, kind){
    const t = document.createElement('div'); t.className = 'toast' + (kind==='crit'?' crit':''); t.textContent = msg;
    document.getElementById('toasts').appendChild(t);
    setTimeout(()=>{ t.style.opacity='0'; t.style.transform='translateX(20px)'; t.style.transition='all .3s'; setTimeout(()=>t.remove(), 300); }, 4200);
  }

  let actx = null;
  function beep(freq, dur, type){
    try{
      if (!actx) actx = new (window.AudioContext||window.webkitAudioContext)();
      const o = actx.createOscillator(), g = actx.createGain();
      o.type = type||'sine'; o.frequency.value = freq||880;
      o.connect(g); g.connect(actx.destination);
      g.gain.setValueAtTime(0, actx.currentTime);
      g.gain.linearRampToValueAtTime(0.08, actx.currentTime+0.01);
      g.gain.exponentialRampToValueAtTime(0.0001, actx.currentTime + (dur||0.15));
      o.start(); o.stop(actx.currentTime + (dur||0.15));
    } catch(e){}
  }
  document.addEventListener('click', function once(){ if(!actx){ try{ actx = new (window.AudioContext||window.webkitAudioContext)(); }catch(e){} } }, {once:true});

  window.addEventListener('load', () => {
    const crits = document.querySelectorAll('.case[data-sev="critical"]').length;
    const highs = document.querySelectorAll('.case[data-sev="high"]').length;
    if (crits > 0) { toast('⚠ '+crits+' CRITICAL incident(s) on deck. Stay sharp.', 'crit'); setTimeout(()=>beep(220,.4,'sawtooth'), 600); setTimeout(()=>beep(180,.5,'sawtooth'), 1100); }
    else if (highs > 0) { toast('▲ '+highs+' high-severity case(s) loaded.'); }
    else { toast('◉ telemetry layer online. all systems nominal.'); }
  });

  (function trail(){
    let _tLast = 0, _tHidden = false;
    document.addEventListener('visibilitychange', () => { _tHidden = document.hidden; });
    addEventListener('mousemove', e => {
      if (_tHidden) return; // skip all DOM work when tab is invisible
      const now = performance.now(); if (now - _tLast < 32) return; _tLast = now;
      const d = document.createElement('div');
      d.className = 'cursor-dot';
      // transform: no layout, compositor-only — avoids reflow cascade
      d.style.transform = 'translate(' + (e.clientX - 3) + 'px,' + (e.clientY - 3) + 'px)';
      document.body.appendChild(d);
      requestAnimationFrame(() => {
        d.style.transform = 'translate(' + (e.clientX - 7) + 'px,' + (e.clientY - 7) + 'px) scale(2.3)';
        d.style.opacity = '0';
      });
      setTimeout(() => { if (d.parentNode) d.remove(); }, 560);
    }, { passive: true });
  })();

  (function konami(){
    const seq = ['ArrowUp','ArrowUp','ArrowDown','ArrowDown','ArrowLeft','ArrowRight','ArrowLeft','ArrowRight','b','a'];
    let i = 0;
    addEventListener('keydown', e => {
      if (e.key === seq[i] || e.key.toLowerCase() === seq[i]) { i++; if (i === seq.length){ i=0; document.body.classList.toggle('declassified'); toast(document.body.classList.contains('declassified') ? '◉ DECLASSIFIED MODE ENGAGED' : '◉ reclassified'); beep(660,.1); setTimeout(()=>beep(990,.15),120);} }
      else i = 0;
    });
  })();

  (function term(){
    const t = document.getElementById('term'), inp = document.getElementById('termIn'), body = document.getElementById('termBody');
    function out(html){
      const line = document.createElement('div'); line.innerHTML = html;
      body.insertBefore(line, inp.parentElement);
      body.scrollTop = body.scrollHeight;
    }
    addEventListener('keydown', e => {
      if (e.key === '`' || e.key === '~'){ e.preventDefault(); t.classList.toggle('open'); if (t.classList.contains('open')) setTimeout(()=>inp.focus(), 100); }
      if (e.key === 'Escape' && t.classList.contains('open')) t.classList.remove('open');
    });
    inp.addEventListener('keydown', e => {
      if (e.key === 'Enter'){
        const v = inp.value.trim(); inp.value = '';
        out('<span class="prompt">root@hisn</span>:~$ '+escapeHtml(v));
        const cmd = v.toLowerCase();
        if (cmd === 'help') out('<span style="color:var(--meta);">commands: help · whoami · scan · matrix · joke · declassify · clear · exit</span>');
        else if (cmd === 'whoami') out('<span style="color:var(--acid);">analyst@hisn · clearance: TS//SCI · session: '+new Date().toISOString()+'</span>');
        else if (cmd === 'scan') { out('<span style="color:var(--amber);">[*] scanning subnet 10.0.0.0/24 ...</span>'); setTimeout(()=>out('<span style="color:var(--meta);">[fake] this is a cosmetic shell — use the dropzone for real triage</span>'), 600); }
        else if (cmd === 'matrix') { document.getElementById('rain').style.opacity = document.getElementById('rain').style.opacity==='0.6'?'0.18':'0.6'; out('matrix density toggled'); }
        else if (cmd === 'declassify'){ document.body.classList.toggle('declassified'); out('classification toggled'); }
        else if (cmd === 'joke') {
          var _jk = [
            'IR analyst finds a breach. Six months of logs. Root cause: phishing email titled URGENT. User clicked it three times.',
            'CISO: did you contain it? Analyst: we opened a ticket. Priority: medium. We had other tickets.',
            'Red team: we are in. Blue team logs: no anomalies. Red team: we have been in three months. Blue team: still nothing.',
            'Junior: how do you stay calm when everything is on fire? Senior: you stop remembering what calm was.',
            'Critical vuln found at 4:59 PM on a Friday. The on-call rotation had just switched.',
            'IOC count: 847. Confirmed malicious: 2. Hours triaging: 14. Attacker dwell time: 214 days.',
            'The playbook says isolate the host. The host is production. The playbook did not account for this.'
          ];
          if (!window._jkIdx) window._jkIdx = 0;
          out('<span style="color:var(--cyan);">' + _jk[window._jkIdx % _jk.length] + '</span>');
          window._jkIdx++;
        }
        else if (cmd === 'clear') { while(body.firstChild!==inp.parentElement) body.removeChild(body.firstChild); }
        else if (cmd === 'exit' || cmd === 'q') t.classList.remove('open');
        else if (cmd) out('<span style="color:var(--crimson);">unknown command: '+escapeHtml(v)+'</span>');
        beep(1200, .04, 'square');
      }
    });
  })();


  // PHISHING TAB
  var lastEmailResult = null;
  (function phishingTab(){
    var pdz = document.getElementById('phishingDropzone');
    var pbb = document.getElementById('phishingBrowseBtn');
    var pfi = document.getElementById('phishingFileInput');
    var per = document.getElementById('phishingError');
    var prs = document.getElementById('phishingResults');
    if (!pdz) return;
    pbb.addEventListener('click', function(){ pfi.click(); });
    pdz.addEventListener('dragover', function(e){ e.preventDefault(); pdz.style.borderColor='var(--amber)'; });
    pdz.addEventListener('dragleave', function(){ pdz.style.borderColor=''; });
    pdz.addEventListener('drop', function(e){
      e.preventDefault(); pdz.style.borderColor='';
      if (e.dataTransfer.files.length) phishScanFile(e.dataTransfer.files[0]);
    });
    pfi.addEventListener('change', function(){ if (pfi.files.length) phishScanFile(pfi.files[0]); });
    function phishScanFile(file) {
      var pext = file.name.split('.').pop().toLowerCase();
      var pallowed = ['eml','msg','png','jpg','jpeg','webp','bmp','gif','tiff','tif'];
      if (!pallowed.includes(pext)) { per.textContent='Please choose a .eml, .msg, or image file.'; return; }
      per.textContent='';
      prs.innerHTML='<div class="empty"><span class="spinner" style="display:inline-block;margin-right:8px;"></span>Analyzing — extracting headers, auth records, URLs, IOCs…</div>';
      pbb.disabled = true; pbb.style.opacity = '0.6';
      var pfd = new FormData(); pfd.append('file', file);
      fetch('/scan-email', { method:'POST', body:pfd })
        .then(function(r){ return r.json(); })
        .then(function(data){
          if (data.error){ per.textContent=data.error; prs.innerHTML=''; return; }
          lastEmailResult=data;
          prs.innerHTML=renderPhishingResult(data);
          if (window.aiSetContext) window.aiSetContext('email', data, data.filename||'Email');
          // Reset + Export buttons
          var _topBtns = document.createElement('div');
          _topBtns.style.cssText='display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;';
          _topBtns.innerHTML=
            '<button type="button" class="pill" id="phishResetBtn" style="color:var(--amber);border-color:var(--amber);">'
            +'↺ Analyze Another Email</button>'
            +'<button type="button" class="pill" id="phishExportBtn" style="color:var(--acid);border-color:var(--acid);">'
            +'↓ Export JSON</button>';
          prs.insertBefore(_topBtns, prs.firstChild);
          document.getElementById('phishResetBtn').addEventListener('click', function(){
            prs.innerHTML='';
            per.textContent='';
            pfi.value='';
            lastEmailResult=null;
            if(window.aiSetContext) window.aiSetContext('none',null,'');
            prs.style.display='';
          });
          document.getElementById('phishExportBtn').addEventListener('click', function(){
            if(!lastEmailResult) return;
            var blob=new Blob([JSON.stringify(lastEmailResult,null,2)],{type:'application/json'});
            var a=document.createElement('a');
            a.href=URL.createObjectURL(blob);
            a.download='HISN_Email_Analysis_'+(lastEmailResult.filename||'report').replace(/[^a-z0-9]/gi,'_')+'.json';
            document.body.appendChild(a); a.click(); a.remove();
            URL.revokeObjectURL(a.href);
            toast('IOC export downloaded.');
          });
          var ab=document.getElementById('phishingAiBtn');
          if (ab) ab.addEventListener('click', function(){
            if (window.aiSetContext) window.aiSetContext('email', lastEmailResult, lastEmailResult.filename||'Email');
            var wt=document.getElementById('aiWidgetToggle');
            if (wt) {
              wt.click();
              // Force update banner and chips immediately
              setTimeout(function(){
                var banner=document.getElementById('aiContextBanner');
                if(banner){banner.textContent='Referencing Email: '+(lastEmailResult.filename||'');banner.classList.add('has-context');}
              }, 100);
            }
          });
          var cb=document.getElementById('copyIocsBtn');
          if (cb) cb.addEventListener('click', function(){
            if (lastEmailResult && lastEmailResult.iocs)
              navigator.clipboard.writeText(JSON.stringify(lastEmailResult.iocs, null, 2));
              var _cb = document.getElementById('copyIocsBtn');
              if(_cb){ var _ot=_cb.textContent; _cb.textContent='Copied!'; _cb.style.color='var(--acid)'; setTimeout(function(){_cb.textContent=_ot;},1800); }
          });
        })
        .catch(function(){ per.textContent='Scan failed.'; prs.innerHTML=''; });
    }
  })();

  function renderPhishingResult(r) {
    var riskColor = r.risk_score>=70?'var(--crimson)':r.risk_score>=40?'var(--amber)':r.risk_score>=20?'var(--gold)':'var(--acid)';
    var h = '<div style="margin-top:20px;">';
    h += '<div class="ioc-box" style="border-left-color:'+riskColor+';margin-bottom:16px;">';
    h += '<span class="ioc-label">Risk Assessment</span>';
    h += '<div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap;">';
    h += '<div><span style="font-size:38px;font-weight:800;color:'+riskColor+';">'+r.risk_score+'</span>';
    h += '<span style="color:'+riskColor+';font-size:13px;">/100</span>';
    h += '<span class="rem-cat" style="background:'+riskColor+';margin-left:12px;">'+escapeHtml(r.risk_label||'')+'</span></div>';
    h += '<div style="flex:1;">';
    (r.risk_factors||[]).forEach(function(f){ h+='<span class="tag-flag" style="margin:2px;font-size:10px;">'+escapeHtml(f)+'</span>'; });
    h += '</div></div></div>';
    if((r.phishing_techniques||[]).length){
      h+='<div class="section-label">Phishing Techniques Detected</div><div style="margin-bottom:14px;">';
      r.phishing_techniques.forEach(function(t){ h+='<span class="tag-flag">'+escapeHtml(t)+'</span> '; });
      h+='</div>';
    }
    var m=r.metadata||{};
    h+='<details class="remediation" open><summary>Email Metadata</summary>';
    [['From (Display)',m.from_display],['From (Email)',m.from_email],['To',m.to],['CC',m.cc],['Reply-To',m.reply_to],['Subject',m.subject],['Date',m.date],['Message-ID',m.message_id],['Mailer',m.mailer]].forEach(function(kv){
      if(kv[1]) h+='<div class="kv"><b>'+kv[0]+':</b> <span style="color:var(--ink);">'+escapeHtml(kv[1])+'</span></div>';
    });
    h+='</details>';
    var auth=r.authentication||{},spf=auth.spf||{},dkim=auth.dkim||{},dmarc=auth.dmarc||{};
    function ab2(res){ var v=(res||'none').toLowerCase(); return v==='pass'?'<span class="tag-ok">PASS</span>':v==='fail'||v==='softfail'?'<span class="tag-flag">'+v.toUpperCase()+'</span>':'<span class="ioc-muted">'+v.toUpperCase()+'</span>'; }
    h+='<details class="remediation" open><summary>Authentication Analysis</summary>';
    h+='<div class="rem-item"><span class="rem-tech">SPF</span> '+ab2(spf.result)+(spf.domain?'<span class="ioc-meta"> '+escapeHtml(spf.domain)+'</span>':'')+'<ul><li>Verifies the sending server is authorised for the domain.</li></ul></div>';
    h+='<div class="rem-item"><span class="rem-tech">DKIM</span> '+ab2(dkim.result)+(dkim.domain?'<span class="ioc-meta"> '+escapeHtml(dkim.domain)+'</span>':'')+'<ul><li>Validates message integrity via cryptographic signature.</li></ul></div>';
    h+='<div class="rem-item"><span class="rem-tech">DMARC</span> '+ab2(dmarc.result)+(dmarc.policy?'<span class="ioc-meta"> Policy: '+escapeHtml(dmarc.policy)+'</span>':'')+'<ul><li>Enforces From-domain alignment. Fail means sender identity unverified.</li></ul></div>';
    h+='</details>';
    var c=r.security_checks||{};
    function chk2(label,val,desc,warn){ var badge=val?(warn?'<span style="color:var(--amber);font-size:10px;border:1px solid var(--amber);padding:1px 6px;">WARN</span>':'<span class="tag-flag">FAIL</span>'):'<span class="tag-ok">PASS</span>'; return '<div class="rem-item"><span class="rem-tech">'+label+'</span> '+badge+'<ul><li>'+escapeHtml(desc)+'</li></ul></div>'; }
    h+='<details class="remediation" open><summary>Security Checks</summary>';
    h+=chk2('External Sender',c.external_sender,'Sender is not from an internal domain.',true);
    h+=chk2('Reply-To Mismatch',c.reply_to_mismatch,'Reply-To domain differs from From domain.',false);
    h+=chk2('Display Name Spoofing',c.display_name_spoofing,'Display name impersonates a known brand.',false);
    h+=chk2('HTML Form',c.has_html_form,'HTML form detected in body - possible credential harvesting.',false);
    h+=chk2('JavaScript',c.has_javascript,'Active JavaScript found in HTML body.',true);
    h+=chk2('Tracking Pixel',c.has_tracking_pixel,'Tiny image used to track if email was opened.',true);
    h+=chk2('Remote Images',c.has_remote_images,'External images can leak recipient IP.',true);
    h+=chk2('Malformed Message-ID',c.invalid_message_id,'Message-ID does not conform to RFC 5322.',true);
    h+='</details>';
    if((r.received_chain||[]).length){
      h+='<details class="remediation"><summary>Delivery Path ('+r.received_chain.length+' hops)</summary>';
      r.received_chain.forEach(function(hop,i){
        h+='<div class="rem-item"><span class="rem-tech">Hop '+(i+1)+'</span>';
        if(hop.from) h+='<div class="kv"><b>From:</b> '+escapeHtml(hop.from)+'</div>';
        if(hop.by)   h+='<div class="kv"><b>By:</b> '+escapeHtml(hop.by)+'</div>';
        if(hop.ip)   h+='<div class="kv"><b>IP:</b> <span class="tag-ok">'+escapeHtml(hop.ip)+'</span> <a href="https://www.abuseipdb.com/check/'+encodeURIComponent(hop.ip)+'" target="_blank" class="ioc-link" style="font-size:10px;">AbuseIPDB</a></div>';
        if(hop.timestamp) h+='<div class="kv"><b>Time:</b> '+escapeHtml(hop.timestamp)+'</div>';
        h+='</div>';
      });
      h+='</details>';
    }
    if((r.urls||[]).length){
      h+='<details class="remediation"><summary>Extracted URLs ('+r.urls.length+')</summary>';
      r.urls.forEach(function(u){
        var sus=/login|verify|account|secure|update|confirm|password|credential|signin|reset/i.test(u);
        h+='<div class="rem-item">'+(sus?'<span class="tag-flag">SUSPICIOUS</span> ':'')+
          '<span style="font-size:10px;word-break:break-all;color:'+(sus?'var(--crimson)':'var(--cyan)')+';">'+escapeHtml(u.length>100?u.slice(0,100)+'...':u)+'</span>'+
          '<div style="margin-top:4px;"><a href="https://www.virustotal.com/gui/search/'+encodeURIComponent(u)+'" target="_blank" class="ioc-link" style="font-size:10px;">VirusTotal</a> '+
          '<a href="https://urlscan.io/search/#'+encodeURIComponent(u)+'" target="_blank" class="ioc-link" style="font-size:10px;">URLScan</a></div></div>';
      });
      h+='</details>';
    }
    if((r.attachments||[]).length){
      h+='<details class="remediation"><summary>Attachments ('+r.attachments.length+')</summary>';
      r.attachments.forEach(function(a){
        h+='<div class="rem-item"><span class="rem-tech">'+escapeHtml(a.filename)+'</span>'+(a.is_executable||a.has_macros?' <span class="tag-flag">HIGH RISK</span>':'')+
          '<div class="kv"><b>SHA256:</b> <span style="font-size:10px;">'+escapeHtml(a.sha256||'')+'</span></div>'+
          (a.has_macros?'<div class="kv" style="color:var(--amber);">May contain macros</div>':'')+
          (a.is_executable?'<div class="kv" style="color:var(--crimson);">Executable file type</div>':'')+
          '<div style="margin-top:6px;"><a href="https://www.virustotal.com/gui/file/'+encodeURIComponent(a.sha256||'')+'" target="_blank" class="ioc-link" style="font-size:10px;">VirusTotal</a> '+
          '<a href="https://bazaar.abuse.ch/browse.php?search=sha256%3A'+encodeURIComponent(a.sha256||'')+'" target="_blank" class="ioc-link" style="font-size:10px;">MalwareBazaar</a></div></div>';
      });
      h+='</details>';
    }
    var iocs=r.iocs||{};
    h+='<details class="remediation"><summary>IOC Summary</summary>';
    if((iocs.ips||[]).length){ h+='<div class="rem-item"><span class="rem-tech">IPs</span><div style="margin-top:4px;">'; iocs.ips.forEach(function(x){ h+='<span class="tag-ok">'+escapeHtml(x)+'</span> '; }); h+='</div></div>'; }
    if((iocs.domains||[]).length){ h+='<div class="rem-item"><span class="rem-tech">Domains</span><div style="margin-top:4px;">'; iocs.domains.forEach(function(x){ h+='<span class="tag-ok">'+escapeHtml(x)+'</span> '; }); h+='</div></div>'; }
    if((iocs.emails||[]).length){ h+='<div class="rem-item"><span class="rem-tech">Emails</span><div style="margin-top:4px;">'; iocs.emails.forEach(function(x){ h+='<span class="tag-ok">'+escapeHtml(x)+'</span> '; }); h+='</div></div>'; }
    if((iocs.hashes||[]).length){ h+='<div class="rem-item"><span class="rem-tech">Hashes</span><div style="margin-top:4px;">'; iocs.hashes.forEach(function(x){ h+='<span class="tag-ok" style="font-size:10px;">'+escapeHtml(x)+'</span> '; }); h+='</div></div>'; }
    h+='<div style="margin-top:8px;"><button type="button" class="pill" id="copyIocsBtn" style="color:var(--acid);border-color:var(--acid);">Copy All IOCs</button></div></details>';
    if((r.mitre_techniques||[]).length){
      h+='<details class="remediation"><summary>MITRE ATT&amp;CK Mapping</summary>';
      r.mitre_techniques.forEach(function(t){ var pts=t.split('.'),base=pts[0],sub=pts[1]; var url=sub?'https://attack.mitre.org/techniques/'+base+'/'+sub+'/':'https://attack.mitre.org/techniques/'+base+'/'; h+='<div class="rem-item"><span class="rem-tech">'+escapeHtml(t)+'</span> <a href="'+url+'" target="_blank" class="ioc-link" style="font-size:10px;">MITRE ATT&amp;CK</a></div>'; });
      h+='</details>';
    }
    if((r.timeline||[]).length){
      h+='<details class="remediation"><summary>Timeline</summary>';
      r.timeline.forEach(function(ev){ h+='<div class="rem-item"><span class="rem-tech">'+escapeHtml(ev.event)+'</span><div class="kv">'+escapeHtml(ev.timestamp||'')+(ev.detail?' \u2014 '+escapeHtml(ev.detail):'')+'</div></div>'; });
      h+='</details>';
    }
    if(r.raw_headers) h+='<details class="remediation"><summary>Raw Headers</summary><div class="excerpt">'+escapeHtml(r.raw_headers)+'</div></details>';
    h+='<div style="margin-top:18px;"><button type="button" class="browse-btn" id="phishingAiBtn">Ask Hisn AI About This Email</button></div>';
    h+='</div>';
    return h;
  }



  // Demo loader
  (function demoLoader(){
    var db = document.getElementById('demoBtn');
    if (!db) return;
    db.addEventListener('click', function(){
      db.textContent = 'Scanning for .evtx files...'; db.disabled = true;
      db.style.opacity = '0.7';
      fetch('/demo', {method: 'POST'})
        .then(function(r){ return r.json(); })
        .then(function(d){
          if (d.status === 'started') {
            var fname = d.file ? ' ('+d.file+')' : '';
          document.getElementById('demoMsg').textContent = 'Fast analysis started — page reloads in ~15s'+fname+' — page will reload when done.';
            var pollDemo = setInterval(function(){
              fetch('/status').then(function(r){ return r.json(); }).then(function(j){
                if (j.done) { clearInterval(pollDemo); location.reload(); }
              });
            }, 1200);
          } else {
            var msg = document.getElementById('demoMsg');
            msg.textContent = d.error || 'No sample file found. Upload a .evtx to begin.';
            msg.style.color = 'var(--amber)';
            db.disabled = false; db.textContent = 'Load Demo Analysis';
            db.style.opacity = '1';
          }
        })
        .catch(function(){ db.disabled = false; db.textContent = 'Load Demo Analysis'; });
    });
  })();



  // Compact ledger numbers — 10685 → 10.7k, keeps the box clean
  (function formatLedgerNumbers(){
    document.querySelectorAll('.ledger-num').forEach(function(el){
      var textNode = Array.from(el.childNodes).find(function(n){ return n.nodeType === 3; });
      if (!textNode) return;
      var raw = textNode.textContent.trim();
      var num = parseInt(raw.replace(/[^0-9]/g,''), 10);
      if (isNaN(num) || num < 10000) return;
      var compact = num >= 1000000
        ? Math.floor(num/1000000) + 'M'
        : Math.floor(num/1000) + 'K';
      textNode.textContent = compact;
    });
  })();


  document.querySelectorAll('.cell.hit').forEach(c => {
    c.addEventListener('click', () => {
      const id = c.firstChild.textContent.trim();
      if (search){ search.value = id.toLowerCase(); applyFilters(); search.scrollIntoView({behavior:'smooth', block:'center'}); toast('filtering by technique '+id); }
    });
    c.style.cursor = 'pointer';
  });
</script>
<footer class="hisn-footer">
  &copy; 2026 HISN v1.0.0<span class="hf-sep">&middot;</span>Built by <a href="https://github.com/KareemCrafts" target="_blank" rel="noopener">Kareem Alshaer</a><span class="hf-sep">&middot;</span>All rights reserved
</footer>
</body>
</html>
"""



@app.route("/")
def dashboard():
    global_context_str = ""
    engine = init_db()
    with Session(engine) as session:
        incidents = session.query(Incident).all()
        alerts = session.query(Alert).all()
        total_alerts = len(alerts)
        total_incidents = len(incidents)
        reduction = round((1 - total_incidents / total_alerts) * 100, 1) if total_alerts else 0

        tech_sev, tech_count = {}, defaultdict(int)
        for a in alerts:
            tid = a.mitre_technique_id
            tech_count[tid] += 1
            cur = tech_sev.get(tid)
            if cur is None or SEVERITY_RANK.get(a.severity, 0) > SEVERITY_RANK.get(cur, 0):
                tech_sev[tid] = a.severity

        matrix = []
        for tactic, techniques in MATRIX:
            cells = [{"id": tid, "hit": tid in tech_sev,
                      "color": SEVERITY_COLOR.get(tech_sev.get(tid, ""), "#333"),
                      "count": tech_count.get(tid, 0)} for tid in techniques]
            matrix.append({"tactic": tactic, "techniques": cells})

        chrono = sorted(incidents, key=lambda i: i.start_time)
        nums = {inc.id: idx + 1 for idx, inc in enumerate(chrono)}
        alerts_by_incident = defaultdict(list)
        for a in alerts:
            if a.incident_id:
                alerts_by_incident[a.incident_id].append(a)

        for inc in incidents:
            inc.case_number = nums[inc.id]
            inc.chain = build_chain(inc.mitre_tactics)
            inc.remediation = get_remediation(inc.mitre_techniques)
            inc.ip_intel = check_ip_reputation(inc.source_ip)
            inc.rule_explanations = get_rule_explanations(inc.rule_names)
            inc.iocs = get_incident_iocs(alerts_by_incident.get(inc.id, []))
            inc.raw_events = get_raw_events(alerts_by_incident.get(inc.id, []))
            inc.context_json = {
                "host": inc.host, "source_ip": inc.source_ip, "max_severity": inc.max_severity,
                "start_time": str(inc.start_time), "end_time": str(inc.end_time),
                "alert_count": inc.alert_count, "mitre_techniques": inc.mitre_techniques,
                "rule_names": inc.rule_names, "ai_summary": inc.ai_summary,
            }

        incidents_sorted = sorted(incidents, key=lambda i: SEVERITY_RANK.get(i.max_severity, 0), reverse=True)
        severities_present = sorted({i.max_severity for i in incidents}, key=lambda s: SEVERITY_RANK.get(s, 0), reverse=True)
        host_stats = get_host_stats(alerts)

        return render_template_string(
            TEMPLATE, incidents=incidents_sorted, total_alerts=total_alerts,
            total_incidents=total_incidents, reduction=reduction,
           techniques_seen=len(tech_sev), matrix=matrix,
            colors=SEVERITY_COLOR, severities=severities_present,
            host_stats=host_stats,
            global_context_str=global_context_str,
        )


if __name__ == "__main__":
    import os as _os
    # Clear previous session on every restart — fresh start each time
    _e = init_db()
    with Session(_e) as _s:
        _s.query(Alert).delete(); _s.query(Incident).delete(); _s.commit()
    _port = int(_os.environ.get("PORT", _os.environ.get("FLASK_PORT", "5000")))
    _host = _os.environ.get("FLASK_HOST", "0.0.0.0")
    _debug = _os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=_debug, host=_host, port=_port)