# src/detection/engine.py
# Detection engine: Sigma rules (precision) + Baseline rules (coverage)
# MITRE enrichment from real ATT&CK STIX database

import uuid, json
from datetime import datetime, timezone
from src.detection.sigma_loader import SigmaEngine
from src.detection.mitre_lookup import MitreLookup


# ── Baseline rules catch common attack patterns Sigma might miss ──────────
# These fire on broader indicators — Sigma rules add precision on top

BASELINE_RULES = [
    {
        "event_id": "4625",
        "rule_name": "Failed Logon Attempt",
        "technique": "T1110",
        "severity": "medium",
        "confidence": 0.70,
    },
    {
        "event_id": "4648",
        "rule_name": "Explicit Credential Use Over Network",
        "technique": "T1550",
        "severity": "medium",
        "confidence": 0.70,
        "condition": lambda data: data.get("IpAddress", "") not in ("", "-", "::1", "127.0.0.1"),
    },
    {
        "event_id": "4624",
        "rule_name": "Network/Remote Logon",
        "technique": "T1078",
        "severity": "low",
        "confidence": 0.40,
        "condition": lambda data: (
            data.get("LogonType", "") in ("3", "10")
            and data.get("IpAddress", "") not in ("", "-", "::1", "127.0.0.1")
            and not data.get("TargetUserName", "").endswith("$")
        ),
    },
    {
        "event_id": "1102",
        "rule_name": "Audit Log Cleared",
        "technique": "T1685.005",
        "severity": "critical",
        "confidence": 0.95,
    },
    {
        "event_id": "4673",
        "rule_name": "Sensitive Privilege Use",
        "technique": "T1134",
        "severity": "medium",
        "confidence": 0.60,
        "condition": lambda data: not data.get("SubjectUserName", "").endswith("$"),
    },
    {
        "event_id": "4769",
        "rule_name": "Kerberos Service Ticket Request",
        "technique": "T1558.003",
        "severity": "low",
        "confidence": 0.35,
    },
    {
        "event_id": "4698",
        "rule_name": "Scheduled Task Created",
        "technique": "T1053.005",
        "severity": "high",
        "confidence": 0.85,
    },
    {
        "event_id": "7045",
        "rule_name": "New Service Installed",
        "technique": "T1543.003",
        "severity": "medium",
        "confidence": 0.70,
    },
    {
        "event_id": "4720",
        "rule_name": "New User Account Created",
        "technique": "T1136",
        "severity": "high",
        "confidence": 0.80,
    },
    {
        "event_id": "4732",
        "rule_name": "User Added to Privileged Group",
        "technique": "T1098",
        "severity": "high",
        "confidence": 0.80,
    },
    {
        "event_id": "4798",
        "rule_name": "Account Enumeration Detected",
        "technique": "T1087",
        "severity": "low",
        "confidence": 0.55,
        "condition": lambda data: not data.get("SubjectUserName", "").endswith("$"),
    },
    {
        "event_id": "4799",
        "rule_name": "Group Enumeration Detected",
        "technique": "T1087",
        "severity": "low",
        "confidence": 0.55,
        "condition": lambda data: not data.get("SubjectUserName", "").endswith("$"),
    },

    # ── Sysmon-based rules (fire only on logs from Microsoft-Windows-Sysmon/Operational) ──
    {
        "event_id": "1",
        "rule_name": "Suspicious PowerShell Execution (Encoded Command)",
        "technique": "T1059.001",
        "severity": "high",
        "confidence": 0.75,
        "condition": lambda data: "powershell" in data.get("Image", "").lower()
            and any(flag in data.get("CommandLine", "").lower() for flag in ["-enc", "-encodedcommand", "-e jab", "frombase64string"]),
    },
    {
        "event_id": "1",
        "rule_name": "LOLBin Proxy Execution (mshta/regsvr32/rundll32)",
        "technique": "T1218",
        "severity": "high",
        "confidence": 0.65,
        "condition": lambda data: any(b in data.get("Image", "").lower() for b in ["mshta.exe", "regsvr32.exe", "rundll32.exe"])
            and any(s in data.get("CommandLine", "").lower() for s in ["http://", "https://", "javascript:", "scrobj.dll"]),
    },
    {
        "event_id": "1",
        "rule_name": "Shadow Copy / Recovery Deletion",
        "technique": "T1490",
        "severity": "critical",
        "confidence": 0.90,
        "condition": lambda data: any(s in data.get("CommandLine", "").lower() for s in [
            "vssadmin delete shadows", "wbadmin delete catalog", "bcdedit /set {default} recoveryenabled no"
        ]),
    },
    {
        "event_id": "1",
        "rule_name": "Suspicious WMI Process Execution",
        "technique": "T1047",
        "severity": "high",
        "confidence": 0.65,
        "condition": lambda data: "wmic" in data.get("Image", "").lower()
            and "process call create" in data.get("CommandLine", "").lower(),
    },
    {
        "event_id": "8",
        "rule_name": "Process Injection (CreateRemoteThread)",
        "technique": "T1055",
        "severity": "high",
        "confidence": 0.80,
    },
    {
        "event_id": "10",
        "rule_name": "LSASS Memory Access (Possible Credential Dumping)",
        "technique": "T1003.001",
        "severity": "critical",
        "confidence": 0.85,
        "condition": lambda data: "lsass.exe" in data.get("TargetImage", "").lower(),
    },
    {
        "event_id": "13",
        "rule_name": "Registry Run Key Persistence",
        "technique": "T1547.001",
        "severity": "high",
        "confidence": 0.70,
        "condition": lambda data: any(p in data.get("TargetObject", "") for p in [
            "\\Run\\", "\\RunOnce\\", "\\Winlogon\\Shell", "\\Winlogon\\Userinit"
        ]),
    },
    {
        "event_id": "13",
        "rule_name": "Service Registry Modification (Persistence)",
        "technique": "T1543.003",
        "severity": "high",
        "confidence": 0.70,
        "condition": lambda data: "\\Services\\" in data.get("TargetObject", "") and "ImagePath" in data.get("TargetObject", ""),
    },
    {
        "event_id": "11",
        "rule_name": "Suspicious File Drop (Temp/Downloads)",
        "technique": "T1105",
        "severity": "low",
        "confidence": 0.45,
        "condition": lambda data: data.get("TargetFilename", "").lower().endswith((".exe", ".dll", ".ps1", ".vbs", ".bat"))
            and any(p in data.get("TargetFilename", "").lower() for p in ["\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\"]),
    },
]


class DetectionEngine:
    def __init__(self, rules_dir="rules/sigma", stix_path="data/enterprise-attack.json"):
        self.sigma = SigmaEngine(rules_dir)
        self.mitre = MitreLookup(stix_path)
        self.baseline_index = {}
        for rule in BASELINE_RULES:
            self.baseline_index.setdefault(rule["event_id"], []).append(rule)

    def run(self, events: list[dict]) -> list[dict]:
        alerts = []
        for event in events:
            seen_rules = set()

            # 1. Sigma rules first (higher precision)
            sigma_hits = self.sigma.scan(event)
            for hit in sigma_hits:
                seen_rules.add(hit["rule_title"])
                mitre_ids = hit.get("mitre_ids", [])
                primary_id = mitre_ids[0] if mitre_ids else "UNKNOWN"
                mitre_info = self.mitre.get(primary_id)

                alerts.append({
                    "alert_id":             str(uuid.uuid4()),
                    "timestamp":            str(event.get("timestamp", datetime.now(timezone.utc))),
                    "host":                 event.get("host", "UNKNOWN"),
                    "user":                 event.get("user", "UNKNOWN"),
                    "event_id":             event.get("event_id", ""),
                    "rule_name":            hit["rule_title"],
                    "sigma_rule_id":        hit["rule_id"],
                    "source":               "sigma",
                    "mitre_technique_id":   primary_id,
                    "mitre_technique_name": mitre_info["name"],
                    "mitre_tactic":         ", ".join(mitre_info["tactics"]),
                    "severity":             hit["level"],
                    "confidence":           self._level_to_confidence(hit["level"]),
                    "all_mitre_ids":        mitre_ids,
                    "raw_event":            json.dumps(event.get("raw_data", {})),
                })

            # 2. Baseline rules (broader coverage, skip if Sigma already caught it)
            eid = event.get("event_id", "")
            baseline_matches = self.baseline_index.get(eid, [])
            for rule in baseline_matches:
                if rule["rule_name"] in seen_rules:
                    continue
                # Check optional condition
                cond = rule.get("condition")
                if cond and not cond(event.get("raw_data", {})):
                    continue

                mitre_info = self.mitre.get(rule["technique"])
                alerts.append({
                    "alert_id":             str(uuid.uuid4()),
                    "timestamp":            str(event.get("timestamp", datetime.now(timezone.utc))),
                    "host":                 event.get("host", "UNKNOWN"),
                    "user":                 event.get("user", "UNKNOWN"),
                    "event_id":             eid,
                    "rule_name":            rule["rule_name"],
                    "sigma_rule_id":        "",
                    "source":               "baseline",
                    "mitre_technique_id":   rule["technique"],
                    "mitre_technique_name": mitre_info["name"],
                    "mitre_tactic":         ", ".join(mitre_info["tactics"]),
                    "severity":             rule["severity"],
                    "confidence":           rule["confidence"],
                    "all_mitre_ids":        [rule["technique"]],
                    "raw_event":            json.dumps(event.get("raw_data", {})),
                })

        return alerts

    def _level_to_confidence(self, level: str) -> float:
        return {
            "critical": 0.95,
            "high":     0.85,
            "medium":   0.65,
            "low":      0.40,
            "informational": 0.20,
        }.get(level, 0.50)


def run_engine(events: list[dict]) -> list[dict]:
    engine = DetectionEngine()
    return engine.run(events)


if __name__ == "__main__":
    from src.parsers.evtx_parser import parse_evtx
    from collections import Counter
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "logs/samples/Security.evtx"

    events = parse_evtx(path)
    engine = DetectionEngine()
    alerts = engine.run(events)

    sigma_count = sum(1 for a in alerts if a.get("source") == "sigma")
    baseline_count = sum(1 for a in alerts if a.get("source") == "baseline")

    print(f"\nEvents parsed    : {len(events)}")
    print(f"Sigma rules      : {len(engine.sigma.rules)}")
    print(f"MITRE techniques : {len(engine.mitre.techniques)}")
    print(f"Alerts fired     : {len(alerts)}")
    print(f"  from Sigma     : {sigma_count}")
    print(f"  from Baseline  : {baseline_count}")
    if events:
        print(f"Detection rate   : {round(len(alerts)/len(events)*100, 1)}%")

    tactics = Counter(a["mitre_tactic"] for a in alerts)
    severities = Counter(a["severity"] for a in alerts)
    rules = Counter(a["rule_name"] for a in alerts)

    print("\nBy Tactic:")
    for t, c in tactics.most_common():
        print(f"  {t}: {c}")

    print("\nBy Severity:")
    for s, c in severities.most_common():
        print(f"  {s.upper()}: {c}")

    print("\nRules that fired:")
    for r, c in rules.most_common(20):
        a = next(x for x in alerts if x["rule_name"] == r)
        src = a.get("source", "?")
        print(f"  [{a['severity'].upper():>8}] ({src:>8}) {r}: {c}x")
        print(f"           MITRE: {a['mitre_technique_id']} - {a['mitre_technique_name']}")