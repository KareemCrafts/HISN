# run_pipeline.py
# Full pipeline: parse logs -> Sigma detection -> MITRE enrichment -> SQLite storage

from src.parsers.evtx_parser import parse_evtx
from src.detection.engine import DetectionEngine
from src.database.models import init_db, Alert
from sqlalchemy.orm import Session
from collections import Counter
import json, sys

def run_pipeline(evtx_path: str):
    # Step 1 — Parse
    print(f"[*] Parsing {evtx_path}...")
    events = parse_evtx(evtx_path)
    print(f"[+] Parsed {len(events)} events")

    if not events:
        print("[!] No events found in file")
        return

    # Step 2 — Detect
    print("[*] Loading Sigma rules + MITRE ATT&CK data...")
    engine = DetectionEngine()
    print(f"[*] Running {len(engine.sigma.rules)} Sigma rules against {len(events)} events...")
    alerts = engine.run(events)
    print(f"[+] {len(alerts)} alerts fired")

    # Step 3 — Store
    print("[*] Saving alerts to database...")
    db_engine = init_db()
    with Session(db_engine) as session:
        for a in alerts:
            record = Alert(
                id                   = a["alert_id"],
                host                 = a["host"],
                user                 = a["user"],
                event_id             = a["event_id"],
                rule_name            = a["rule_name"],
                sigma_rule_id        = a.get("sigma_rule_id", ""),
                mitre_technique_id   = a["mitre_technique_id"],
                mitre_technique_name = a["mitre_technique_name"],
                mitre_tactic         = a["mitre_tactic"],
                severity             = a["severity"],
                confidence           = a["confidence"],
                raw_event            = a["raw_event"]
            )
            session.add(record)
        session.commit()
    print(f"[+] {len(alerts)} alerts saved to soc_copilot.db")

    # Step 4 — Summary
    print("\n" + "=" * 60)
    print("  DETECTION SUMMARY")
    print("=" * 60)

    print(f"\n  Events parsed   : {len(events)}")
    print(f"  Alerts fired    : {len(alerts)}")
    print(f"  Detection rate  : {round(len(alerts)/len(events)*100, 1)}%")

    tactics = Counter(a["mitre_tactic"] for a in alerts)
    severities = Counter(a["severity"] for a in alerts)
    rules = Counter(a["rule_name"] for a in alerts)

    print("\n  By Tactic:")
    for tactic, count in tactics.most_common():
        print(f"    {tactic}: {count}")

    print("\n  By Severity:")
    for sev, count in severities.most_common():
        print(f"    {sev.upper()}: {count}")

    print("\n  Top Rules Fired:")
    for rule_name, count in rules.most_common(15):
        a = next(x for x in alerts if x["rule_name"] == rule_name)
        print(f"    [{a['severity'].upper():>8}] {rule_name} ({count}x)")
        print(f"             MITRE: {a['mitre_technique_id']} - {a['mitre_technique_name']}")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "logs/samples/Security.evtx"
    run_pipeline(path)
