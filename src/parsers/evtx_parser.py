# src/parsers/evtx_parser.py
# Reads Windows .evtx files — handles ALL formats and edge cases

import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
import json, sys

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

def parse_evtx(file_path: str) -> list[dict]:
    events = []

    with evtx.Evtx(file_path) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                root    = ET.fromstring(xml_str)
                system  = root.find(f"{NS}System")

                if system is None:
                    continue

                # ── Extract Event ID (handles simple and complex formats)
                eid_elem = system.find(f"{NS}EventID")
                if eid_elem is None:
                    continue
                event_id = eid_elem.text
                if event_id is None:
                    event_id = eid_elem.attrib.get("Qualifiers", "0")

                # ── Timestamp
                time_elem = system.find(f"{NS}TimeCreated")
                timestamp = time_elem.attrib.get("SystemTime", "") if time_elem is not None else ""

                # ── Computer
                comp_elem = system.find(f"{NS}Computer")
                computer  = comp_elem.text if comp_elem is not None else "UNKNOWN"

                # ── Provider / Channel
                provider_elem = system.find(f"{NS}Provider")
                provider = provider_elem.attrib.get("Name", "") if provider_elem is not None else ""

                channel_elem = system.find(f"{NS}Channel")
                channel = channel_elem.text if channel_elem is not None else ""

                # ── Pull ALL data fields (EventData AND UserData)
                data = {}

                event_data = root.find(f"{NS}EventData")
                if event_data is not None:
                    for item in event_data:
                        name  = item.attrib.get("Name", f"Field_{len(data)}")
                        value = item.text or ""
                        data[name] = value

                # Some events use UserData instead of EventData
                user_data = root.find(f"{NS}UserData")
                if user_data is not None:
                    for parent in user_data:
                        for item in parent:
                            tag = item.tag.split("}")[-1] if "}" in item.tag else item.tag
                            data[tag] = item.text or ""

                events.append({
                    "event_id":  str(event_id),
                    "timestamp": timestamp,
                    "host":      computer,
                    "provider":  provider,
                    "channel":   channel,
                    "user":      data.get("TargetUserName") or data.get("SubjectUserName") or data.get("User", "UNKNOWN"),
                    "raw_data":  data
                })

            except Exception:
                continue

    return events


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python evtx_parser.py <path>")
        sys.exit(1)

    results = parse_evtx(sys.argv[1])
    print(f"Parsed {len(results)} events")

    from collections import Counter
    ids = Counter(e["event_id"] for e in results)
    print("\nEvent ID breakdown:")
    for eid, count in ids.most_common():
        print(f"  {eid}: {count}")

    if results:
        print(f"\nFirst event sample:")
        print(json.dumps(results[0], indent=2, default=str))
