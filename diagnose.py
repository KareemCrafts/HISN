import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

for filepath in [
    "logs/samples/brute-force.evtx",
    "logs/samples/mimikatz.evtx"
]:
    print(f"\n=== {filepath} ===")
    try:
        with evtx.Evtx(filepath) as log:
            count = 0
            for record in log.records():
                try:
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)
                    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
                    system = root.find(f"{ns}System")
                    eid = system.find(f"{ns}EventID").text
                    print(f"  Event ID: {eid}")
                    count += 1
                    if count >= 10:
                        break
                except Exception as e:
                    print(f"  Record error: {e}")
                    continue
    except Exception as e:
        print(f"  File error: {e}")