# src/detection/mitre_lookup.py
# Loads the REAL MITRE ATT&CK STIX database and provides lookups

import json, os

class MitreLookup:
    def __init__(self, stix_path: str = "data/enterprise-attack.json"):
        self.techniques = {}
        self._load(stix_path)

    def _load(self, path: str):
        if not os.path.exists(path):
            print(f"[!] STIX file not found at {path} — run setup_data.py first")
            return

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
                continue

            refs = obj.get("external_references", [])
            tech_id = None
            for ref in refs:
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id")
                    break

            if not tech_id:
                continue

            tactics = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.append(phase["phase_name"])

            self.techniques[tech_id] = {
                "id":          tech_id,
                "name":        obj.get("name", "Unknown"),
                "description": obj.get("description", "")[:300],
                "tactics":     tactics,
                "platforms":   obj.get("x_mitre_platforms", []),
            }

        print(f"[+] MITRE Lookup loaded: {len(self.techniques)} techniques")

    def get(self, technique_id: str) -> dict:
        return self.techniques.get(technique_id, {
            "id": technique_id,
            "name": "Unknown Technique",
            "description": "",
            "tactics": ["unknown"],
            "platforms": [],
        })

    def search(self, keyword: str) -> list[dict]:
        keyword = keyword.lower()
        return [
            t for t in self.techniques.values()
            if keyword in t["name"].lower() or keyword in t["description"].lower()
        ]


if __name__ == "__main__":
    m = MitreLookup()
    for tid in ["T1110", "T1558.003", "T1070.001", "T1003.001"]:
        t = m.get(tid)
        print(f"{tid}: {t['name']} -> {', '.join(t['tactics'])}")
