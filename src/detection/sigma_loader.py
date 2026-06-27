# src/detection/sigma_loader.py
# Loads Sigma rules from YAML files and matches them against normalized events
# Filters rules by logsource to prevent false positives

import yaml, os, re

# Map event properties to Sigma logsource categories
SYSMON_CATEGORY_MAP = {
    "1":  "process_creation",
    "2":  "file_change",
    "3":  "network_connection",
    "5":  "process_termination",
    "6":  "driver_load",
    "7":  "image_load",
    "8":  "create_remote_thread",
    "9":  "raw_access_thread",
    "10": "process_access",
    "11": "file_event",
    "12": "registry_event",
    "13": "registry_event",
    "14": "registry_event",
    "15": "create_stream_hash",
    "17": "pipe_created",
    "18": "pipe_created",
    "22": "dns_query",
    "23": "file_delete",
    "24": "clipboard_change",
    "25": "process_tampering",
    "26": "file_delete",
}

def get_event_logsource(event: dict) -> dict:
    """Determine Sigma logsource properties from an event"""
    channel  = (event.get("channel") or "").lower()
    provider = (event.get("provider") or "").lower()
    eid      = event.get("event_id", "")

    result = {"product": "windows"}

    # Determine service
    if "security" in channel:
        result["service"] = "security"
    elif "system" in channel:
        result["service"] = "system"
    elif "powershell" in channel or "powershell" in provider:
        result["service"] = "powershell"
        result["category"] = "ps_script"
    elif "sysmon" in channel or "sysmon" in provider:
        result["service"] = "sysmon"
        cat = SYSMON_CATEGORY_MAP.get(str(eid))
        if cat:
            result["category"] = cat
    elif "windows defender" in channel or "windows defender" in provider:
        result["service"] = "windefend"
    elif "applocker" in channel:
        result["service"] = "applocker"
    elif "application" in channel:
        result["service"] = "application"
    elif "taskscheduler" in provider:
        result["service"] = "taskscheduler"

    return result


def logsource_matches(rule_logsource: dict, event_logsource: dict) -> bool:
    """Check if a rule's logsource matches the event's logsource"""
    if not rule_logsource:
        return False

    rule_product  = (rule_logsource.get("product") or "").lower()
    rule_service  = (rule_logsource.get("service") or "").lower()
    rule_category = (rule_logsource.get("category") or "").lower()

    event_product  = (event_logsource.get("product") or "").lower()
    event_service  = (event_logsource.get("service") or "").lower()
    event_category = (event_logsource.get("category") or "").lower()

    # Product must match
    if rule_product and rule_product != event_product:
        return False

    # If rule specifies a service, it must match
    if rule_service and event_service and rule_service != event_service:
        return False

    # If rule specifies a category, it must match
    if rule_category and event_category and rule_category != event_category:
        return False

    # If rule has category but event has no category (e.g. Security logs),
    # the rule doesn't apply (prevents process_creation rules on Security events)
    if rule_category and not event_category:
        return False

    return True


class SigmaRule:
    def __init__(self, rule_data: dict):
        self.title       = rule_data.get("title", "Unknown Rule")
        self.rule_id     = rule_data.get("id", "")
        self.description = rule_data.get("description", "")
        self.level       = rule_data.get("level", "medium")
        self.logsource   = rule_data.get("logsource", {})
        self.detection   = rule_data.get("detection", {})
        self.tags        = rule_data.get("tags", []) or []
        self.mitre_ids   = self._extract_mitre_ids()

    def _extract_mitre_ids(self) -> list[str]:
        ids = []
        for tag in self.tags:
            tag = str(tag).lower()
            if tag.startswith("attack.t"):
                tid = tag.replace("attack.", "").upper()
                ids.append(tid)
        return ids

    def matches(self, event: dict) -> bool:
        detection = self.detection
        if not detection:
            return False

        condition = str(detection.get("condition", "selection"))

        selections = {}
        for key, val in detection.items():
            if key != "condition" and isinstance(val, (dict, list)):
                selections[key] = val

        try:
            return self._eval_condition(condition, selections, event)
        except Exception:
            return False

    def _eval_condition(self, condition: str, selections: dict, event: dict) -> bool:
        condition = condition.strip()

        if condition == "1 of them":
            return any(self._match_selection(v, event) for v in selections.values())
        if condition == "all of them":
            return all(self._match_selection(v, event) for v in selections.values())

        match = re.match(r'1 of (\w+)\*', condition)
        if match:
            prefix = match.group(1)
            matching = [v for k, v in selections.items() if k.startswith(prefix)]
            return any(self._match_selection(v, event) for v in matching)

        match = re.match(r'all of (\w+)\*', condition)
        if match:
            prefix = match.group(1)
            matching = [v for k, v in selections.items() if k.startswith(prefix)]
            return all(self._match_selection(v, event) for v in matching) if matching else False

        if " or " in condition:
            parts = condition.split(" or ")
            return any(self._eval_condition(p.strip(), selections, event) for p in parts)

        if " and " in condition:
            parts = self._split_and(condition)
            result = True
            for part in parts:
                part = part.strip()
                if part.startswith("not "):
                    name = part[4:].strip()
                    if name in selections:
                        result = result and not self._match_selection(selections[name], event)
                elif part.startswith("1 of ") and part.endswith("*"):
                    prefix = part[5:-1]
                    matching = [v for k, v in selections.items() if k.startswith(prefix)]
                    result = result and any(self._match_selection(v, event) for v in matching)
                else:
                    if part in selections:
                        result = result and self._match_selection(selections[part], event)
                    else:
                        result = False
            return result

        if condition.startswith("not "):
            name = condition[4:].strip()
            if name in selections:
                return not self._match_selection(selections[name], event)
            return True

        if condition in selections:
            return self._match_selection(selections[condition], event)

        return False

    def _split_and(self, condition: str) -> list[str]:
        parts = []
        current = ""
        tokens = condition.split(" ")
        i = 0
        while i < len(tokens):
            if tokens[i] == "and":
                if current.strip():
                    parts.append(current.strip())
                current = ""
            else:
                current += " " + tokens[i]
            i += 1
        if current.strip():
            parts.append(current.strip())
        return parts

    def _match_selection(self, selection, event: dict) -> bool:
        if not selection:
            return False
        if isinstance(selection, list):
            return any(self._match_single(s, event) for s in selection if isinstance(s, dict))
        if isinstance(selection, dict):
            return self._match_single(selection, event)
        return False

    def _match_single(self, selection: dict, event: dict) -> bool:
        data = event.get("raw_data", {})
        merged = {
            **data,
            "EventID": str(event.get("event_id", "")),
            "Computer": event.get("host", ""),
            "Channel": event.get("channel", ""),
            "Provider_Name": event.get("provider", ""),
        }

        for field_key, expected in selection.items():
            parts = field_key.split("|")
            field_name = parts[0]
            modifiers  = parts[1:] if len(parts) > 1 else []

            actual = merged.get(field_name)
            if actual is None:
                for k, v in merged.items():
                    if k.lower() == field_name.lower():
                        actual = v
                        break

            if actual is None:
                actual = ""
            actual = str(actual)

            if not self._match_value(actual, expected, modifiers):
                return False

        return True

    def _match_value(self, actual: str, expected, modifiers: list) -> bool:
        if expected is None:
            return actual == ""
        if isinstance(expected, list):
            return any(self._match_value(actual, e, modifiers) for e in expected)

        expected_str = str(expected)

        if "contains" in modifiers and "all" in modifiers:
            return expected_str.lower() in actual.lower()
        elif "contains" in modifiers:
            return expected_str.lower() in actual.lower()
        elif "endswith" in modifiers:
            return actual.lower().endswith(expected_str.lower())
        elif "startswith" in modifiers:
            return actual.lower().startswith(expected_str.lower())
        elif "re" in modifiers:
            try:
                return bool(re.search(expected_str, actual, re.IGNORECASE))
            except re.error:
                return False
        else:
            return actual.lower() == expected_str.lower()


class SigmaEngine:
    def __init__(self, rules_dir: str = "rules/sigma"):
        self.rules = []
        self._load_rules(rules_dir)

    def _load_rules(self, rules_dir: str):
        if not os.path.exists(rules_dir):
            print(f"[!] Rules directory not found: {rules_dir}")
            return

        loaded = 0
        failed = 0
        for filename in os.listdir(rules_dir):
            if not filename.endswith(".yml"):
                continue
            filepath = os.path.join(rules_dir, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    rule_data = yaml.safe_load(f)
                if rule_data and isinstance(rule_data, dict) and "detection" in rule_data:
                    self.rules.append(SigmaRule(rule_data))
                    loaded += 1
            except Exception:
                failed += 1
                continue

        print(f"[+] Sigma Engine: loaded {loaded} rules ({failed} skipped)")

    def scan(self, event: dict) -> list[dict]:
        """Scan a single event against rules that match its logsource"""
        event_ls = get_event_logsource(event)
        hits = []
        for rule in self.rules:
            try:
                if not logsource_matches(rule.logsource, event_ls):
                    continue
                if rule.matches(event):
                    hits.append({
                        "rule_title":  rule.title,
                        "rule_id":     rule.rule_id,
                        "level":       rule.level,
                        "mitre_ids":   rule.mitre_ids,
                        "description": rule.description,
                        "tags":        rule.tags,
                    })
            except Exception:
                continue
        return hits


if __name__ == "__main__":
    engine = SigmaEngine()
    print(f"\nTotal rules loaded: {len(engine.rules)}")

    # Count by logsource
    from collections import Counter
    services = Counter()
    categories = Counter()
    for r in engine.rules:
        svc = r.logsource.get("service", "none")
        cat = r.logsource.get("category", "none")
        services[svc] += 1
        categories[cat] += 1

    print("\nRules by service:")
    for s, c in services.most_common(10):
        print(f"  {s}: {c}")
    print("\nRules by category:")
    for s, c in categories.most_common(10):
        print(f"  {s}: {c}")
