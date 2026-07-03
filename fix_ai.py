content = '''\
# src/ai_assistant.py
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2"

SYSTEM_PERSONA = (
    "You are Hisn AI, an expert Tier 3 SOC Analyst, Incident Responder, Threat Hunter, "
    "Digital Forensics Analyst, and Detection Engineer built into a professional Blue Team SOC platform. "
    "Your objective is to help analysts investigate incidents accurately, efficiently, and professionally. "
    "Write like a senior analyst: calm, precise, concise, and highly thorough. Avoid unnecessary filler. "
    "Never exaggerate certainty. Strictly distinguish between Facts, Likely Conclusions, Possible Hypotheses, "
    "and Unknown Information. Never invent technical facts, IOCs, malware family names, VirusTotal results, "
    "or specifics not present in the provided context. If evidence or data is missing, explicitly state so. "
    "When asked to generate a query, rule, or script, output it in a fenced code block using triple backticks "
    "and note it is a draft that should be tested before use."
)

PRESET_PROMPTS = {
    "summarize": "Summarize this investigation in a few clear, technically dense sentences for a senior security analyst.",
    "explain_alert": "Explain in plain language why these rules likely fired, what technique they represent, and the underlying security risk.",
    "false_positive": "Based only on the facts given, assess whether this could plausibly be a false positive or benign activity, and explain your exact analytical reasoning.",
    "next_steps": "Recommend specific, actionable next concrete investigation steps an analyst should take to verify or scope this case.",
    "containment": "Recommend specific, prioritized containment and immediate response actions for this incident.",
    "exec_summary": "Write a short, non-technical executive summary suitable for leadership, focused exclusively on business impact, risk, and high-level outcomes.",
    "analyst_report": (
        "Generate a fully comprehensive, structured Analyst Report incorporating all provided context. "
        "You must include the following sections exactly:\\n"
        "- Executive Summary\\n"
        "- Technical Summary\\n"
        "- Attack Chain & Timeline\\n"
        "- Affected Hosts & Users\\n"
        "- Indicators of Compromise (IOCs)\\n"
        "- MITRE ATT&CK Mapping\\n"
        "- Evidence Supporting Your Conclusions\\n"
        "- Confidence Level & Business Impact\\n"
        "- Recommended Investigation & Containment Steps\\n"
        "- Recovery & False Positive Considerations\\n"
        "- Long-term Hardening Recommendations"
    ),
    "kql": "Write a Microsoft Sentinel KQL query that would detect this same pattern of activity. Output only the query in a code block, with a one-line explanation above it.",
    "splunk": "Write a Splunk SPL query that would detect this same pattern of activity. Output only the query in a code block, with a one-line explanation above it.",
    "sigma": "Write a Sigma detection rule (YAML) for this pattern of activity, using the standard Sigma schema. Output only the YAML in a code block.",
    "junior": "Explain this case using Teaching Mode as if mentoring a junior analyst who is new to the SOC. Define any jargon, explain the behavior clearly, and provide real-world context.",
}


def build_context_text(context_type, context):
    if context_type == "incident" and context:
        return (
            "INCIDENT CONTEXT:\\n"
            f"Host: {context.get(\'host\')}\\n"
            f"Source IP: {context.get(\'source_ip\') or \'none/internal\'}\\n"
            f"Severity: {context.get(\'max_severity\')}\\n"
            f"Time window: {context.get(\'start_time\')} to {context.get(\'end_time\')}\\n"
            f"Alert count: {context.get(\'alert_count\')}\\n"
            f"MITRE techniques: {context.get(\'mitre_techniques\')}\\n"
            f"Rules that fired: {context.get(\'rule_names\')}\\n"
            f"Existing analyst note: {context.get(\'ai_summary\') or \'none yet\'}\\n"
        )
    if context_type == "document" and context:
        vt = context.get("vt_intel") or {}
        return (
            "DOCUMENT CONTEXT:\\n"
            f"Filename: {context.get(\'filename\')}\\n"
            f"Type: {context.get(\'file_type\')}\\n"
            f"Macros found: {context.get(\'macros_found\')}\\n"
            f"Suspicious keywords: {context.get(\'suspicious_keywords\')}\\n"
            f"PDF object tags: {context.get(\'dangerous_tags\')}\\n"
            f"Extracted indicators: {context.get(\'text_indicators\')}\\n"
            f"VirusTotal: {vt.get(\'malicious\', \'unknown\')} / {vt.get(\'total_engines\', \'unknown\')} engines flagged malicious\\n"
        )
    return (
        "No case or document is currently selected for you to reference. "
        "If the analyst\'s question depends on a specific incident, plainly state that no case is selected "
        "and ask them to click \'Ask AI About This Case\' on the case they mean, rather than asking a list "
        "of clarifying questions. If the question is a general security/SOC knowledge question "
        "(e.g. explaining a MITRE technique or Event ID) that does not require specific case data, answer it normally."
    )


def ask_ai(context_type, context, question):
    context_text = build_context_text(context_type, context)
    prompt = (
        f"{SYSTEM_PERSONA}\\n\\n"
        f"{context_text}\\n"
        f"ANALYST QUESTION: {question}\\n\\n"
        "Answer:"
    )
    try:
        resp = requests.post(
            OLLAMA_URL,
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=60,
        )
        if resp.status_code == 200:
            return {"answer": resp.json().get("response", "").strip(), "error": None}
        return {"answer": None, "error": f"Ollama returned status {resp.status_code}"}
    except Exception as e:
        return {
            "answer": None,
            "error": f"AI engine unavailable ({e}). Make sure Ollama is running with llama3.2 pulled.",
        }
'''

with open('src/ai_assistant.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

print("Written successfully — no tabs, pure spaces.")