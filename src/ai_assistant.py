# src/ai_assistant.py
# Hisn AI — supports Ollama (local) with Groq fallback (cloud)
import requests
import os

OLLAMA_URL  = os.environ.get("OLLAMA_URL",  "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_URL    = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL  = "llama-3.1-8b-instant"

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
    "summarize": (
        "WRITE EXACTLY 4 SHORT SENTENCES. HARD STOP AFTER SENTENCE 4. NO EXCEPTIONS. "
        "NO headers. NO bullets. NO numbered lists. NO introduction. NO conclusion. "
        "Sentence 1 (max 20 words): What happened and where. "
        "Sentence 2 (max 20 words): Detection — which rule or technique fired. "
        "Sentence 3 (max 20 words): Attacker objective. "
        "Sentence 4 (max 20 words): Immediate action required. "
        "If your response contains more than 4 sentences you have failed. Stop at sentence 4."
    ),
    "explain_alert": "Explain in plain language why these rules or indicators fired, what technique they represent, and the underlying security risk.",
    "false_positive": "Based only on the facts given, assess whether this could plausibly be a false positive or benign activity, and explain your exact analytical reasoning.",
    "next_steps": "Recommend specific, actionable next concrete investigation steps an analyst should take to verify or scope this case.",
    "containment": "Recommend specific, prioritized containment and immediate response actions for this incident.",
    "exec_summary": "Write a short, non-technical executive summary suitable for leadership, focused exclusively on business impact, risk, and high-level outcomes.",
    "analyst_report": (
        "Generate a fully comprehensive, structured Analyst Report incorporating all provided context. "
        "Include: Executive Summary, Technical Summary, Attack Chain and Timeline, "
        "Affected Hosts and Users, Indicators of Compromise, MITRE ATT&CK Mapping, "
        "Evidence Supporting Conclusions, Confidence Level and Business Impact, "
        "Recommended Investigation and Containment Steps, Recovery Considerations, "
        "Long-term Hardening Recommendations."
    ),
    "kql": "Write a Microsoft Sentinel KQL query that would detect this same pattern of activity. Output only the query in a code block, with a one-line explanation above it.",
    "splunk": "Write a Splunk SPL query that would detect this same pattern of activity. Output only the query in a code block, with a one-line explanation above it.",
    "sigma": "Write a Sigma detection rule (YAML) for this pattern of activity, using the standard Sigma schema. Output only the YAML in a code block.",
    "junior": "Explain this case using Teaching Mode as if mentoring a junior analyst who is new to the SOC. Define any jargon, explain the behavior clearly, and provide real-world context.",
}


def build_context_text(context_type, context, global_context=""):
    parts = []

    if global_context:
        parts.append(global_context)

    if context_type == "incident" and context:
        parts.append(
            "FOCUSED CASE CONTEXT (analyst is currently viewing this case):\n"
            "Host: " + str(context.get("host", "")) + "\n"
            "Source IP: " + str(context.get("source_ip") or "none/internal") + "\n"
            "Severity: " + str(context.get("max_severity", "")) + "\n"
            "Time window: " + str(context.get("start_time", "")) + " to " + str(context.get("end_time", "")) + "\n"
            "Alert count: " + str(context.get("alert_count", "")) + "\n"
            "MITRE techniques: " + str(context.get("mitre_techniques", "")) + "\n"
            "Rules that fired: " + str(context.get("rule_names", "")) + "\n"
            "Existing analyst note: " + str(context.get("ai_summary") or "none yet") + "\n"
        )

    elif context_type == "email" and context:
        meta  = context.get("metadata") or {}
        auth  = context.get("authentication") or {}
        spf   = (auth.get("spf") or {}).get("result", "unknown")
        dkim  = (auth.get("dkim") or {}).get("result", "unknown")
        dmarc = (auth.get("dmarc") or {}).get("result", "unknown")
        findings = context.get("findings") or []
        finding_titles = "; ".join(f.get("title", "") for f in findings[:5]) if findings else "none"
        parts.append(
            "EMAIL / PHISHING INVESTIGATION CONTEXT:\n"
            "File: " + str(context.get("filename", "")) + "\n"
            "Risk Score: " + str(context.get("risk_score", "")) + "/100 (" + str(context.get("risk_label", "")) + ")\n"
            "Verdict: " + str(context.get("verdict_summary", "")) + "\n"
            "From: " + str(meta.get("from_display", "")) + " <" + str(meta.get("from_email", "")) + ">\n"
            "Subject: " + str(meta.get("subject", "")) + "\n"
            "SPF: " + spf + " | DKIM: " + dkim + " | DMARC: " + dmarc + "\n"
            "Phishing Techniques: " + str(context.get("phishing_techniques", "")) + "\n"
            "MITRE Techniques: " + str(context.get("mitre_techniques", "")) + "\n"
            "Detection Findings: " + finding_titles + "\n"
        )

    elif context_type == "document" and context:
        vt = context.get("vt_intel") or {}
        findings = context.get("findings") or []
        finding_titles = "; ".join(f.get("title", "") for f in findings[:5]) if findings else "none"
        parts.append(
            "DOCUMENT CONTEXT:\n"
            "Filename: " + str(context.get("filename", "")) + "\n"
            "Type: " + str(context.get("file_type", "")) + "\n"
            "Risk Score: " + str(context.get("risk_score", "")) + "/100 (" + str(context.get("risk_label", "")) + ")\n"
            "Verdict: " + str(context.get("verdict_summary", "")) + "\n"
            "Macros found: " + str(context.get("macros_found", "")) + "\n"
            "Detection Findings: " + finding_titles + "\n"
            "VirusTotal: " + str(vt.get("malicious", "unknown")) + " / " + str(vt.get("total_engines", "unknown")) + " engines flagged\n"
        )

    elif not global_context:
        parts.append(
            "No case or document is currently selected. "
            "If the question depends on a specific incident or email, state that no context is selected. "
            "If the question is a general security/SOC knowledge question, answer it normally."
        )

    return "\n\n".join(parts)


def _ask_groq(prompt, max_tokens=None):
    """Call Groq API — free, fast, Llama 3.1."""
    if not GROQ_API_KEY:
        return {"answer": None, "error": "No AI engine available. Add GROQ_API_KEY environment variable for cloud AI, or run Ollama locally."}
    try:
        payload = {
            "model": GROQ_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens or 1024,
            "temperature": 0.3,
        }
        resp = requests.post(
            GROQ_URL,
            headers={
                "Authorization": "Bearer " + GROQ_API_KEY,
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=30,
        )
        if resp.status_code == 200:
            answer = resp.json()["choices"][0]["message"]["content"].strip()
            return {"answer": answer, "error": None}
        return {"answer": None, "error": "Groq API error: " + str(resp.status_code)}
    except Exception as e:
        return {"answer": None, "error": "Groq unavailable: " + str(e)}


def _ask_ollama(prompt, max_tokens=None):
    """Call local Ollama instance."""
    try:
        payload = {"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}
        if max_tokens:
            payload["options"] = {"num_predict": max_tokens, "temperature": 0.3}
        resp = requests.post(OLLAMA_URL, json=payload, timeout=90)
        if resp.status_code == 200:
            return {"answer": resp.json().get("response", "").strip(), "error": None}
        return {"answer": None, "error": "Ollama error: " + str(resp.status_code)}
    except Exception as e:
        return None  # Signal to fall back to Groq


def ask_ai(context_type, context, question, global_context="", max_tokens=None):
    context_text = build_context_text(context_type, context, global_context)
    prompt = (
        SYSTEM_PERSONA + "\n\n"
        + context_text + "\n"
        + "ANALYST QUESTION: " + question + "\n\n"
        + "Answer:"
    )

    # Try Ollama first (local users), fall back to Groq (cloud)
    if OLLAMA_URL:
        result = _ask_ollama(prompt, max_tokens)
        if result is not None:
            return result

    # Groq fallback
    return _ask_groq(prompt, max_tokens)
