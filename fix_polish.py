import re

with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    app = f.read()

fixes = []

# ══════════════════════════════════════════════════════
# 1. TERMINAL: blacksite → hisn + proper SOC jokes
# ══════════════════════════════════════════════════════
# Rename all terminal prompts
for old, new in [
    ("root@blacksite", "root@hisn"),
    ("analyst@blacksite", "analyst@hisn"),
    ("// hisn \u00b7 interactive shell", "// hisn \u00b7 terminal"),
    ("// soc-copilot \u00b7 interactive shell", "// hisn \u00b7 terminal"),
]:
    if old in app:
        app = app.replace(old, new)
        fixes.append(f"Terminal: {old} → {new[:20]}")

# Replace the single bad joke with rotating SOC/IR jokes
old_joke = (
    "        else if (cmd === 'joke') out('<span style=\"color:var(--cyan);\">why did the SOC analyst "
    "cross the road? to investigate the chicken on the other side\\'s lateral movement.</span>');"
)
new_joke = (
    "        else if (cmd === 'joke') {\n"
    "          var _jokes = [\n"
    "            'IR analyst finds breach. Begins RCA. Traces it back six months. Finds the root cause is an email titled \\'URGENT: Your VPN password expires today\\'. The user clicked. Three times.',\n"
    "            'CISO: Did you contain the breach? Analyst: We triaged it. CISO: What does that mean? Analyst: We put it in a ticket. CISO: What priority? Analyst: Medium. CISO: Why? Analyst: We needed time to finish our other tickets.',\n"
    "            'A new analyst asks a senior: how do you stay calm when everything is on fire? The senior says: you stop knowing what calm feels like.',\n"
    "            'What do you call a critical vuln found at 4:59 PM on a Friday? A career-defining moment for all the wrong reasons.',\n"
    "            'Red team: we are in. Blue team logs: no anomalies detected. Red team: we have been in for three months. Blue team logs: no anomalies detected.',\n"
    "            'IOC count: 847. Confirmed malicious: 2. Time spent triaging: 14 hours. Attacker dwell time: 214 days.',\n"
    "            'The playbook says isolate the host. The host is production. The playbook did not anticipate this.',\n"
    "          ];\n"
    "          if (!window._jokeIdx) window._jokeIdx = 0;\n"
    "          out('<span style=\"color:var(--cyan);\">' + _jokes[window._jokeIdx % _jokes.length] + '</span>');\n"
    "          window._jokeIdx++;\n"
    "        }"
)
if "lateral movement." in app:
    # Use regex to handle any variation
    joke_pat = re.compile(
        r"else if \(cmd === 'joke'\) out\([^;]+\);",
        re.DOTALL
    )
    if joke_pat.search(app):
        app = joke_pat.sub(new_joke.strip(), app, count=1)
        fixes.append("Terminal: SOC/IR jokes (7 rotating, no more chickens)")
    elif old_joke in app:
        app = app.replace(old_joke, new_joke, 1)
        fixes.append("Terminal: SOC/IR jokes")

# ══════════════════════════════════════════════════════
# 2. PHISHING TAB: reset button + JSON export
# ══════════════════════════════════════════════════════
# Add reset + export buttons to the JS that runs after scan completes
old_ai_btn_wire = (
    "          var ab=document.getElementById('phishingAiBtn');\n"
    "          if (ab) ab.addEventListener('click', function(){"
)
new_ai_btn_wire = (
    "          // Reset + Export buttons\n"
    "          var _topBtns = document.createElement('div');\n"
    "          _topBtns.style.cssText='display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;';\n"
    "          _topBtns.innerHTML=\n"
    "            '<button type=\"button\" class=\"pill\" id=\"phishResetBtn\" style=\"color:var(--amber);border-color:var(--amber);\">'\n"
    "            +'\u21ba Analyze Another Email</button>'\n"
    "            +'<button type=\"button\" class=\"pill\" id=\"phishExportBtn\" style=\"color:var(--acid);border-color:var(--acid);\">'\n"
    "            +'\u2193 Export JSON</button>';\n"
    "          prs.insertBefore(_topBtns, prs.firstChild);\n"
    "          document.getElementById('phishResetBtn').addEventListener('click', function(){\n"
    "            prs.innerHTML='';\n"
    "            per.textContent='';\n"
    "            pfi.value='';\n"
    "            lastEmailResult=null;\n"
    "            if(window.aiSetContext) window.aiSetContext('none',null,'');\n"
    "            prs.style.display='';\n"
    "          });\n"
    "          document.getElementById('phishExportBtn').addEventListener('click', function(){\n"
    "            if(!lastEmailResult) return;\n"
    "            var blob=new Blob([JSON.stringify(lastEmailResult,null,2)],{type:'application/json'});\n"
    "            var a=document.createElement('a');\n"
    "            a.href=URL.createObjectURL(blob);\n"
    "            a.download='HISN_Email_Analysis_'+(lastEmailResult.filename||'report').replace(/[^a-z0-9]/gi,'_')+'.json';\n"
    "            document.body.appendChild(a); a.click(); a.remove();\n"
    "            URL.revokeObjectURL(a.href);\n"
    "            toast('IOC export downloaded.');\n"
    "          });\n"
    "          var ab=document.getElementById('phishingAiBtn');\n"
    "          if (ab) ab.addEventListener('click', function(){"
)
if old_ai_btn_wire in app:
    app = app.replace(old_ai_btn_wire, new_ai_btn_wire, 1)
    fixes.append("Phishing: reset + JSON export buttons added")
else:
    # Try alternate pattern
    old2 = "          var ab=document.getElementById('phishingAiBtn');\n          if (ab) ab.addEventListener('click', function(){\n            if (window.aiSetContext)"
    if old2 in app:
        new2 = ("          var _rb=document.createElement('div');\n"
                "          _rb.style.cssText='display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;';\n"
                "          _rb.innerHTML='<button type=\"button\" class=\"pill\" id=\"phishResetBtn\" style=\"color:var(--amber);border-color:var(--amber)\">\u21ba Analyze Another</button>';\n"
                "          prs.insertBefore(_rb, prs.firstChild);\n"
                "          document.getElementById('phishResetBtn').addEventListener('click',function(){\n"
                "            prs.innerHTML=''; per.textContent=''; pfi.value=''; lastEmailResult=null;\n"
                "            if(window.aiSetContext) window.aiSetContext('none',null,'');\n"
                "          });\n"
                "          var ab=document.getElementById('phishingAiBtn');\n"
                "          if (ab) ab.addEventListener('click', function(){\n"
                "            if (window.aiSetContext)")
        app = app.replace(old2, new2, 1)
        fixes.append("Phishing: reset button (alt pattern)")

# ══════════════════════════════════════════════════════
# 3. AI SUMMARIZE: hard token limit + brutal constraint
# ══════════════════════════════════════════════════════
# Fix in ai_assistant.py
with open('src/ai_assistant.py', 'r', encoding='utf-8') as f:
    ai = f.read()

# Replace the summarize prompt with a stricter version
old_sum = (
    '"summarize": (\n'
    '        "STRICT RULE: You must write EXACTLY 4 sentences. Not 5. Not 6. Exactly 4. "\n'
    '        "No bullet points. No headers. No numbered lists. Plain prose only. "\n'
    '        "Sentence 1: What happened and on which host or email. "\n'
    '        "Sentence 2: Which technique, rule, or detection fired. "\n'
    '        "Sentence 3: What the attacker or sender likely intended. "\n'
    '        "Sentence 4: The key risk and recommended immediate action. "\n'
    '        "Stop writing after sentence 4."\n'
    '    ),'
)
new_sum = (
    '"summarize": (\n'
    '        "WRITE EXACTLY 4 SHORT SENTENCES. HARD STOP AFTER SENTENCE 4. NO EXCEPTIONS. "\n'
    '        "NO headers. NO bullets. NO numbered lists. NO introduction. NO conclusion. "\n'
    '        "Sentence 1 (max 20 words): What happened and where. "\n'
    '        "Sentence 2 (max 20 words): Detection — which rule or technique fired. "\n'
    '        "Sentence 3 (max 20 words): Attacker objective. "\n'
    '        "Sentence 4 (max 20 words): Immediate action required. "\n'
    '        "If your response contains more than 4 sentences you have failed. Stop at sentence 4."\n'
    '    ),'
)
if old_sum in ai:
    ai = ai.replace(old_sum, new_sum, 1)
    fixes.append("AI summarize: 4 sentences hard limit (max 20 words each)")
else:
    # Try to find any summarize key and patch it
    sum_pat = re.compile(
        r'"summarize":\s*\(.*?"Stop writing after sentence 4\."\s*\n\s*\),',
        re.DOTALL
    )
    if sum_pat.search(ai):
        ai = sum_pat.sub(new_sum.strip(), ai, count=1)
        fixes.append("AI summarize: 4 sentences hard limit (regex)")
    else:
        fixes.append("MISS: summarize prompt not found — check ai_assistant.py")

# Add max token limit to Ollama call for summarize via the route
with open('src/ai_assistant.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(ai)

# Patch the ai-chat route to add num_predict:200 for summarize
old_ask = (
    '    result = ask_ai(context_type, context_data, question, global_context)\n'
    '    return jsonify(result)'
)
new_ask = (
    '    # Hard token cap for summarize to enforce brevity\n'
    '    _max_tok = 220 if preset == "summarize" else None\n'
    '    result = ask_ai(context_type, context_data, question, global_context, max_tokens=_max_tok)\n'
    '    return jsonify(result)'
)
if old_ask in app:
    app = app.replace(old_ask, new_ask, 1)
    fixes.append("AI route: 220 token cap on summarize")

# Update ask_ai to accept max_tokens
with open('src/ai_assistant.py', 'r', encoding='utf-8') as f:
    ai2 = f.read()

old_fn = 'def ask_ai(context_type, context, question, global_context=""):'
new_fn = 'def ask_ai(context_type, context, question, global_context="", max_tokens=None):'
if old_fn in ai2:
    ai2 = ai2.replace(old_fn, new_fn, 1)
    fixes.append("ask_ai: max_tokens parameter added")

old_payload = '        resp = requests.post(\n            OLLAMA_URL,\n            json={"model": MODEL, "prompt": prompt, "stream": False},'
new_payload = (
    '        _payload = {"model": MODEL, "prompt": prompt, "stream": False}\n'
    '        if max_tokens:\n'
    '            _payload["options"] = {"num_predict": max_tokens, "temperature": 0.3}\n'
    '        resp = requests.post(\n            OLLAMA_URL,\n            json=_payload,'
)
if old_payload in ai2:
    ai2 = ai2.replace(old_payload, new_payload, 1)
    fixes.append("ask_ai: num_predict injected for token-limited calls")

with open('src/ai_assistant.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(ai2)

# ══════════════════════════════════════════════════════
# WRITE BACK
# ══════════════════════════════════════════════════════
with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(app)

print("Fixes applied:")
for f2 in fixes:
    print(f"  OK: {f2}")