import re

# ── 1. SUMMARIZE: brutal length constraint ──────────────────────────
with open('src/ai_assistant.py', 'r', encoding='utf-8') as f:
    ai = f.read()

old_s = '"summarize": "Summarize this investigation in a few clear, technically dense sentences for a senior security analyst."'
new_s = (
    '"summarize": ('
    '"STRICT RULE: You must write EXACTLY 4 sentences. Not 5. Not 6. Exactly 4. "'
    '"No bullet points. No headers. No numbered lists. Plain prose only. "'
    '"Sentence 1: What happened and on which host. "'
    '"Sentence 2: Which MITRE technique and which rules fired. "'
    '"Sentence 3: What the attacker likely intended. "'
    '"Sentence 4: The key risk and recommended immediate action. "'
    '"Stop writing after sentence 4. If you write more you are failing your task."'
    ')'
)

if old_s in ai:
    ai = ai.replace(old_s, new_s, 1)
    print("Summarize prompt updated.")
else:
    print("WARNING: summarize string not found — check ai_assistant.py")

# ── 2. EMAIL CONTEXT TYPE in ai_assistant.py ───────────────────────
old_doc_block = (
    '    if context_type == "document" and context:\n'
    '        vt = context.get("vt_intel") or {}\n'
    '        return (\n'
    '            "DOCUMENT CONTEXT:\\n"'
)
new_doc_block = (
    '    if context_type == "email" and context:\n'
    '        return (\n'
    '            "EMAIL / PHISHING INVESTIGATION CONTEXT:\\n"\n'
    '            f"Filename: {context.get(\'filename\')}\\n"\n'
    '            f"Risk Score: {context.get(\'risk_score\')}/100 ({context.get(\'risk_label\')})\\n"\n'
    '            f"Risk Factors: {context.get(\'risk_factors\')}\\n"\n'
    '            f"Phishing Techniques: {context.get(\'phishing_techniques\')}\\n"\n'
    '            f"MITRE Techniques: {context.get(\'mitre_techniques\')}\\n"\n'
    '            f"From: {context.get(\'metadata\', {}).get(\'from_email\')}\\n"\n'
    '            f"Subject: {context.get(\'metadata\', {}).get(\'subject\')}\\n"\n'
    '            f"SPF: {context.get(\'authentication\', {}).get(\'spf\', {}).get(\'result\')}\\n"\n'
    '            f"DKIM: {context.get(\'authentication\', {}).get(\'dkim\', {}).get(\'result\')}\\n"\n'
    '            f"DMARC: {context.get(\'authentication\', {}).get(\'dmarc\', {}).get(\'result\')}\\n"\n'
    '            f"Security Checks: {context.get(\'security_checks\')}\\n"\n'
    '            f"URLs found: {len(context.get(\'urls\') or [])}\\n"\n'
    '            f"Attachments: {[a.get(\'filename\') for a in (context.get(\'attachments\') or [])]}\\n"\n'
    '        )\n'
    '    if context_type == "document" and context:\n'
    '        vt = context.get("vt_intel") or {}\n'
    '        return (\n'
    '            "DOCUMENT CONTEXT:\\n"'
)

if old_doc_block in ai:
    ai = ai.replace(old_doc_block, new_doc_block, 1)
    print("Email context type added to ai_assistant.")
else:
    print("WARNING: document context block not found — may already be patched.")

with open('src/ai_assistant.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(ai)

# ── 3. ARROW: persist until X clicked ──────────────────────────────
with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    app = f.read()

# Add relative positioning to callout so X button can be positioned inside it
old_callout_css = '.ai-callout{ position:fixed; right:90px; bottom:28px; z-index:92; display:flex; align-items:center; gap:10px; animation: calloutPulse 2s ease-in-out infinite; pointer-events:none; }'
new_callout_css = '.ai-callout{ position:fixed; right:90px; bottom:28px; z-index:92; display:flex; align-items:center; gap:10px; animation: calloutPulse 2s ease-in-out infinite; pointer-events:auto; }'
if old_callout_css in app:
    app = app.replace(old_callout_css, new_callout_css, 1)
    print("Callout CSS pointer-events fixed.")

# Add X button inside callout HTML
old_callout_html = ('<div id="aiCallout" class="ai-callout">\n'
    '  <div class="ai-callout-inner">HISN AI ASSISTANT<span>Click for AI investigation support</span></div>\n'
    '  <div class="ai-callout-arrow">&#9658;</div>\n'
    '</div>')
new_callout_html = ('<div id="aiCallout" class="ai-callout">\n'
    '  <div class="ai-callout-inner" style="cursor:pointer;" id="aiCalloutOpenBtn">HISN AI ASSISTANT<span>Click for AI investigation support</span></div>\n'
    '  <div class="ai-callout-arrow">&#9658;</div>\n'
    '  <button id="aiCalloutClose" type="button" style="position:absolute;top:-8px;right:-8px;background:var(--crimson);border:none;color:#fff;width:18px;height:18px;border-radius:50%;font-size:11px;cursor:pointer;line-height:1;padding:0;font-family:inherit;">&times;</button>\n'
    '</div>')
if old_callout_html in app:
    app = app.replace(old_callout_html, new_callout_html, 1)
    print("Callout X button added.")
else:
    print("WARNING: callout HTML not found exactly — check whitespace.")

# Remove hideCallout from toggle click so arrow stays unless X is clicked
old_toggle = "    toggleBtn.addEventListener('click', () => { hideCallout(); expand(); });"
new_toggle = "    toggleBtn.addEventListener('click', expand);"
if old_toggle in app:
    app = app.replace(old_toggle, new_toggle, 1)
    print("Toggle no longer auto-hides callout.")

# Wire up X button and open-by-click on the callout text
old_callout_js = "    if (callout && sessionStorage.getItem('aiCalloutSeen')) callout.classList.add('hidden');\n    toggleBtn.addEventListener('click', expand);"
new_callout_js = (
    "    if (callout && sessionStorage.getItem('aiCalloutSeen')) callout.classList.add('hidden');\n"
    "    const calloutClose = document.getElementById('aiCalloutClose');\n"
    "    if (calloutClose) calloutClose.addEventListener('click', e => { e.stopPropagation(); hideCallout(); });\n"
    "    const calloutOpen = document.getElementById('aiCalloutOpenBtn');\n"
    "    if (calloutOpen) calloutOpen.addEventListener('click', () => { expand(); });\n"
    "    toggleBtn.addEventListener('click', expand);"
)
if old_callout_js in app:
    app = app.replace(old_callout_js, new_callout_js, 1)
    print("Callout X + open-on-click JS wired.")
else:
    print("WARNING: callout JS anchor not found.")

with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(app)

print("Quick fixes done.")