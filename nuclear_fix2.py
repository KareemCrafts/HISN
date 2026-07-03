import re

with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

fixes = []

# ══════════════════════════════════════════════════
# 1. KILL BROKEN JOKE CODE — slice between anchors
# ══════════════════════════════════════════════════
CLEAN_JOKE = (
    "else if (cmd === 'joke') {\n"
    "          var _jk = [\n"
    "            'IR analyst finds a breach. Six months of logs. Root cause: phishing email titled URGENT. User clicked it three times.',\n"
    "            'CISO: did you contain it? Analyst: we opened a ticket. Priority: medium. We had other tickets.',\n"
    "            'Red team: we are in. Blue team logs: no anomalies. Red team: we have been in three months. Blue team: still nothing.',\n"
    "            'Junior: how do you stay calm when everything is on fire? Senior: you stop remembering what calm was.',\n"
    "            'Critical vuln found at 4:59 PM on a Friday. The on-call rotation had just switched.',\n"
    "            'IOC count: 847. Confirmed malicious: 2. Hours triaging: 14. Attacker dwell time: 214 days.',\n"
    "            'The playbook says isolate the host. The host is production. The playbook did not account for this.'\n"
    "          ];\n"
    "          if (!window._jkIdx) window._jkIdx = 0;\n"
    '          out(\'<span style="color:var(--cyan);">\' + _jk[window._jkIdx % _jk.length] + \'</span>\');\n'
    "          window._jkIdx++;\n"
    "        }"
)

joke_start = content.find("else if (cmd === 'joke')")
clear_pos  = content.find("else if (cmd === 'clear')", joke_start + 1) if joke_start != -1 else -1

if joke_start != -1 and clear_pos != -1:
    content = content[:joke_start] + CLEAN_JOKE + "\n        " + content[clear_pos:]
    fixes.append("Joke: clean SOC/IR jokes (slice-replace, no regex)")
else:
    fixes.append(f"MISS: joke_start={joke_start} clear_pos={clear_pos}")

# ══════════════════════════════════════════════════
# 2. RESTORE RAIN FONT LINE IF MISSING
# ══════════════════════════════════════════════════
script_start = content.rfind('<script>')
script_end   = content.rfind('</script>')
script = content[script_start:script_end]

if "ctx.font = '13px JetBrains Mono'" not in script:
    old_fill = "ctx.fillStyle = 'rgba(3,6,8,0.08)'; ctx.fillRect(0,0,w,h);"
    new_fill = ("ctx.fillStyle = 'rgba(3,6,8,0.08)'; ctx.fillRect(0,0,w,h);\n"
                "      ctx.fillStyle = '#7CFFB2'; ctx.font = '13px JetBrains Mono';")
    if old_fill in script:
        script = script.replace(old_fill, new_fill, 1)
        content = content[:script_start] + script + content[script_end:]
        fixes.append("Rain: font line restored")
    else:
        fixes.append("MISS: rain fillRect not found")
else:
    fixes.append("Rain: font line present")

# ══════════════════════════════════════════════════
# 3. FOOTER — injected into TEMPLATE (final time)
# ══════════════════════════════════════════════════
FOOTER_CSS = """
  /* HISN FOOTER */
  .hisn-footer{
    margin-top:64px; padding:20px 0 14px; text-align:center;
    border-top:1px solid rgba(0,255,170,.05);
    font-family:'JetBrains Mono',monospace; font-size:9px;
    letter-spacing:.22em; text-transform:uppercase;
    color:rgba(91,122,117,.35); position:relative; z-index:5;
    user-select:none;
  }
  .hisn-footer a{
    color:rgba(124,255,178,.2); text-decoration:none;
    transition:color .25s; pointer-events:auto;
  }
  .hisn-footer a:hover{ color:rgba(124,255,178,.55); }
"""
FOOTER_HTML = (
    '\n<footer class="hisn-footer">\n'
    '  &copy; 2026 HISN &nbsp;&middot;&nbsp; '
    'Built by <a href="https://github.com/KareemCrafts" target="_blank">Kareem Alshaer</a>'
    ' &nbsp;&middot;&nbsp; All rights reserved\n'
    '</footer>'
)

if 'hisn-footer' not in content:
    content = content.replace('</style>', FOOTER_CSS + '\n</style>', 1)
    if '</body>' in content:
        content = content.replace('</body>', FOOTER_HTML + '\n</body>', 1)
        fixes.append("Footer: CSS + HTML injected into template")
    else:
        fixes.append("MISS: </body> not found")
else:
    fixes.append("Footer: already present")

# ══════════════════════════════════════════════════
# 4. VERIFY JS BRACE BALANCE
# ══════════════════════════════════════════════════
s = content[content.rfind('<script>'):content.rfind('</script>')]
op = s.count('{'); cl = s.count('}')
print(f"\nJS braces: {op} open / {cl} close (diff={op-cl})")
if op == cl:
    print("  Balanced OK — buttons should work")
else:
    print("  WARNING: mismatch — there may still be a syntax error")

# Check for duplicate escapeHtml (still the classic killer)
esc_count = s.count('function escapeHtml')
print(f"escapeHtml definitions: {esc_count} (should be 1)")
if esc_count > 1:
    # Remove all but the first
    first_pos = s.find('function escapeHtml')
    rest = s[first_pos + 30:]
    dup_pat = re.compile(r'\n\s*function escapeHtml\b[^{]*\{[^}]*\}')
    rest_clean, n = dup_pat.subn('', rest)
    if n:
        s = s[:first_pos + 30] + rest_clean
        content = content[:content.rfind('<script>')] + content[content.rfind('<script>'):content.rfind('</script>')].replace(
            content[content.rfind('<script>'):content.rfind('</script>')], s) + content[content.rfind('</script>'):]
        fixes.append(f"Removed {n} duplicate escapeHtml")

# ══════════════════════════════════════════════════
# 5. REMOVE PHISHING RESET INJECTION IF IT BROKE
#    (re-inject cleanly below)
# ══════════════════════════════════════════════════
broken_reset_marker = "_topBtns.innerHTML="
if broken_reset_marker in content:
    fixes.append("Phishing reset: was previously injected")
else:
    # Inject the reset button cleanly — NO string concatenation, NO backslashes in sub
    old_wire = "          var ab=document.getElementById('phishingAiBtn');"
    new_wire = (
        "          // Reset + Export\n"
        "          var _rb2 = document.createElement('div');\n"
        "          _rb2.style.cssText = 'display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;';\n"
        "          var _resetBtn = document.createElement('button');\n"
        "          _resetBtn.type = 'button'; _resetBtn.className = 'pill';\n"
        "          _resetBtn.textContent = 'Analyze Another Email';\n"
        "          _resetBtn.style.cssText = 'color:var(--amber);border-color:var(--amber);';\n"
        "          var _exportBtn = document.createElement('button');\n"
        "          _exportBtn.type = 'button'; _exportBtn.className = 'pill';\n"
        "          _exportBtn.textContent = 'Export JSON Report';\n"
        "          _exportBtn.style.cssText = 'color:var(--acid);border-color:var(--acid);';\n"
        "          _rb2.appendChild(_resetBtn); _rb2.appendChild(_exportBtn);\n"
        "          prs.insertBefore(_rb2, prs.firstChild);\n"
        "          _resetBtn.addEventListener('click', function(){\n"
        "            prs.innerHTML = ''; per.textContent = ''; pfi.value = '';\n"
        "            lastEmailResult = null;\n"
        "            if (window.aiSetContext) window.aiSetContext('none', null, '');\n"
        "          });\n"
        "          _exportBtn.addEventListener('click', function(){\n"
        "            if (!lastEmailResult) return;\n"
        "            var _blob = new Blob([JSON.stringify(lastEmailResult, null, 2)], {type:'application/json'});\n"
        "            var _ea = document.createElement('a');\n"
        "            _ea.href = URL.createObjectURL(_blob);\n"
        "            _ea.download = 'HISN_Email_' + (lastEmailResult.filename || 'report') + '.json';\n"
        "            document.body.appendChild(_ea); _ea.click(); _ea.remove();\n"
        "          });\n"
        "          var ab=document.getElementById('phishingAiBtn');"
    )
    if old_wire in content and 'Analyze Another Email' not in content:
        content = content.replace(old_wire, new_wire, 1)
        fixes.append("Phishing: reset + export buttons injected cleanly")

# ══════════════════════════════════════════════════
# WRITE BACK
# ══════════════════════════════════════════════════
with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

print("\nFixes:")
for f2 in fixes:
    print(f"  {f2}")