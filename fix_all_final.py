import re

with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

fixes = []

# ── 1. NULL-SAFE TAB SWITCHING (prevents the crash regardless) ──────
old_tab = (
    "  tabBtns.forEach(btn => btn.addEventListener('click', () => {\n"
    "    tabBtns.forEach(b => b.classList.remove('active'));\n"
    "    btn.classList.add('active');\n"
    "    tabPanels.forEach(p => p.classList.remove('active'));\n"
    "    document.getElementById(btn.dataset.tab).classList.add('active');\n"
    "  }));"
)
new_tab = (
    "  tabBtns.forEach(btn => btn.addEventListener('click', () => {\n"
    "    tabBtns.forEach(b => b.classList.remove('active'));\n"
    "    btn.classList.add('active');\n"
    "    tabPanels.forEach(p => p.classList.remove('active'));\n"
    "    var _tp = document.getElementById(btn.dataset.tab);\n"
    "    if (_tp) _tp.classList.add('active');\n"
    "  }));"
)
if old_tab in content:
    content = content.replace(old_tab, new_tab, 1); fixes.append("Tab switching null-safe")
else:
    print("MISS: tab switching")

# ── 2. INJECT PHISHING PANEL HTML IF MISSING ───────────────────────
if 'id="tab-phishing"' not in content:
    PHISHING_PANEL = '''
  <div id="tab-phishing" class="tab-panel">
    <div class="subline" style="margin:0 0 18px;"><span class="ai-dot" style="background:var(--amber);box-shadow:0 0 10px var(--amber);"></span>EMAIL &amp; PHISHING INVESTIGATION &mdash; .EML &middot; .MSG &middot; SCREENSHOTS</div>
    <div class="dropzone simple" id="phishingDropzone" style="text-align:center;">
      <svg class="upload-icon" width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
      <p style="color:var(--meta);margin-top:8px;">Drop an .eml, .msg, or screenshot to begin investigation</p>
      <button class="browse-btn" type="button" id="phishingBrowseBtn">Choose Email or Screenshot</button>
      <input type="file" id="phishingFileInput" accept=".eml,.msg,.png,.jpg,.jpeg,.webp,.bmp,.gif,.tiff" style="display:none;">
    </div>
    <div class="error-text" id="phishingError"></div>
    <div id="phishingResults"></div>
  </div>

'''
    anchor = '\n\n</main>'
    if anchor in content:
        content = content.replace(anchor, PHISHING_PANEL + '\n\n</main>', 1)
        fixes.append("Phishing panel HTML injected")
    else:
        print("MISS: </main> anchor")
else:
    fixes.append("Phishing panel HTML already present")

# ── 3. REMOVE DUPLICATE function escapeHtml ─────────────────────────
script_start = content.rfind('<script>') + len('<script>')
script_end   = content.rfind('</script>')
pre    = content[:script_start]
script = content[script_start:script_end]
post   = content[script_end:]

positions = [m.start() for m in re.finditer(r'\n  function escapeHtml\b', script)]
print(f"escapeHtml definitions found: {len(positions)}")
if len(positions) > 1:
    for pos in reversed(positions[1:]):
        # Find end of function body
        i = script.find('{', pos)
        depth = 0; started = False
        while i < len(script):
            if script[i] == '{': depth += 1; started = True
            elif script[i] == '}':
                depth -= 1
                if started and depth == 0:
                    script = script[:pos] + script[i+1:]
                    fixes.append("Removed duplicate escapeHtml")
                    break
            i += 1

# ── 4. RESTORE RAIN FONT LINE ───────────────────────────────────────
if "ctx.font = '13px JetBrains Mono'" not in script:
    old_rain = "ctx.fillStyle = '#7CFFB2'; ctx.font = "
    # It was removed, restore it
    old_fillonly = "ctx.fillStyle = '#7CFFB2';\n      for"
    new_fillwith = "ctx.fillStyle = '#7CFFB2'; ctx.font = '13px JetBrains Mono';\n      for"
    if old_fillonly in script:
        script = script.replace(old_fillonly, new_fillwith, 1)
        fixes.append("Restored rain font line")
    else:
        # Try another pattern
        rain_pat = re.compile(r"(ctx\.fillStyle = '#7CFFB2';)\s*\n(\s*for \(let i)", re.M)
        script, n = rain_pat.subn(r"ctx.fillStyle = '#7CFFB2'; ctx.font = '13px JetBrains Mono';\n\2for (let i", script, 1)
        if n: fixes.append("Restored rain font (regex)")
        else: print("MISS: could not restore rain font")
else:
    fixes.append("Rain font already present")

content = pre + script + post

# ── 5. RENAME SOC // COPILOT → HISN ────────────────────────────────
renames = [
    ('SOC COPILOT // BLACK SITE', 'HISN // UNIFIED THREAT INVESTIGATION'),
    ('SOC // COPILOT // BLACK SITE', 'HISN // UNIFIED THREAT INVESTIGATION'),
    ('"SOC COPILOT // BLACK SITE"', '"HISN // UNIFIED THREAT INVESTIGATION"'),
]
for old, new in renames:
    if old in content:
        content = content.replace(old, new)
        fixes.append(f"Renamed: {old[:40]}")

# Title tag
content = re.sub(r'<title>[^<]*</title>', '<title>HISN // UNIFIED THREAT INVESTIGATION</title>', content, 1)
fixes.append("Title tag set")

# h1 glitch text — handle all variations
for old in [
    'data-text="SOC // COPILOT">SOC // COPILOT</h1>',
    'data-text="SOC // COPILOT">SOC // COPILOT',
]:
    if old in content:
        content = content.replace(old, 'data-text="HISN">HISN</h1>', 1)
        fixes.append("h1 renamed")
        break

# Subtitle line
for old in [
    'DETECT &rarr; CORRELATE &rarr; TRIAGE &rarr; CONTAIN <span style="opacity:.5">// BLACK SITE TERMINAL</span>',
    'DETECT → CORRELATE → TRIAGE → CONTAIN // BLACK SITE TERMINAL',
]:
    if old in content:
        content = content.replace(old,
            'UNIFIED THREAT INVESTIGATION &amp; ANALYTICS TOOL '
            '<span style="opacity:.5">// YOUR ENTIRE INVESTIGATION, ALL IN ONE PLACE.</span>', 1)
        fixes.append("Subtitle renamed")
        break

# Folder tab
for old in ['<span class="folder-tab">SOC-COPILOT</span>', 'SOC-COPILOT</span>']:
    if old in content:
        content = content.replace(old.replace('SOC-COPILOT', 'SOC-COPILOT'), old.replace('SOC-COPILOT', 'HISN'), 1)
        fixes.append("Folder tab renamed")
        break
# Direct replacement
content = content.replace('>SOC-COPILOT</span>', '>HISN</span>', 1)

# AI widget title
content = re.sub(
    r'<span class="ai-widget-title">.*?<span id="aiContextLabel"',
    '<span class="ai-widget-title">HISN AI<span id="aiContextLabel"',
    content, 1
)
fixes.append("AI widget title renamed")

# Terminal prompt
content = content.replace(
    "// soc-copilot \u00b7 interactive shell",
    "// hisn \u00b7 interactive shell"
)

# ── 6. IP LINKS IN IOC BOX ──────────────────────────────────────────
OLD_IP = ('{% if inc.iocs.ips %}<div class="kv" style="margin-top:0;"><b>IPs:</b></div>'
          '{% for ip in inc.iocs.ips %}<span class="tag-ok">{{ ip }}</span>{% endfor %}{% endif %}')
NEW_IP = ('{% if inc.iocs.ips %}<div class="kv" style="margin-top:0;"><b>IPs:</b></div>'
          '{% for ip in inc.iocs.ips %}'
          '<div style="margin:4px 0;">'
          '<span class="tag-ok">{{ ip }}</span> '
          '<a href="https://www.abuseipdb.com/check/{{ ip }}" target="_blank" class="ioc-link" style="font-size:10px;">AbuseIPDB &rarr;</a> '
          '<a href="https://viz.greynoise.io/ip/{{ ip }}" target="_blank" class="ioc-link" style="font-size:10px;margin-left:6px;">GreyNoise &rarr;</a> '
          '<a href="https://www.shodan.io/host/{{ ip }}" target="_blank" class="ioc-link" style="font-size:10px;margin-left:6px;">Shodan &rarr;</a>'
          '</div>{% endfor %}{% endif %}')
if OLD_IP in content:
    content = content.replace(OLD_IP, NEW_IP, 1); fixes.append("IP links added")
elif '{% for ip in inc.iocs.ips %}<span class="tag-ok">{{ ip }}</span>{% endfor %}' in content:
    content = content.replace(
        '{% for ip in inc.iocs.ips %}<span class="tag-ok">{{ ip }}</span>{% endfor %}',
        '{% for ip in inc.iocs.ips %}'
        '<div style="margin:4px 0;"><span class="tag-ok">{{ ip }}</span> '
        '<a href="https://www.abuseipdb.com/check/{{ ip }}" target="_blank" class="ioc-link" style="font-size:10px;">AbuseIPDB &rarr;</a> '
        '<a href="https://viz.greynoise.io/ip/{{ ip }}" target="_blank" class="ioc-link" style="font-size:10px;margin-left:6px;">GreyNoise &rarr;</a> '
        '<a href="https://www.shodan.io/host/{{ ip }}" target="_blank" class="ioc-link" style="font-size:10px;margin-left:6px;">Shodan &rarr;</a></div>'
        '{% endfor %}', 1)
    fixes.append("IP links added (alt)")
else:
    print("MISS: IP block not found")

# ── VERIFY ──────────────────────────────────────────────────────────
script2 = content[content.rfind('<script>')+8:content.rfind('</script>')]
print(f"\nfinal escapeHtml count: {script2.count('function escapeHtml')}")
print(f"final renderPhishingResult count: {script2.count('function renderPhishingResult')}")
print(f"phishing panel in HTML: {'id=\"tab-phishing\"' in content}")
print(f"tab-safe switch: {'var _tp = document.getElementById' in content}")
print(f"HISN in title: {'HISN' in content[:500] or 'HISN' in content[content.find('<title>'):content.find('</title>')+20]}")

with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

print("\nFixes applied:")
for f2 in fixes:
    print(f"  OK: {f2}")
print("\nDone.")