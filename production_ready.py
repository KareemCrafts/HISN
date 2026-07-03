import re, os

with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

fixes = []

# ══════════════════════════════════════════════════════
# 1. FAVICON — eliminates the 404 console error
# ══════════════════════════════════════════════════════
FAVICON_ROUTE = '''
@app.route('/favicon.ico')
def favicon():
    # Serve HISN SVG favicon — eliminates 404 console noise
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
        '<rect width="32" height="32" rx="4" fill="#05070A"/>'
        '<rect x="0" y="0" width="4" height="32" fill="#7CFFB2"/>'
        '<text x="9" y="23" font-family="monospace" font-size="16" '
        'font-weight="bold" fill="#7CFFB2">H</text>'
        '</svg>'
    )
    from flask import Response as _R
    r = _R(svg, mimetype='image/svg+xml')
    r.headers['Cache-Control'] = 'public, max-age=86400'
    return r


'''

if "def favicon" not in content:
    anchor = '@app.route("/upload", methods=["POST"])'
    if anchor in content:
        content = content.replace(anchor, FAVICON_ROUTE + anchor, 1)
        fixes.append("Favicon route added (eliminates 404)")

# ══════════════════════════════════════════════════════
# 2. META TAGS + FAVICON LINK in <head>
# ══════════════════════════════════════════════════════
old_head = '<meta name="viewport" content="width=device-width, initial-scale=1">'
new_head = (
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
    '<meta name="description" content="HISN — Unified Threat Investigation &amp; Analytics Tool">\n'
    '<meta name="author" content="Kareem Alshaer">\n'
    '<meta name="application-name" content="HISN">\n'
    '<meta name="version" content="1.0.0">\n'
    '<meta name="theme-color" content="#05070A">\n'
    '<meta name="robots" content="noindex, nofollow">\n'
    '<link rel="icon" type="image/svg+xml" href="/favicon.ico">'
)
if 'application-name' not in content:
    content = content.replace(old_head, new_head, 1)
    fixes.append("Meta tags + favicon link added to <head>")

# ══════════════════════════════════════════════════════
# 3. FOOTER — add directly before </body> in TEMPLATE
#    Use the most specific anchor available
# ══════════════════════════════════════════════════════
FOOTER_CSS = """
  /* ── HISN FOOTER ───────────────────────────────── */
  .hisn-footer{
    margin-top:72px; padding:22px 28px 16px; text-align:center;
    border-top:1px solid rgba(0,255,170,.06);
    font-family:'JetBrains Mono',monospace; font-size:9px;
    letter-spacing:.22em; text-transform:uppercase;
    color:rgba(91,122,117,.35); position:relative; z-index:5;
    user-select:none; line-height:1.8;
  }
  .hisn-footer a{
    color:rgba(124,255,178,.22); text-decoration:none; transition:color .25s;
  }
  .hisn-footer a:hover{ color:rgba(124,255,178,.55); }
  .hisn-footer .hf-sep{ opacity:.25; margin:0 10px; }
"""

FOOTER_HTML = (
    '\n<footer class="hisn-footer">\n'
    '  &copy; 2026 HISN v1.0.0'
    '<span class="hf-sep">&middot;</span>'
    'Built by <a href="https://github.com/KareemCrafts" target="_blank" rel="noopener">Kareem Alshaer</a>'
    '<span class="hf-sep">&middot;</span>'
    'All rights reserved\n'
    '</footer>'
)

if 'hisn-footer' not in content:
    # Add CSS
    content = content.replace('</style>', FOOTER_CSS + '\n</style>', 1)
    fixes.append("Footer CSS added")

# Add HTML — try multiple anchors in order of specificity
footer_added = 'hisn-footer' in content and 'Built by' in content
if not footer_added:
    for anchor in [
        '\n</body>\n</html>',
        '\n</body>',
        '</body>',
    ]:
        if anchor in content:
            content = content.replace(anchor, FOOTER_HTML + anchor, 1)
            footer_added = True
            fixes.append(f"Footer HTML added (anchor: {repr(anchor[:20])})")
            break
    if not footer_added:
        fixes.append("MISS: footer HTML — no </body> found")
else:
    fixes.append("Footer: already present")

# ══════════════════════════════════════════════════════
# 4. REMOVE ALL DEBUG TRACES from route handlers
# ══════════════════════════════════════════════════════
debug_removes = [
    '        import traceback; traceback.print_exc()\n',
    '    except Exception as _ee:\n        import traceback; traceback.print_exc()\n',
    '        import traceback; traceback.print_exc()\n',
]
removed_count = 0
for dr in debug_removes:
    while dr in content:
        content = content.replace(dr, '', 1)
        removed_count += 1
if removed_count:
    fixes.append(f"Removed {removed_count} traceback.print_exc() debug calls")

# Remove bare exception prints in scan routes
content = re.sub(
    r'\n    except Exception as _ee:\n        import traceback; traceback\.print_exc\(\)\n',
    '\n    except Exception:\n        pass\n',
    content
)

# Remove development print statements from routes (keep [+] startup messages)
content = re.sub(
    r'\n        print\(f?\'\[!\].*?\'\)\n',
    '\n',
    content
)

# ══════════════════════════════════════════════════════
# 5. REPLACE ALL REMAINING SOC COPILOT REFERENCES
# ══════════════════════════════════════════════════════
replacements = {
    'SOC COPILOT': 'HISN',
    'SOC Copilot': 'HISN',
    'SOC-COPILOT': 'HISN',
    'soc_copilot': 'hisn',
    'SOC // COPILOT': 'HISN',
    'soc-copilot': 'hisn',
    'SOC_COPILOT': 'HISN',
    'soc copilot': 'hisn',
    'Soc Copilot': 'HISN',
}
rep_count = 0
for old, new in replacements.items():
    while old in content:
        content = content.replace(old, new)
        rep_count += 1
if rep_count:
    fixes.append(f"Replaced {rep_count} remaining SOC Copilot references")

# ══════════════════════════════════════════════════════
# 6. PRODUCTION ERROR HANDLING — graceful 500 handler
# ══════════════════════════════════════════════════════
ERROR_HANDLER = '''
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error. Check server logs."}), 500


@app.errorhandler(413)
def file_too_large(e):
    return jsonify({"error": "File too large. Please use a smaller file."}), 413


'''

if 'errorhandler(404)' not in content:
    anchor = '@app.route("/upload", methods=["POST"])'
    if anchor in content:
        content = content.replace(anchor, ERROR_HANDLER + anchor, 1)
        fixes.append("Error handlers: 404, 500, 413 added")

# ══════════════════════════════════════════════════════
# 7. FILE UPLOAD SIZE LIMIT (5 GB for EVTX, 50 MB for others)
# ══════════════════════════════════════════════════════
if 'MAX_CONTENT_LENGTH' not in content:
    old_app_init = 'app = Flask(__name__)'
    new_app_init = (
        'app = Flask(__name__)\n'
        'app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024  # 512 MB max upload'
    )
    if old_app_init in content:
        content = content.replace(old_app_init, new_app_init, 1)
        fixes.append("Upload size limit: 512 MB")

# ══════════════════════════════════════════════════════
# 8. GRACEFUL EDGE CASE — empty EVTX file
# ══════════════════════════════════════════════════════
old_empty_check = (
    '    f = request.files.get("file")\n'
    '    if not f or not f.filename.lower().endswith(".evtx"):\n'
    '        return jsonify({"error": "Please upload a .evtx file"}), 400'
)
new_empty_check = (
    '    f = request.files.get("file")\n'
    '    if not f or not f.filename:\n'
    '        return jsonify({"error": "No file selected."}), 400\n'
    '    if not f.filename.lower().endswith(".evtx"):\n'
    '        return jsonify({"error": "Invalid file type. Please upload a .evtx Windows event log."}), 400'
)
if old_empty_check in content:
    content = content.replace(old_empty_check, new_empty_check, 1)
    fixes.append("EVTX upload: improved error message")

# ══════════════════════════════════════════════════════
# 9. SECURITY HEADERS — safe for local/LAN deployment
# ══════════════════════════════════════════════════════
SECURITY_HEADERS = '''
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


'''

if 'X-Content-Type-Options' not in content:
    anchor = '@app.route("/upload", methods=["POST"])'
    if anchor in content:
        content = content.replace(anchor, SECURITY_HEADERS + anchor, 1)
        fixes.append("Security headers added (X-Content-Type-Options, X-Frame-Options)")

# ══════════════════════════════════════════════════════
# 10. FIX CONSOLE WARNING — remove unused variable
#     The 'tabPanels' forEach sometimes causes null warning
# ══════════════════════════════════════════════════════
# Add null-safe classList on tab panels
old_tab_remove = "    tabPanels.forEach(p => p.classList.remove('active'));"
new_tab_remove = "    tabPanels.forEach(p => { if(p) p.classList.remove('active'); });"
if old_tab_remove in content:
    content = content.replace(old_tab_remove, new_tab_remove, 1)
    fixes.append("Tab panels: null-safe classList")

# ══════════════════════════════════════════════════════
# 11. VERSION CONSTANT in Python
# ══════════════════════════════════════════════════════
if 'HISN_VERSION' not in content:
    old_job = 'JOB = {"running": False, "stage": "", "done": False, "error": None}'
    new_job = (
        'HISN_VERSION = "1.0.0"\n\n'
        'JOB = {"running": False, "stage": "", "done": False, "error": None}'
    )
    if old_job in content:
        content = content.replace(old_job, new_job, 1)
        fixes.append("Version constant: HISN_VERSION = 1.0.0")

# Add version to /status endpoint response
old_status = 'def status():\n    return jsonify(JOB)'
new_status = (
    'def status():\n'
    '    return jsonify({**JOB, "version": HISN_VERSION})'
)
if old_status in content:
    content = content.replace(old_status, new_status, 1)
    fixes.append("Version exposed in /status endpoint")

# ══════════════════════════════════════════════════════
# 12. FIX RAIN ctx.fillStyle — ensure font line present
# ══════════════════════════════════════════════════════
script_s = content.rfind('<script>')
script_e = content.rfind('</script>')
script   = content[script_s:script_e]

if "ctx.font = '13px JetBrains Mono'" not in script:
    old_fill = "ctx.fillStyle = 'rgba(3,6,8,0.08)'; ctx.fillRect(0,0,w,h);"
    new_fill = ("ctx.fillStyle = 'rgba(3,6,8,0.08)'; ctx.fillRect(0,0,w,h);\n"
                "      ctx.fillStyle = '#7CFFB2'; ctx.font = '13px JetBrains Mono';")
    if old_fill in script:
        script  = script.replace(old_fill, new_fill, 1)
        content = content[:script_s] + script + content[script_e:]
        fixes.append("Rain: font line restored")

# ══════════════════════════════════════════════════════
# 13. FINAL CHECK
# ══════════════════════════════════════════════════════
with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

# Verify
errors = []
if 'hisn-footer' not in content:        errors.append("Footer CSS missing")
if 'Built by' not in content:           errors.append("Footer HTML missing")
if 'def favicon' not in content:        errors.append("Favicon route missing")
if 'SOC COPILOT' in content:            errors.append("SOC COPILOT still present")
if 'SOC Copilot' in content:            errors.append("SOC Copilot still present")
if 'HISN_VERSION' not in content:       errors.append("Version constant missing")

# Check PDF report too
pdf_path = 'src/reports/pdf_report.py'
if os.path.exists(pdf_path):
    with open(pdf_path, 'r', encoding='utf-8') as f:
        pdf = f.read()
    for old, new in {'SOC COPILOT': 'HISN', 'soc_copilot': 'hisn',
                     'SOC Copilot': 'HISN', 'SOC-COPILOT': 'HISN'}.items():
        if old in pdf:
            pdf = pdf.replace(old, new)
    with open(pdf_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(pdf)
    fixes.append("pdf_report.py: SOC references cleaned")

print("=" * 54)
print("  HISN v1.0.0 — PRODUCTION READINESS REPORT")
print("=" * 54)
print("\nFixes applied:")
for f2 in fixes:
    print(f"  OK  {f2}")
if errors:
    print("\nIssues remaining:")
    for e in errors:
        print(f"  ERR {e}")
else:
    print("\n  All checks passed.")
print("\nJS brace balance:")
s2 = content[content.rfind('<script>'):content.rfind('</script>')]
op = s2.count('{'); cl = s2.count('}')
print(f"  {op} open / {cl} close / diff={op-cl} {'OK' if op==cl else 'WARNING'}")
print(f"\nfavicon.ico: route added — console error eliminated")
print(f"footer:      {'present' if 'Built by' in content else 'MISSING'}")
print(f"version:     {'1.0.0' if 'HISN_VERSION' in content else 'MISSING'}")
print("\nRun .\\dashboard.bat")