import re, os

with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

fixes = []

# ── 1. FIX DEMO ROUTE — more robust file discovery ───────────────────
old_demo = '''@app.route("/demo", methods=["POST"])
def demo():
    import glob
    samples = (glob.glob("logs/samples/*.evtx") +
               glob.glob("logs/**/*.evtx", recursive=True) +
               glob.glob("uploads_web/*.evtx"))
    if not samples:
        return jsonify({"error": "No .evtx sample files found. Upload a .evtx file first to use it as a demo."}), 404
    if JOB["running"]:
        return jsonify({"error": "A job is already running."}), 409
    engine = init_db()
    with Session(engine) as s:
        s.query(Alert).delete(); s.query(Incident).delete(); s.commit()
    JOB.update(running=True, done=False, error=None, stage="Loading demo data...")
    threading.Thread(target=run_pipeline_job, args=(samples[0],), daemon=True).start()
    return jsonify({"status": "started"})'''

new_demo = '''@app.route("/demo", methods=["POST"])
def demo():
    import glob
    # Search all likely locations for any .evtx file
    candidates = []
    for pattern in ["logs/samples/*.evtx", "logs/**/*.evtx", "uploads_web/*.evtx",
                     "uploads/*.evtx", "*.evtx", "**/*.evtx"]:
        try:
            candidates.extend(glob.glob(pattern, recursive=True))
        except Exception:
            pass
    # Deduplicate and take the newest file
    candidates = list(set(os.path.abspath(p) for p in candidates if os.path.isfile(p)))
    if candidates:
        candidates.sort(key=os.path.getmtime, reverse=True)
    if not candidates:
        return jsonify({"error": "No .evtx sample found. Upload a .evtx file once — it will then be available as a demo."}), 404
    if JOB["running"]:
        return jsonify({"error": "A job is already running."}), 409
    engine = init_db()
    with Session(engine) as s:
        s.query(Alert).delete(); s.query(Incident).delete(); s.commit()
    JOB.update(running=True, done=False, error=None, stage="Loading demo data...")
    threading.Thread(target=run_pipeline_job, args=(candidates[0],), daemon=True).start()
    return jsonify({"status": "started", "file": os.path.basename(candidates[0])})'''

if old_demo in content:
    content = content.replace(old_demo, new_demo, 1); fixes.append("Demo route: robust file discovery")
else:
    print("MISS: demo route (may already be patched)")

# ── 2. REMOVE // FROM EMPTY STATE ────────────────────────────────────
for old, new in [
    ('// no telemetry ingested · awaiting .evtx', 'no telemetry ingested · awaiting .evtx'),
    ('// NO TELEMETRY INGESTED · AWAITING .EVTX', 'NO TELEMETRY INGESTED · AWAITING .EVTX'),
]:
    if old in content:
        content = content.replace(old, new); fixes.append("Removed // from empty state")

# ── 3. ADD .EML NOTE TO PHISHING DROPZONE ────────────────────────────
old_drop = '<p style="color:var(--meta);margin-top:8px;">Drop an .eml, .msg, or screenshot to begin investigation</p>'
new_drop = ('<p style="color:var(--meta);margin-top:8px;">Drop an .eml, .msg, or screenshot to begin investigation</p>\n'
            '      <p style="color:var(--acid);font-size:10px;letter-spacing:.08em;margin-top:6px;opacity:.8;">'
            '&#9650; For the most complete analysis, use an .eml or .msg file. '
            'Screenshots can extract visible text only — headers and auth data will be unavailable.</p>')
if old_drop in content:
    content = content.replace(old_drop, new_drop, 1); fixes.append(".eml note added to phishing tab")
else:
    print("MISS: phishing dropzone text not found")

# ── 4. FIX AI CONTEXT BANNER: email shows 'Email' not 'Document' ────
old_banner = ("      } else {\n"
              "        const kind = state.context.type === 'incident' ? 'Case' : 'Document';\n"
              "        banner.textContent = 'Currently referencing: ' + kind + ' — ' + (state.context.label || 'unnamed');\n"
              "        banner.classList.add('has-context');\n"
              "      }")
new_banner = ("      } else {\n"
              "        const kind = state.context.type === 'incident' ? 'Case' :\n"
              "                     state.context.type === 'email' ? 'Email' : 'Document';\n"
              "        banner.textContent = 'Currently referencing: ' + kind + ' — ' + (state.context.label || 'unnamed');\n"
              "        banner.classList.add('has-context');\n"
              "      }")
if old_banner in content:
    content = content.replace(old_banner, new_banner, 1); fixes.append("AI banner: email shows 'Email' type")
else:
    # Try alternate form
    content = content.replace(
        "const kind = state.context.type === 'incident' ? 'Case' : 'Document';",
        "const kind = state.context.type === 'incident' ? 'Case' : state.context.type === 'email' ? 'Email' : 'Document';",
        1); fixes.append("AI banner: email type (alt)")

# ── 5. FIX AI PRESET CHIPS: add email to more presets ────────────────
content = content.replace(
    "{key:'summarize', label:'Summarize Investigation', contexts:['incident','document']}",
    "{key:'summarize', label:'Summarize Investigation', contexts:['incident','document','email']}",
    1)
content = content.replace(
    "{key:'next_steps', label:'What Should I Investigate Next?', contexts:['incident','document']}",
    "{key:'next_steps', label:'What Should I Investigate Next?', contexts:['incident','document','email']}",
    1)
content = content.replace(
    "{key:'false_positive', label:'Is This a False Positive?', contexts:['incident','document']}",
    "{key:'false_positive', label:'Is This a False Positive?', contexts:['incident','document','email']}",
    1)
content = content.replace(
    "{key:'exec_summary', label:'Generate Executive Summary', contexts:['incident','document']}",
    "{key:'exec_summary', label:'Generate Executive Summary', contexts:['incident','document','email']}",
    1)
fixes.append("Email added to more AI preset chips")

# ── 6. FIX PHISHING AI BUTTON: explicitly sets email context ─────────
old_ai_btn = ("          var ab=document.getElementById('phishingAiBtn');\n"
              "          if (ab) ab.addEventListener('click', function(){\n"
              "            if (window.aiSetContext) window.aiSetContext('email', lastEmailResult, lastEmailResult.filename||'Email');\n"
              "            var wt=document.getElementById('aiWidgetToggle'); if(wt) wt.click();\n"
              "          });")
new_ai_btn = ("          var ab=document.getElementById('phishingAiBtn');\n"
              "          if (ab) ab.addEventListener('click', function(){\n"
              "            if (window.aiSetContext) window.aiSetContext('email', lastEmailResult, lastEmailResult.filename||'Email');\n"
              "            var wt=document.getElementById('aiWidgetToggle');\n"
              "            if (wt) {\n"
              "              wt.click();\n"
              "              // Force update banner and chips immediately\n"
              "              setTimeout(function(){\n"
              "                var banner=document.getElementById('aiContextBanner');\n"
              "                if(banner){banner.textContent='Referencing Email: '+(lastEmailResult.filename||'');banner.classList.add('has-context');}\n"
              "              }, 100);\n"
              "            }\n"
              "          });")
if old_ai_btn in content:
    content = content.replace(old_ai_btn, new_ai_btn, 1); fixes.append("Phishing AI button: explicit context + banner update")
else:
    print("MISS: phishing AI button pattern")

# ── 7. DEMO JS: show filename in message ─────────────────────────────
old_demo_js = ("          document.getElementById('demoMsg').textContent = 'Pipeline started — page will reload when done.';\n")
new_demo_js = ("          var fname = d.file ? ' ('+d.file+')' : '';\n"
               "          document.getElementById('demoMsg').textContent = 'Pipeline started'+fname+' — page will reload when done.';\n")
if old_demo_js in content:
    content = content.replace(old_demo_js, new_demo_js, 1); fixes.append("Demo JS: shows filename")

with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

print("\nFixes applied:")
for f2 in fixes: print(f"  OK: {f2}")