import re

with open("src/dashboard/app.py", "r", encoding="utf-8") as f:
    content = f.read()

fixes = []

# ── 1. RAIN: restore font line ──────────────────────────────────────
old_rain = "      ctx.fillStyle = 'rgba(3,6,8,0.08)'; ctx.fillRect(0,0,w,h);\n      for (let i=0"
new_rain = ("      ctx.fillStyle = 'rgba(3,6,8,0.08)'; ctx.fillRect(0,0,w,h);\n"
            "      ctx.fillStyle = '#7CFFB2'; ctx.font = '13px JetBrains Mono';\n"
            "      for (let i=0")
if old_rain in content:
    content = content.replace(old_rain, new_rain, 1); fixes.append("Rain font line restored")
else:
    fixes.append("MISS: rain font line")

# ── 2. RAIN: slow down ───────────────────────────────────────────────
for fast, slow in [("y + 18;", "y + 6;"), ("y + 18 :", "y + 6 :")]:
    if fast in content:
        content = content.replace(fast, slow, 1); fixes.append("Rain slowed down"); break

# ── 3. TITLE: HISN only ─────────────────────────────────────────────
for old_t in ["<title>HISN // UNIFIED THREAT INVESTIGATION</title>",
              "<title>SOC COPILOT // BLACK SITE</title>",
              "<title>HISN // UNIFIED THREAT INVESTIGATION // BLACK SITE</title>"]:
    if old_t in content:
        content = content.replace(old_t, "<title>HISN</title>", 1)
        fixes.append("Title set to HISN"); break

# ── 4. HEADER LAYOUT: stacked 3-line ────────────────────────────────
# Add CSS for title-sub
CSS_INJECT = """
  .title-sub{
    color:#C8D6CF; font-size:11px; letter-spacing:.28em; text-transform:uppercase;
    margin-top:6px; font-family:'JetBrains Mono',monospace; font-weight:500;
    opacity:.9;
  }
"""
if ".title-sub" not in content:
    content = content.replace("</style>", CSS_INJECT + "\n</style>", 1)
    fixes.append("title-sub CSS added")

# Replace the subline HTML to be stacked (handle both possible existing formats)
old_sublines = [
    '<div class="subline"><span class="ai-dot"></span>UNIFIED THREAT INVESTIGATION &amp; ANALYTICS TOOL <span style="opacity:.5">// YOUR ENTIRE INVESTIGATION, ALL IN ONE PLACE.</span></div>',
    '<div class="subline"><span class="ai-dot"></span>UNIFIED THREAT INVESTIGATION &amp; ANALYTICS TOOL<span style="opacity:.5"> // YOUR ENTIRE INVESTIGATION, ALL IN ONE PLACE.</span></div>',
]
new_subline = ('<div class="title-sub">UNIFIED THREAT INVESTIGATION &amp; ANALYTICS TOOL</div>\n'
               '      <div class="subline"><span class="ai-dot"></span>YOUR ENTIRE INVESTIGATION, ALL IN ONE PLACE.</div>')
for old_s in old_sublines:
    if old_s in content:
        content = content.replace(old_s, new_subline, 1)
        fixes.append("Header layout: 3-line stacked"); break
else:
    # Fallback: regex replace
    pat = re.compile(r'<div class="subline">.*?</div>', re.DOTALL)
    m = pat.search(content)
    if m and 'UNIFIED' in m.group():
        content = content[:m.start()] + new_subline + content[m.end():]
        fixes.append("Header layout: regex fallback")

# ── 5. EMPTY STATE: demo button + clear note ─────────────────────────
old_empty = '  {% if total_alerts == 0 %}\n  <div class="empty">// no telemetry ingested · awaiting .evtx</div>'
new_empty = (
    '  {% if total_alerts == 0 %}\n'
    '  <div class="empty" style="padding:48px 28px; text-align:center;">\n'
    '    <div style="font-size:13px; color:var(--ink); margin-bottom:10px; letter-spacing:.15em;">'
    '// no telemetry ingested · awaiting .evtx</div>\n'
    '    <div class="ioc-muted" style="margin-bottom:20px; max-width:520px; margin-left:auto; margin-right:auto;">'
    'Upload any Windows event log (.evtx) to begin investigation. '
    'All analysis runs locally — nothing leaves this machine.</div>\n'
    '    <button type="button" class="browse-btn" id="demoBtn" style="margin-top:0;">Load Demo Analysis</button>\n'
    '    <div id="demoMsg" class="ioc-muted" style="margin-top:10px;"></div>\n'
    '  </div>'
)
if old_empty in content:
    content = content.replace(old_empty, new_empty, 1); fixes.append("Demo button added to empty state")

# ── 6. DEMO JS: wire the button ──────────────────────────────────────
DEMO_JS = """
  // Demo loader
  (function demoLoader(){
    var db = document.getElementById('demoBtn');
    if (!db) return;
    db.addEventListener('click', function(){
      db.textContent = 'Loading...'; db.disabled = true;
      fetch('/demo', {method: 'POST'})
        .then(function(r){ return r.json(); })
        .then(function(d){
          if (d.status === 'started') {
            document.getElementById('demoMsg').textContent = 'Pipeline started — page will reload when done.';
            var pollDemo = setInterval(function(){
              fetch('/status').then(function(r){ return r.json(); }).then(function(j){
                if (j.done) { clearInterval(pollDemo); location.reload(); }
              });
            }, 1200);
          } else {
            document.getElementById('demoMsg').textContent = d.error || 'No sample file found. Upload a .evtx to begin.';
            db.disabled = false; db.textContent = 'Load Demo Analysis';
          }
        })
        .catch(function(){ db.disabled = false; db.textContent = 'Load Demo Analysis'; });
    });
  })();

"""
anchor = "  document.querySelectorAll('.cell.hit').forEach"
if anchor in content and 'demoLoader' not in content:
    content = content.replace(anchor, DEMO_JS + "\n  " + "document.querySelectorAll('.cell.hit').forEach", 1)
    fixes.append("Demo JS injected")

# ── 7. DEMO ROUTE ────────────────────────────────────────────────────
DEMO_ROUTE = '''
@app.route("/demo", methods=["POST"])
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
    return jsonify({"status": "started"})


'''
if '/demo' not in content:
    anchor_route = '@app.route("/report/incidents")'
    if anchor_route in content:
        content = content.replace(anchor_route, DEMO_ROUTE + anchor_route, 1)
        fixes.append("Demo route added")

# ── 8. CLEAR DB ON STARTUP ───────────────────────────────────────────
old_run = 'if __name__ == "__main__":\n    app.run(debug=False, port=5000)'
new_run = ('if __name__ == "__main__":\n'
           '    # Clear previous session on every restart — fresh start each time\n'
           '    _e = init_db()\n'
           '    with Session(_e) as _s:\n'
           '        _s.query(Alert).delete(); _s.query(Incident).delete(); _s.commit()\n'
           '    app.run(debug=False, port=5000)')
if old_run in content:
    content = content.replace(old_run, new_run, 1); fixes.append("Clear on startup added")

with open("src/dashboard/app.py", "w", encoding="utf-8", newline="\n") as f:
    f.write(content)

print("\nFixes applied:")
for f2 in fixes:
    print(f"  OK: {f2}")
print("\nDone.")