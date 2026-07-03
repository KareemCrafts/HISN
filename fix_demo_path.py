import re

with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace the entire demo function body with one that uses absolute paths
old = '''@app.route("/demo", methods=["POST"])
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

new = '''@app.route("/demo", methods=["POST"])
def demo():
    import glob
    # Get the project root (where app.py lives, two levels up from src/dashboard/)
    here = os.path.dirname(os.path.abspath(__file__))          # src/dashboard/
    root = os.path.abspath(os.path.join(here, '..', '..'))     # project root

    search_dirs = [
        os.path.join(root, 'logs', 'samples'),
        os.path.join(root, 'uploads_web'),
        os.path.join(root, 'logs'),
        root,
    ]
    candidates = []
    for d in search_dirs:
        if os.path.isdir(d):
            for fname in os.listdir(d):
                if fname.lower().endswith('.evtx'):
                    candidates.append(os.path.join(d, fname))

    # Prefer brute-force or metasploit samples as they produce good results
    preferred = [c for c in candidates if any(x in c.lower() for x in ['metasploit','mimikatz','brute','security','uacme'])]
    if preferred:
        candidates = preferred

    if not candidates:
        return jsonify({"error": f"No .evtx files found under {root}"}), 404

    if JOB["running"]:
        return jsonify({"error": "A job is already running."}), 409

    chosen = candidates[0]
    engine = init_db()
    with Session(engine) as s:
        s.query(Alert).delete(); s.query(Incident).delete(); s.commit()
    JOB.update(running=True, done=False, error=None, stage=f"Loading demo: {os.path.basename(chosen)}...")
    threading.Thread(target=run_pipeline_job, args=(chosen,), daemon=True).start()
    return jsonify({"status": "started", "file": os.path.basename(chosen)})'''

if old in content:
    content = content.replace(old, new, 1)
    print("OK: demo route replaced with absolute-path version")
else:
    # Fallback: replace whatever demo function exists using regex
    import re
    pat = re.compile(
        r"@app\.route\(\"/demo\",.*?def demo\(\):.*?return jsonify\(\{\"status\": \"started\".*?\}\)\n",
        re.DOTALL
    )
    m = pat.search(content)
    if m:
        content = pat.sub(new + '\n', content, count=1)
        print("OK: demo route replaced (regex fallback)")
    else:
        print("ERROR: could not find demo route - injecting it fresh")
        anchor = '@app.route("/report/incidents")'
        if anchor in content:
            content = content.replace(anchor, new + '\n\n\n' + anchor, 1)
            print("OK: demo route injected fresh")

with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print("Done.")