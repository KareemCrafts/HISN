import os, subprocess

ROOT = os.getcwd()

def write(path, content):
    full = os.path.join(ROOT, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, 'w', encoding='utf-8', newline='\n') as f:
        f.write(content)
    print(f"  wrote: {path}")

def git(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=ROOT)

# ── 1. FIX app.py ─────────────────────────────────────────────
print("[1/5] Fixing app.py PORT binding...")
app_path = os.path.join(ROOT, 'src', 'dashboard', 'app.py')
with open(app_path, 'r', encoding='utf-8') as f:
    app = f.read()

app = app.replace(
    '_port = int(_os.environ.get("FLASK_PORT", "5000"))',
    '_port = int(_os.environ.get("PORT", _os.environ.get("FLASK_PORT", "5000")))',
    1
)
app = app.replace(
    '_host = _os.environ.get("FLASK_HOST", "127.0.0.1")',
    '_host = _os.environ.get("FLASK_HOST", "0.0.0.0")',
    1
)

if '/health' not in app:
    health = (
        '\n\n@app.route("/health")\n'
        'def health_check():\n'
        '    return jsonify({"status": "ok", "version": HISN_VERSION}), 200\n\n'
    )
    anchor = '@app.route("/favicon.ico")'
    if anchor in app:
        app = app.replace(anchor, health + anchor, 1)
    print("  /health endpoint added")

with open(app_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(app)
print("  app.py: PORT + HOST + healthcheck fixed")

# ── 2. FIX Procfile ───────────────────────────────────────────
print("\n[2/5] Fixing Procfile...")
write('Procfile',
    'web: gunicorn --bind 0.0.0.0:$PORT --timeout 120 --workers 1 --threads 4 src.dashboard.app:app\n'
)

# ── 3. FIX railway.toml ───────────────────────────────────────
print("\n[3/5] Fixing railway.toml...")
write('railway.toml',
    '[build]\n'
    'builder = "nixpacks"\n'
    'buildCommand = "pip install -r requirements.txt && python setup_data.py"\n'
    '\n'
    '[deploy]\n'
    'startCommand = "gunicorn --bind 0.0.0.0:$PORT --timeout 120 --workers 1 --threads 4 src.dashboard.app:app"\n'
    'healthcheckPath = "/health"\n'
    'healthcheckTimeout = 60\n'
    'restartPolicyType = "on_failure"\n'
)

# ── 4. FIX setup_data.py ──────────────────────────────────────
print("\n[4/5] Making setup_data.py cloud-safe...")
setup_path = os.path.join(ROOT, 'setup_data.py')
if os.path.exists(setup_path):
    with open(setup_path, 'r', encoding='utf-8') as f:
        setup = f.read()

    if '_already_setup' not in setup:
        guard = (
            'import os as _os, sys as _sys\n'
            '_SIGMA = _os.path.join(_os.path.dirname(__file__), "rules", "sigma")\n'
            '_MITRE = _os.path.join(_os.path.dirname(__file__), "data", "enterprise-attack.json")\n'
            '_sigma_ok = _os.path.isdir(_SIGMA) and len(_os.listdir(_SIGMA)) > 100\n'
            '_mitre_ok = _os.path.isfile(_MITRE) and _os.path.getsize(_MITRE) > 10000\n'
            'def _already_setup(): return _sigma_ok and _mitre_ok\n'
            'if _already_setup():\n'
            '    print("[+] HISN: detection data already present, skipping download.")\n'
            '    _sys.exit(0)\n\n'
        )
        setup = guard + setup
        with open(setup_path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(setup)
        print("  setup_data.py: skip-if-exists guard added")
    else:
        print("  setup_data.py: already has guard")

# ── 5. COMMIT + PUSH ──────────────────────────────────────────
print("\n[5/5] Committing and pushing...")
git('git add .')
subprocess.run('git add .', shell=True, cwd=ROOT)

msg = 'fix: Railway deployment - PORT env var, gunicorn, health endpoint'
result = subprocess.run(
    ['git', 'commit', '-m', msg],
    capture_output=True, text=True, cwd=ROOT
)

if 'nothing to commit' in result.stdout + result.stderr:
    subprocess.run(
        ['git', 'commit', '--allow-empty', '-m', 'fix: trigger Railway redeploy'],
        cwd=ROOT
    )
    print("  Empty commit added to trigger redeploy")
else:
    print(f"  Committed: {msg}")

push = subprocess.run('git push origin main', shell=True, capture_output=True, text=True, cwd=ROOT)
if push.returncode == 0:
    print("  Pushed — Railway will redeploy in ~60 seconds")
else:
    print(f"  Push failed: {push.stderr[:200]}")
    print("  Run manually: git push origin main")

print("""
Done. Watch Railway redeploy at:
  railway.app -> your project -> Build Logs

Expected result:
  OK  Initialization
  OK  Build
  OK  Deploy
  OK  Network > Healthcheck  <- /health endpoint fixes this

DOMAIN OPTIONS (search at porkbun.com):
  gethisn.com    ~$10/yr  most likely available
  hisn.app       ~$14/yr  likely available
  hisn.dev       ~$12/yr  likely available
  hisnsoc.com    ~$10/yr  likely available
  usehisn.com    ~$10/yr  likely available

After buying: Railway -> Settings -> Networking -> Custom Domain
""")