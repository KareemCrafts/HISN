import os, subprocess

ROOT = os.getcwd()

def write(path, content):
    full = os.path.join(ROOT, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, 'w', encoding='utf-8', newline='\n') as f:
        f.write(content)
    print(f"  wrote: {path}")

def git(cmd):
    return subprocess.run(f'git {cmd}', shell=True, capture_output=True, text=True, cwd=ROOT)

# ══════════════════════════════════════════════════════
# 1. FIX app.py — read Railway's PORT env var
# ══════════════════════════════════════════════════════
print("[1/5] Fixing PORT env var in app.py...")
app_path = os.path.join(ROOT, 'src', 'dashboard', 'app.py')
with open(app_path, 'r', encoding='utf-8') as f:
    app = f.read()

# Fix the __main__ block to read PORT (Railway standard) first
old_port = '_port = int(_os.environ.get("FLASK_PORT", "5000"))'
new_port = '_port = int(_os.environ.get("PORT", _os.environ.get("FLASK_PORT", "5000")))'
if old_port in app:
    app = app.replace(old_port, new_port, 1)
    print("  PORT: reads Railway $PORT first")

# Fix host to always bind 0.0.0.0 in production
old_host = '_host = _os.environ.get("FLASK_HOST", "127.0.0.1")'
new_host = '_host = _os.environ.get("FLASK_HOST", "0.0.0.0")'
if old_host in app:
    app = app.replace(old_host, new_host, 1)
    print("  HOST: defaults to 0.0.0.0 (required for Railway)")

# Add /health endpoint for Railway healthcheck
health_route = '''
@app.route("/health")
def health_check():
    """Railway/Render healthcheck endpoint."""
    return jsonify({"status": "ok", "version": HISN_VERSION, "service": "HISN"}), 200


'''
if '/health' not in app:
    anchor = '@app.route("/favicon.ico")'
    if anchor in app:
        app = app.replace(anchor, health_route + anchor, 1)
        print("  /health endpoint added")

with open(app_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(app)

# ══════════════════════════════════════════════════════
# 2. FIX Procfile — gunicorn with $PORT
# ══════════════════════════════════════════════════════
print("\n[2/5] Fixing Procfile with gunicorn...")
write('Procfile',
    'web: gunicorn --bind 0.0.0.0:$PORT --timeout 120 --workers 1 --threads 4 src.dashboard.app:app\n'
)

# ══════════════════════════════════════════════════════
# 3. FIX railway.toml — correct port + healthcheck
# ══════════════════════════════════════════════════════
print("\n[3/5] Fixing railway.toml...")
write('railway.toml', '''[build]
builder = "nixpacks"
buildCommand = "pip install -r requirements.txt && python setup_data.py"

[deploy]
startCommand = "gunicorn --bind 0.0.0.0:$PORT --timeout 120 --workers 1 --threads 4 src.dashboard.app:app"
healthcheckPath = "/health"
healthcheckTimeout = 60
restartPolicyType = "on_failure"
''')

# ══════════════════════════════════════════════════════
# 4. FIX setup_data.py — graceful in cloud (no crash if slow)
# ══════════════════════════════════════════════════════
print("\n[4/5] Making setup_data.py cloud-safe...")
setup_path = os.path.join(ROOT, 'setup_data.py')
if os.path.exists(setup_path):
    with open(setup_path, 'r', encoding='utf-8') as f:
        setup = f.read()

    # Add skip-if-exists logic at the top
    skip_guard = '''# HISN Setup — downloads Sigma rules + MITRE ATT&CK data
# Safe to re-run: skips if data already exists
import os, sys

SIGMA_DIR = os.path.join(os.path.dirname(__file__), 'rules', 'sigma')
MITRE_FILE = os.path.join(os.path.dirname(__file__), 'data', 'enterprise-attack.json')

# In production (Railway/Render), data is downloaded during build phase
# Skip gracefully if network is unavailable
def _already_setup():
    sigma_ok = os.path.isdir(SIGMA_DIR) and len(os.listdir(SIGMA_DIR)) > 100
    mitre_ok = os.path.isfile(MITRE_FILE) and os.path.getsize(MITRE_FILE) > 10000
    return sigma_ok and mitre_ok

if _already_setup():
    print("[+] HISN: detection data already present, skipping download.")
    sys.exit(0)

'''
    if '_already_setup' not in setup:
        setup = skip_guard + setup
        with open(setup_path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(setup)
        print("  setup_data.py: cloud-safe skip guard added")
    else:
        print("  setup_data.py: already has skip guard")

# ══════════════════════════════════════════════════════
# 5. COMMIT + PUSH → triggers Railway redeploy
# ══════════════════════════════════════════════════════
print("\n[5/5] Committing and pushing to trigger redeploy...")
git('add .')
result = git('commit -m "fix: Railway deployment — PORT env var, gunicorn, /health endpoint\n\n- Read Railway\\'s PORT env var (was reading FLASK_PORT only)\n- Switch to gunicorn for production stability\n- Add /health endpoint for Railway healthcheck\n- Fix HOST default to 0.0.0.0\n- setup_data.py: skip-if-exists guard for cloud builds"')

if 'nothing to commit' in result.stdout + result.stderr:
    print("  Nothing new — forcing push of existing commit...")
    git('commit --allow-empty -m "fix: trigger Railway redeploy"')

push = git('push origin main')
if push.returncode == 0:
    print("  Pushed successfully — Railway will auto-redeploy in ~60 seconds")
else:
    print(f"  Push output: {push.stderr[:200]}")
    print("  Run manually: git push origin main")

# ══════════════════════════════════════════════════════
# DOMAIN GUIDANCE
# ══════════════════════════════════════════════════════
print("""
═══════════════════════════════════════════════════════
  RAILWAY: Should redeploy automatically in ~60s
  Check: railway.app → your project → Deploy logs
═══════════════════════════════════════════════════════

DOMAIN OPTIONS (cheapest to most expensive):
─────────────────────────────────────────────
  Best deals — check availability at porkbun.com:

  gethisn.com       ~$10/year  (likely available)
  hisn.app          ~$14/year  (likely available)
  hisn.dev          ~$12/year  (likely available)
  hisn.io           ~$30/year  (might be taken)
  hisnsoc.com       ~$10/year  (likely available)
  hisntool.com      ~$10/year  (likely available)
  usehisn.com       ~$10/year  (likely available)
  hisn.com          ~$10/year  (probably taken)

  Best registrar: porkbun.com (cheapest, good UI)
  Alt: cloudflare.com/products/registrar (at-cost)

CONNECTING DOMAIN TO RAILWAY:
  1. Buy domain at porkbun.com
  2. Railway → Settings → Networking → Custom Domain
  3. Copy the CNAME target Railway gives you
  4. At Porkbun → DNS → Add CNAME record:
       Host:  @  (or www)
       Value: [Railway CNAME target]
       TTL:   300
  5. Back in Railway → Verify domain
  6. Railway auto-provisions SSL certificate (free)
  Live in ~5 minutes after DNS propagates.
""")