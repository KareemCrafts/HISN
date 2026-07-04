import os, subprocess

ROOT = os.getcwd()

def git(cmd_list):
    return subprocess.run(cmd_list, capture_output=True, text=True, cwd=ROOT)

# ── 1. DELETE Dockerfile so Railway uses nixpacks + Procfile ───
dockerfile = os.path.join(ROOT, 'Dockerfile')
if os.path.exists(dockerfile):
    os.remove(dockerfile)
    print("OK: Dockerfile removed (Railway will now use Procfile)")

# ── 2. DELETE docker-compose.yml from root (keep docs only) ───
dc = os.path.join(ROOT, 'docker-compose.yml')
# Keep it — it's useful for local. Just ensure Dockerfile is gone.

# ── 3. Verify Procfile is correct ─────────────────────────────
procfile_path = os.path.join(ROOT, 'Procfile')
correct = 'web: gunicorn --bind 0.0.0.0:$PORT --timeout 120 --workers 1 --threads 4 src.dashboard.app:app\n'
with open(procfile_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(correct)
print("OK: Procfile verified — gunicorn binds to 0.0.0.0:$PORT")

# ── 4. Clean railway.toml — remove [env] section Railway ignores ──
toml = (
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
with open(os.path.join(ROOT, 'railway.toml'), 'w', encoding='utf-8', newline='\n') as f:
    f.write(toml)
print("OK: railway.toml cleaned — no unsupported [env] section")

# ── 5. Write a minimal Dockerfile for Docker users (not Railway) ──
# Renamed to Dockerfile.docker so Railway ignores it
docker_content = (
    '# HISN Docker Image — for local/VPS use only\n'
    '# Railway users: this file is intentionally named Dockerfile.docker\n'
    '# Railway deploys via Procfile + nixpacks\n'
    'FROM python:3.11-slim\n'
    'WORKDIR /app\n'
    'RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*\n'
    'COPY requirements.txt .\n'
    'RUN pip install --no-cache-dir -r requirements.txt\n'
    'COPY src/ ./src/\n'
    'COPY setup_data.py run_all.py ./\n'
    'RUN python setup_data.py\n'
    'RUN mkdir -p uploads_web uploads_docs logs/samples\n'
    'EXPOSE 8080\n'
    'ENV FLASK_HOST=0.0.0.0\n'
    'ENV PORT=8080\n'
    'CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-8080} --timeout 120 --workers 1 --threads 4 src.dashboard.app:app"]\n'
)
with open(os.path.join(ROOT, 'Dockerfile.docker'), 'w', encoding='utf-8', newline='\n') as f:
    f.write(docker_content)
print("OK: Dockerfile.docker created (Railway ignores this, Docker users use it)")

# ── 6. Ensure /health endpoint is in app.py ───────────────────
app_path = os.path.join(ROOT, 'src', 'dashboard', 'app.py')
with open(app_path, 'r', encoding='utf-8') as f:
    app = f.read()

if '/health' not in app:
    health = (
        '\n\n@app.route("/health")\n'
        'def health_check():\n'
        '    return jsonify({"status": "ok", "version": HISN_VERSION}), 200\n\n'
    )
    for anchor in ['@app.route("/favicon.ico")', '@app.route("/upload"']:
        if anchor in app:
            app = app.replace(anchor, health + anchor, 1)
            break
    with open(app_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(app)
    print("OK: /health endpoint added to app.py")
else:
    print("OK: /health endpoint already present")

# Fix PORT binding
app_path2 = os.path.join(ROOT, 'src', 'dashboard', 'app.py')
with open(app_path2, 'r', encoding='utf-8') as f:
    app2 = f.read()

app2 = app2.replace(
    '_port = int(_os.environ.get("FLASK_PORT", "5000"))',
    '_port = int(_os.environ.get("PORT", _os.environ.get("FLASK_PORT", "5000")))'
)
app2 = app2.replace(
    '_host = _os.environ.get("FLASK_HOST", "127.0.0.1")',
    '_host = _os.environ.get("FLASK_HOST", "0.0.0.0")'
)
with open(app_path2, 'w', encoding='utf-8', newline='\n') as f:
    f.write(app2)
print("OK: app.py binds to 0.0.0.0:$PORT")

# ── 7. Update .gitignore to ignore Dockerfile (not .docker version) ─
gi_path = os.path.join(ROOT, '.gitignore')
with open(gi_path, 'r', encoding='utf-8') as f:
    gi = f.read()
# Make sure Dockerfile is NOT in gitignore (we want Dockerfile.docker committed)
if '\nDockerfile\n' in gi:
    gi = gi.replace('\nDockerfile\n', '\n')
    with open(gi_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(gi)

# ── 8. COMMIT AND PUSH ────────────────────────────────────────
subprocess.run('git add .', shell=True, cwd=ROOT)
subprocess.run('git rm --cached Dockerfile 2>nul', shell=True, cwd=ROOT)

result = subprocess.run(
    ['git', 'commit', '-m',
     'fix: remove Dockerfile so Railway uses nixpacks + Procfile\n\n'
     'Railway was using Dockerfile (binding 127.0.0.1) instead of\n'
     'Procfile gunicorn command (binding 0.0.0.0:$PORT).\n'
     'Dockerfile renamed to Dockerfile.docker for local/VPS use only.'],
    capture_output=True, text=True, cwd=ROOT
)
print(f"git commit: {result.stdout.strip() or result.stderr.strip()[:80]}")

push = subprocess.run('git push origin main', shell=True, capture_output=True, text=True, cwd=ROOT)
if push.returncode == 0:
    print("OK: pushed to GitHub")
else:
    print(f"Push: {push.stderr[:100]}")
    print("Run manually: git push origin main")

print("""
═══════════════════════════════════════════════════════════
  WHAT TO DO NOW
═══════════════════════════════════════════════════════════

STEP 1: Add payment method to Railway (required)
  railway.app/workspace/billing
  You will NOT be charged — $5 free credit covers weeks of use.
  No credit card = workspace stays restricted.

STEP 2: In Railway dashboard (after billing resolved)
  Service -> Settings -> Deploy section:
  - Start command: [leave empty — Procfile handles it]
  - OR set to: gunicorn --bind 0.0.0.0:$PORT --timeout 120 --workers 1 --threads 4 src.dashboard.app:app
  Then click "Redeploy"

STEP 3: After successful deploy, connect your domain:
  Service -> Settings -> Networking -> Custom Domain -> Add

═══════════════════════════════════════════════════════════
  ALTERNATIVE: Render.com (truly free, no credit card)
═══════════════════════════════════════════════════════════
  1. render.com -> New -> Web Service
  2. Connect GitHub -> select HISN repo
  3. Build command: pip install -r requirements.txt && python setup_data.py
  4. Start command: gunicorn --bind 0.0.0.0:$PORT --timeout 120 --workers 1 --threads 4 src.dashboard.app:app
  5. Add env vars: ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY
  6. Deploy (free tier, spins down after 15min inactivity)
  7. Add custom domain in Render settings
""")