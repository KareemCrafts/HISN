import webbrowser, time

print("""
GitHub repository configuration steps:
Open each URL and complete the action.
""")

steps = [
    ("https://github.com/KareemCrafts/HISN",
     "1. Verify repo is public and README is visible"),
    ("https://github.com/KareemCrafts/HISN/settings",
     "2. Add Description: 'Unified Threat Investigation & Analytics Tool'"),
    ("https://github.com/KareemCrafts/HISN/releases/new",
     "3. Create v1.0.0 release"),
    ("https://github.com/KareemCrafts/HISN/security",
     "4. Enable Dependabot + secret scanning"),
]

for url, label in steps:
    print(f"  Opening: {label}")
    webbrowser.open(url)
    time.sleep(2)