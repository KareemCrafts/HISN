with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

script_start = content.rfind('<script>')
script_end   = content.rfind('</script>')
if script_start == -1 or script_end == -1:
    print("ERROR: cannot find script block"); exit()

script = content[script_start:script_end]
lines  = script.split('\n')
print(f"Script block: {len(lines)} lines")

checks = ['browseBtn','poll()','applyFilters','animateCount','tabBtns',
          'settingsPanel','aiWidget','phishingTab','renderPhishingResult']
for c in checks:
    print(f"  {'OK  ' if c in script else 'MISS'}: {c}")

opens  = script.count('{')
closes = script.count('}')
print(f"\nBraces: {opens} open / {closes} close  (diff = {opens-closes})")
if opens != closes:
    print("  *** MISMATCH — this is the JS killer ***")
else:
    print("  Braces balanced — look for a different cause")

# Check for </script inside the block (would terminate the tag early)
if '</script' in script.lower():
    print("  *** WARNING: </script found inside script block ***")