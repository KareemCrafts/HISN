with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

script_start = content.rfind('<script>')
script_end   = content.rfind('</script>')
script = content[script_start:script_end]
lines = script.split('\n')

print(f"Script: {len(lines)} lines total\n")

# Show first 30 lines (where global declarations and first code lives)
print("=== FIRST 30 LINES ===")
for i, line in enumerate(lines[:30], 1):
    print(f"{i:3}: {line[:110]}")

# Check for unbalanced single quotes per line (catches unclosed string literals)
print("\n=== LINES WITH POSSIBLY UNBALANCED SINGLE QUOTES ===")
import re
problems = []
for i, line in enumerate(lines, 1):
    stripped = re.sub(r"\\'", '', line)       # remove escaped quotes
    stripped = re.sub(r'"[^"]*"', '""', stripped)  # remove double-quoted content
    count = stripped.count("'")
    if count % 2 != 0:
        problems.append((i, count, line[:100]))
if problems:
    for i, c, l in problems[:20]:
        print(f"  Line {i} ({c} quotes): {l}")
else:
    print("  None found.")

# Check the phishing JS section specifically
ph_start = next((i for i,l in enumerate(lines) if 'PHISHING TAB' in l), None)
if ph_start:
    print(f"\n=== PHISHING JS: lines {ph_start+1} to {ph_start+30} ===")
    for i, line in enumerate(lines[ph_start:ph_start+30], ph_start+1):
        print(f"{i:3}: {line[:110]}")
else:
    print("\nPhishing JS section NOT FOUND in script block.")

# Check for the AI_GLOBAL_CONTEXT line
gc = next((i for i,l in enumerate(lines) if 'AI_GLOBAL_CONTEXT' in l), None)
if gc:
    print(f"\n=== AI_GLOBAL_CONTEXT (line {gc+1}) ===")
    print(f"  {lines[gc][:200]}")
else:
    print("\nAI_GLOBAL_CONTEXT line NOT FOUND.")