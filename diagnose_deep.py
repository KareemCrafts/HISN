import re
from collections import Counter

with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

script_start = content.rfind('<script>')
script_end   = content.rfind('</script>')
script = content[script_start+8:script_end]
lines  = script.split('\n')

print(f"Script: {len(lines)} lines\n")

# 1. Paren + bracket balance
p_open = script.count('('); p_close = script.count(')')
b_open = script.count('['); b_close = script.count(']')
print(f"Parens:   {p_open} open / {p_close} close  (diff={p_open-p_close})")
print(f"Brackets: {b_open} open / {b_close} close  (diff={b_open-b_close})")

# 2. Duplicate const / let declarations
consts = re.findall(r'\b(?:const|let)\s+(\w+)\b', script)
dupes = [(n, c) for n, c in Counter(consts).items() if c > 1]
if dupes:
    print(f"\n*** DUPLICATE DECLARATIONS (this breaks strict mode): ***")
    for name, count in dupes:
        for i, l in enumerate(lines):
            if re.search(rf'\b(?:const|let)\s+{name}\b', l):
                print(f"  Line {i+1}: {l.strip()[:90]}")
else:
    print("\nNo duplicate const/let declarations.")

# 3. Show first 40 lines
print("\n=== FIRST 40 LINES OF SCRIPT ===")
for i, l in enumerate(lines[:40], 1):
    print(f"{i:3}: {l[:110]}")

# 4. AI_GLOBAL_CONTEXT line
gc = next((i for i,l in enumerate(lines) if 'AI_GLOBAL_CONTEXT' in l), None)
if gc:
    print(f"\n=== AI_GLOBAL_CONTEXT at line {gc+1} ===")
    print(lines[gc][:200])

# 5. Count how many times key functions appear (should each be 1)
for fn in ['function escapeHtml', 'function sendFile', 'function poll', 
           'function applyFilters', 'phishingTab', 'renderPhishingResult']:
    n = script.count(fn)
    flag = '*** DUPLICATE ***' if n > 1 else 'OK'
    print(f"  {flag}: '{fn}' appears {n} time(s)")

# 6. Heatmap position in template
html_part = content[content.find('{% if total_alerts == 0 %}'):content.find('<script>')]
hm_pos  = html_part.find('{% if host_stats %}')
mat_pos = html_part.find('class="matrix"')
inc_pos = html_part.find('Incident Case Files')
print(f"\n=== TEMPLATE SECTION ORDER (positions) ===")
print(f"  Matrix div:    {mat_pos}")
print(f"  host_stats if: {hm_pos}")
print(f"  Case Files:    {inc_pos}")
if hm_pos < mat_pos:
    print("  *** heatmap is BEFORE the matrix (wrong) ***")
elif hm_pos > mat_pos and hm_pos < inc_pos:
    print("  Heatmap is between matrix and case files (CORRECT)")
elif hm_pos == -1:
    print("  *** heatmap block NOT FOUND in template ***")