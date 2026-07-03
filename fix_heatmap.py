import re

with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Pattern: heatmap block then MITRE section
pattern = re.compile(
    r'(\s*{%-?\s*if host_stats\s*-?%\}.*?{%-?\s*endif\s*-?%\})'  # heatmap block
    r'(\s*<div class="section-label">MITRE ATT&amp;CK Coverage.*?</div>\s*)'  # MITRE label
    r'(\s*<div class="matrix">.*?</div>\s*)',  # MITRE matrix
    re.DOTALL
)

m = pattern.search(content)
if m:
    heatmap = m.group(1)
    mitre_label = m.group(2)
    mitre_matrix = m.group(3)
    new_order = mitre_label + mitre_matrix + '\n' + heatmap
    content = content[:m.start()] + new_order + content[m.end():]
    with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
        f.write(content)
    print("Heatmap moved below MITRE matrix.")
else:
    print("Pattern not found — paste the check_js.py output so I can debug.")