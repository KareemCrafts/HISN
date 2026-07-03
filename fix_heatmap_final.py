import re

with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Remove ALL occurrences of the heatmap block wherever they ended up
hm = re.compile(r'\n?\s*\{%-?\s*if host_stats\s*-?%\}.*?\{%-?\s*endif\s*-?%\}', re.DOTALL)
found = hm.findall(content)
print(f"Found {len(found)} heatmap block(s) — removing all")
content = hm.sub('', content)

# Re-insert in the correct place: just before Incident Case Files
HEATMAP = '''

  {% if host_stats %}
  <div class="section-label">Severity Heatmap &mdash; Top Hosts by Alert Volume</div>
  {% for hs in host_stats %}
  <div class="heatmap-row">
    <div class="heatmap-host">{{ hs.host }}</div>
    <div class="heatmap-bar-wrap"><div class="heatmap-bar" style="width:{{ hs.pct }}%;"></div></div>
    <div class="heatmap-count">{{ hs.count }}</div>
  </div>
  {% endfor %}
  {% endif %}'''

anchor = '\n  <div class="section-label">Incident Case Files</div>'
if anchor in content:
    content = content.replace(anchor, HEATMAP + anchor, 1)
    print("Heatmap placed correctly after MITRE matrix.")
else:
    print("ERROR: 'Incident Case Files' anchor not found.")

with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print("Done.")