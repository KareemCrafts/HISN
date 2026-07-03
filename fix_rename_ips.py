with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

renames = [
    ('<title>SOC COPILOT // BLACK SITE</title>',
     '<title>HISN // UNIFIED THREAT INVESTIGATION</title>'),
    ('<span class="folder-tab">SOC-COPILOT</span>',
     '<span class="folder-tab">HISN</span>'),
    ('<h1 data-text="SOC // COPILOT">SOC // COPILOT</h1>',
     '<h1 data-text="HISN">HISN</h1>'),
    ('DETECT &rarr; CORRELATE &rarr; TRIAGE &rarr; CONTAIN <span style="opacity:.5">// BLACK SITE TERMINAL</span>',
     'UNIFIED THREAT INVESTIGATION &amp; ANALYTICS TOOL <span style="opacity:.5">// YOUR ENTIRE INVESTIGATION, ALL IN ONE PLACE.</span>'),
    ("<span>// soc-copilot \u00b7 interactive shell \u00b7 type 'help'</span>",
     "<span>// hisn \u00b7 interactive shell \u00b7 type 'help'</span>"),
    ('<span class="ai-widget-title">AI ASSISTANT<span id="aiContextLabel" class="ai-context-label"></span></span>',
     '<span class="ai-widget-title">HISN AI<span id="aiContextLabel" class="ai-context-label"></span></span>'),
]

for old, new in renames:
    if old in content:
        content = content.replace(old, new, 1)
        print(f"OK: {old[:50]}")
    else:
        print(f"MISS: {old[:50]}")

# IP links in IOC box
old_ip = '{% if inc.iocs.ips %}<div class="kv" style="margin-top:0;"><b>IPs:</b></div>{% for ip in inc.iocs.ips %}<span class="tag-ok">{{ ip }}</span>{% endfor %}{% endif %}'
new_ip = ('{% if inc.iocs.ips %}<div class="kv" style="margin-top:0;"><b>IPs:</b></div>'
          '{% for ip in inc.iocs.ips %}'
          '<div style="margin:4px 0;">'
          '<span class="tag-ok">{{ ip }}</span> '
          '<a href="https://www.abuseipdb.com/check/{{ ip }}" target="_blank" class="ioc-link" style="font-size:10px;">AbuseIPDB &rarr;</a> '
          '<a href="https://viz.greynoise.io/ip/{{ ip }}" target="_blank" class="ioc-link" style="font-size:10px;margin-left:6px;">GreyNoise &rarr;</a> '
          '<a href="https://www.shodan.io/host/{{ ip }}" target="_blank" class="ioc-link" style="font-size:10px;margin-left:6px;">Shodan &rarr;</a>'
          '</div>{% endfor %}{% endif %}')

if old_ip in content:
    content = content.replace(old_ip, new_ip, 1)
    print("OK: IP links added")
else:
    print("MISS: IP string not found exactly")

with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print("Rename + IP links done.")