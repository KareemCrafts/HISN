import re

with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

print(f"File loaded: {len(content)} chars")

# ── 1. FIX EMAIL SCAN ROUTE (add try/except so errors return JSON) ─────
old_email_route = (
    '    from src.parsers.email_parser import parse_file\n'
    '    result = parse_file(path)\n'
    '    return jsonify(result)'
)
new_email_route = (
    '    try:\n'
    '        from src.parsers.email_parser import parse_file\n'
    '        result = parse_file(path)\n'
    '        if not result:\n'
    '            return jsonify({"error": "Parser returned no result."}), 500\n'
    '        return jsonify(result)\n'
    '    except Exception as _e:\n'
    '        import traceback; traceback.print_exc()\n'
    '        return jsonify({"error": f"Parser error: {str(_e)}"}), 500'
)
if old_email_route in content:
    content = content.replace(old_email_route, new_email_route, 1)
    print("OK: email route error handling added")
else:
    print("MISS: email route - may already be patched")

# ── 2. ADD NEW CASE CARD CSS before </style> ───────────────────────────
NEW_CSS = """
  /* ═══════════════════ NEW CASE CARD GRID (override old .case) ═══════ */
  .case{
    --rail:var(--meta); --rail-soft:color-mix(in oklab,var(--meta) 22%,transparent);
    position:relative; display:grid;
    grid-template-columns:56px minmax(0,1.55fr) minmax(280px,.95fr);
    grid-template-rows:auto auto auto;
    grid-template-areas:"ledger header header" "ledger briefing evidence" "ledger footer footer";
    background:linear-gradient(180deg,rgba(9,14,19,.94) 0%,rgba(6,10,14,.94) 100%);
    border:1px solid var(--rule); border-left:none; margin:0 0 18px;
    --i:0; animation:caseIn .45s var(--ease) both;
    animation-delay:calc(var(--i,0)*.04s); clip-path:none; padding:0;
    transition:border-color .25s var(--ease); box-shadow:none;
  }
  .case[data-sev="critical"]{--rail:var(--crimson);--rail-soft:color-mix(in oklab,var(--crimson) 22%,transparent);}
  .case[data-sev="high"]{--rail:var(--amber);--rail-soft:color-mix(in oklab,var(--amber) 22%,transparent);}
  .case[data-sev="medium"]{--rail:var(--cyan);--rail-soft:color-mix(in oklab,var(--cyan) 22%,transparent);}
  .case[data-sev="low"]{--rail:var(--meta);--rail-soft:color-mix(in oklab,var(--meta) 35%,transparent);}
  .case:hover{border-color:color-mix(in oklab,var(--rail) 45%,var(--rule));transform:none;}
  .case::before,.case::after{display:none!important;}
  .case-ledger{
    grid-area:ledger; position:relative;
    background:linear-gradient(180deg,color-mix(in oklab,var(--rail) 18%,transparent),transparent 65%),linear-gradient(180deg,rgba(0,0,0,.35),rgba(0,0,0,.55));
    border-left:3px solid var(--rail); box-shadow:inset -1px 0 0 var(--rule),0 0 28px -8px var(--rail-soft);
    display:flex; flex-direction:column; align-items:center; padding:18px 0 14px; gap:14px;
  }
  .ledger-sev{writing-mode:vertical-rl;transform:rotate(180deg);font-family:'JetBrains Mono',monospace;font-weight:800;font-size:10px;letter-spacing:.6em;text-transform:uppercase;color:var(--rail);text-shadow:0 0 14px color-mix(in oklab,var(--rail) 55%,transparent);padding:6px 0;}
  .ledger-tick{width:14px;height:1px;background:var(--rule);}
  .ledger-num{font-family:'Major Mono Display',monospace;font-size:22px;color:#EAFFF2;line-height:1;text-align:center;}
  .ledger-num small{display:block;font-family:'JetBrains Mono',monospace;font-size:8px;letter-spacing:.32em;color:var(--meta);margin-top:6px;text-transform:uppercase;}
  .ledger-status{margin-top:auto;font-family:'JetBrains Mono',monospace;font-size:8px;letter-spacing:.32em;color:var(--rail);display:flex;flex-direction:column;align-items:center;gap:6px;}
  .ledger-status::before{content:'';width:6px;height:6px;border-radius:50%;background:var(--rail);box-shadow:0 0 10px var(--rail);animation:pulse 1.8s ease-in-out infinite;}
  .case-header{grid-area:header;display:flex;align-items:center;justify-content:space-between;gap:18px;flex-wrap:wrap;padding:16px 24px 14px;border-bottom:1px solid var(--rule);background:linear-gradient(180deg,rgba(255,255,255,.015),transparent);}
  .case-asset{min-width:0;}
  .case-asset .host{font-family:'Major Mono Display',monospace;font-weight:400;font-size:19px;letter-spacing:.04em;color:#EAFFF2;line-height:1.1;text-shadow:0 0 14px rgba(124,255,178,.18);word-break:break-all;}
  .case-asset .id-line{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-top:6px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--meta);letter-spacing:.06em;}
  .case-asset .id-line .ip{color:#B8CFC7;}.case-asset .id-line .sep{opacity:.35;}
  .case-meta{text-align:right;display:flex;flex-direction:column;gap:6px;align-items:flex-end;}
  .case-window{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--meta);letter-spacing:.08em;display:flex;align-items:center;gap:8px;}
  .case-window::before{content:'';width:6px;height:6px;border:1px solid var(--meta);border-radius:50%;}
  .case-briefing{grid-area:briefing;padding:22px 26px 20px;border-right:1px solid var(--rule);min-width:0;}
  .briefing-eyebrow{display:flex;align-items:center;gap:10px;font-family:'JetBrains Mono',monospace;font-size:9px;letter-spacing:.4em;text-transform:uppercase;color:var(--acid);font-weight:700;margin-bottom:14px;}
  .briefing-eyebrow::before{content:'';width:14px;height:1px;background:var(--acid);box-shadow:0 0 8px var(--acid);}
  .briefing-eyebrow .ai-chip{margin-left:auto;font-size:8px;letter-spacing:.3em;color:var(--meta);border:1px solid var(--rule);padding:2px 7px;border-radius:2px;display:inline-flex;align-items:center;gap:6px;}
  .briefing-eyebrow .ai-chip::before{content:'';width:5px;height:5px;border-radius:50%;background:var(--acid);box-shadow:0 0 6px var(--acid);}
  .briefing-body{font-family:'Space Grotesk',sans-serif;font-size:14.5px;line-height:1.72;color:#E5EFE9;letter-spacing:.005em;padding-left:14px;border-left:1px solid color-mix(in oklab,var(--acid) 35%,var(--rule));}
  .briefing-empty{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--meta);letter-spacing:.18em;text-transform:uppercase;padding:12px 0;opacity:.7;}
  .chain-block{margin-top:24px;padding-top:18px;border-top:1px dashed var(--rule);}
  .chain-label{font-family:'JetBrains Mono',monospace;font-size:9px;letter-spacing:.4em;text-transform:uppercase;color:var(--meta);margin-bottom:14px;font-weight:600;}
  .chain{display:grid;grid-auto-flow:column;grid-auto-columns:1fr;align-items:start;gap:0;position:relative;padding:8px 4px 0;border-top:none;border-bottom:none;margin:0;overflow-x:auto;}
  .chain::before{content:'';position:absolute;left:6%;right:6%;top:14px;height:1px;background:repeating-linear-gradient(90deg,var(--rule) 0 4px,transparent 4px 8px);}
  .stage{text-align:center;font-family:'JetBrains Mono',monospace;font-size:9px;letter-spacing:.18em;text-transform:uppercase;color:color-mix(in oklab,var(--meta) 80%,transparent);padding-top:24px;position:relative;transition:color .2s;border-top:none;min-width:auto;}
  .stage::before{content:'';position:absolute;top:8px;left:50%;transform:translateX(-50%);width:11px;height:11px;border-radius:50%;background:#06090C;border:1px solid var(--rule);z-index:1;}
  .stage.active{color:#EAFFF2;font-weight:700;}
  .stage.active::before{background:var(--rail);border-color:var(--rail);box-shadow:0 0 12px var(--rail),0 0 0 3px color-mix(in oklab,var(--rail) 18%,transparent);}
  .case-evidence{grid-area:evidence;padding:22px 22px 20px;background:linear-gradient(180deg,rgba(0,0,0,.18),transparent 30%);display:flex;flex-direction:column;gap:18px;min-width:0;}
  .ev-block{display:flex;flex-direction:column;gap:8px;}
  .ev-head{font-family:'JetBrains Mono',monospace;font-size:9px;letter-spacing:.36em;text-transform:uppercase;color:var(--meta);font-weight:600;display:flex;align-items:center;gap:10px;}
  .ev-head::after{content:'';flex:1;height:1px;background:var(--rule);}
  .ev-row{font-family:'JetBrains Mono',monospace;font-size:11.5px;color:#D6E8DC;line-height:1.55;word-break:break-word;}
  .ev-row .k{display:inline-block;min-width:46px;color:var(--meta);font-size:9px;letter-spacing:.22em;text-transform:uppercase;margin-right:8px;}
  .ev-rule{font-family:'Space Grotesk',sans-serif;font-size:12px;color:#CFE0D8;line-height:1.55;padding-left:10px;border-left:1px solid var(--rule);}
  .repu{display:flex;align-items:flex-start;gap:12px;padding:10px 12px;background:rgba(5,8,12,.55);border:1px solid var(--rule);border-radius:2px;}
  .repu-score{font-family:'Major Mono Display',monospace;font-size:22px;line-height:1;color:#EAFFF2;min-width:54px;}
  .repu-score small{display:block;font-family:'JetBrains Mono',monospace;font-size:8px;letter-spacing:.28em;color:var(--meta);margin-top:6px;text-transform:uppercase;}
  .repu-meta{font-family:'JetBrains Mono',monospace;font-size:11px;color:#CFE0D8;line-height:1.5;flex:1;min-width:0;}
  .repu-meta .muted{color:var(--meta);font-size:10px;}
  .repu-links{display:flex;flex-wrap:wrap;gap:10px;margin-top:6px;}
  .hash-row{display:flex;flex-direction:column;gap:3px;margin-bottom:8px;}
  .hash-row .hash-links{display:flex;flex-wrap:wrap;gap:10px;padding-left:2px;}
  .case-footer{grid-area:footer;border-top:1px solid var(--rule);background:linear-gradient(180deg,rgba(0,0,0,.25),rgba(0,0,0,.4));display:flex;flex-direction:column;}
  .case-footer-bar{display:flex;align-items:stretch;flex-wrap:wrap;}
  details.drawer{flex:1 1 auto;min-width:220px;border-right:1px solid var(--rule);background:transparent;border-top:none;padding:0;margin:0;}
  details.drawer:last-child{border-right:none;}
  details.drawer summary{cursor:pointer;list-style:none;padding:12px 22px;font-family:'JetBrains Mono',monospace;font-size:9.5px;letter-spacing:.32em;text-transform:uppercase;color:var(--meta);font-weight:600;display:flex;align-items:center;gap:12px;transition:color .15s,background .15s;}
  details.drawer summary::-webkit-details-marker{display:none;}
  details.drawer summary:hover{color:var(--acid);background:rgba(124,255,178,.03);}
  details.drawer summary::before{content:'▸';color:var(--acid);font-size:9px;transition:transform .2s;display:inline-block;}
  details.drawer[open] summary{color:var(--acid);background:linear-gradient(180deg,rgba(124,255,178,.06),transparent);border-bottom:1px solid color-mix(in oklab,var(--acid) 25%,var(--rule));}
  details.drawer[open] summary::before{transform:rotate(90deg);}
  details.drawer summary .count-chip{margin-left:auto;font-size:9px;letter-spacing:.2em;color:#EAFFF2;padding:1px 7px;border:1px solid var(--rule);border-radius:2px;background:rgba(0,0,0,.35);}
  .drawer-body{padding:16px 22px 18px;}
  @media(max-width:1080px){
    .case{grid-template-columns:48px 1fr;grid-template-areas:"ledger header" "ledger briefing" "ledger evidence" "ledger footer";}
    .case-briefing{border-right:none;border-bottom:1px solid var(--rule);}
    .case-evidence{background:transparent;}
  }
  @media(max-width:600px){
    .case{grid-template-columns:40px 1fr;}
    .case-briefing,.case-evidence,.case-header{padding-left:16px;padding-right:16px;}
    details.drawer{border-right:none;border-bottom:1px solid var(--rule);}
  }
"""

if '</style>' in content:
    content = content.replace('</style>', NEW_CSS + '\n</style>', 1)
    print("OK: new case CSS injected")

# ── 3. REPLACE OLD CASE CARD HTML with new grid design ─────────────────
NEW_CASES_HTML = """  <div id="cases">
  {% for inc in incidents %}
  <div class="case" style="--i:{{ loop.index }};" data-sev="{{ inc.max_severity }}" data-host="{{ (inc.host ~ ' ' ~ (inc.source_ip or '')) | lower }}">

    {# ── LEDGER: vertical severity rail ── #}
    <aside class="case-ledger" aria-hidden="true">
      <div class="ledger-sev">{{ inc.max_severity }}</div>
      <div class="ledger-tick"></div>
      <div class="ledger-num">{{ inc.alert_count }}<small>signals</small></div>
      <div class="ledger-status">OPEN</div>
    </aside>

    {# ── HEADER STRIP ── #}
    <div class="case-header">
      <div class="case-asset">
        <div class="host">{{ inc.host }}</div>
        <div class="id-line">
          <span class="ip">{{ inc.source_ip or 'no external IP' }}</span>
          <span class="sep">│</span>
          <span>{{ inc.alert_count }} alerts</span>
        </div>
      </div>
      <div class="case-meta">
        <span class="case-id">CASE-{{ "%03d"|format(inc.case_number) }}</span>
        <span class="case-window">{{ inc.start_time }} &rarr; {{ inc.end_time }}</span>
        <button type="button" class="pill ai-context-btn" data-context='{{ inc.context_json | tojson | e }}' data-label="CASE-{{ "%03d"|format(inc.case_number) }}" style="border-color:var(--cyan);color:var(--cyan);font-size:9px;padding:4px 10px;margin-top:4px;">Ask Hisn AI</button>
      </div>
    </div>

    {# ── BRIEFING + KILL CHAIN ── #}
    <div class="case-briefing">
      <div class="briefing-eyebrow">
        Intelligence Briefing
        <span class="ai-chip">AI-DRAFTED · VERIFY</span>
      </div>
      {% if inc.ai_summary %}
        <div class="briefing-body">{{ inc.ai_summary }}</div>
      {% else %}
        <div class="briefing-empty">// no analyst note generated for this case</div>
      {% endif %}
      <div class="chain-block">
        <div class="chain-label">Attack Progression · Kill Chain</div>
        <div class="chain">
          {% for label, active in inc.chain %}<div class="stage {{ 'active' if active else '' }}">{{ label }}</div>{% endfor %}
        </div>
      </div>
    </div>

    {# ── EVIDENCE LEDGER (right column) ── #}
    <aside class="case-evidence">
      <div class="ev-block">
        <div class="ev-head">MITRE Techniques</div>
        <div class="ev-row">{{ inc.mitre_techniques }}</div>
      </div>
      <div class="ev-block">
        <div class="ev-head">Detection Rules</div>
        <div class="ev-rule">{{ inc.rule_names }}</div>
      </div>
      {% if inc.ip_intel %}
      <div class="ev-block">
        <div class="ev-head">IP Reputation</div>
        {% if inc.ip_intel.mode == 'internal' %}
          <div class="ioc-muted">Internal address — not externally routable.</div>
        {% else %}
          {% if inc.ip_intel.mode == 'live' %}
          <div class="repu">
            <div class="repu-score" style="color:{{ '#E0483E' if inc.ip_intel.abuse_score >= 50 else ('#D9B44A' if inc.ip_intel.abuse_score >= 20 else '#7BE6FF') }};">
              {{ inc.ip_intel.abuse_score }}<small>% abuse</small>
            </div>
            <div class="repu-meta">
              {{ inc.ip_intel.country or 'Unknown' }} · {{ inc.ip_intel.isp or 'Unknown ISP' }}<br>
              <span class="muted">{{ inc.ip_intel.total_reports }} report(s)</span>
              <div class="repu-links">
                <a href="{{ inc.ip_intel.link }}" target="_blank" class="ioc-link">AbuseIPDB &rarr;</a>
                <a href="https://viz.greynoise.io/ip/{{ inc.source_ip }}" target="_blank" class="ioc-link">GreyNoise &rarr;</a>
                <a href="https://www.shodan.io/host/{{ inc.source_ip }}" target="_blank" class="ioc-link">Shodan &rarr;</a>
              </div>
            </div>
          </div>
          {% else %}
          <div class="ioc-muted">{{ inc.ip_intel.message }}</div>
          <div class="repu-links" style="margin-top:6px;">
            <a href="{{ inc.ip_intel.link }}" target="_blank" class="ioc-link">AbuseIPDB &rarr;</a>
            <a href="https://viz.greynoise.io/ip/{{ inc.source_ip }}" target="_blank" class="ioc-link">GreyNoise &rarr;</a>
          </div>
          {% endif %}
        {% endif %}
      </div>
      {% endif %}
      {% if inc.iocs and (inc.iocs.ips or inc.iocs.hashes or inc.iocs.files) %}
      <div class="ev-block">
        <div class="ev-head">Indicators of Compromise</div>
        {% if inc.iocs.ips %}
        <div class="ev-row">
          <span class="k">IPs</span>
          {% for ip in inc.iocs.ips %}
          <div style="margin:3px 0;">
            <span class="tag-ok">{{ ip }}</span>
            <a href="https://www.abuseipdb.com/check/{{ ip }}" target="_blank" class="ioc-link" style="font-size:9px;">AbuseIPDB</a>
            <a href="https://viz.greynoise.io/ip/{{ ip }}" target="_blank" class="ioc-link" style="font-size:9px;margin-left:6px;">GreyNoise</a>
          </div>
          {% endfor %}
        </div>
        {% endif %}
        {% if inc.iocs.files %}<div class="ev-row"><span class="k">Files</span>{% for f in inc.iocs.files %}<span class="tag-ok">{{ f }}</span>{% endfor %}</div>{% endif %}
        {% if inc.iocs.hashes %}
        <div style="margin-top:8px;"><span class="k" style="display:block;margin-bottom:4px;font-size:9px;letter-spacing:.22em;text-transform:uppercase;color:var(--meta);">Hashes (SHA256)</span></div>
        {% for h in inc.iocs.hashes %}
        <div class="hash-row">
          <span class="tag-ok" style="font-size:9px;">{{ h }}</span>
          <span class="hash-links">
            <a href="https://www.virustotal.com/gui/file/{{ h }}" target="_blank" class="ioc-link">VirusTotal &rarr;</a>
            <a href="https://www.hybrid-analysis.com/search?query={{ h }}" target="_blank" class="ioc-link">Hybrid &rarr;</a>
            <a href="https://bazaar.abuse.ch/browse.php?search=sha256%3A{{ h }}" target="_blank" class="ioc-link">MalwareBazaar &rarr;</a>
            <a href="https://tria.ge/s?q={{ h }}" target="_blank" class="ioc-link">Triage &rarr;</a>
          </span>
        </div>
        {% endfor %}
        {% endif %}
      </div>
      {% endif %}
    </aside>

    {# ── FOOTER: drawers for Detection Logic, Remediation, Raw Events ── #}
    <div class="case-footer">
      <div class="case-footer-bar">
        <details class="drawer">
          <summary>Detection Logic <span class="count-chip">{{ inc.rule_explanations|length }}</span></summary>
          <div class="drawer-body">
            {% for r in inc.rule_explanations %}
            <div class="rem-item">
              <span class="rem-tech">{{ r.name }}</span>
              <a href="{{ r.sigmahq_link }}" target="_blank" class="ioc-link" style="margin-left:10px;font-size:9px;">SigmaHQ &rarr;</a>
              <ul><li>{{ r.description }}</li></ul>
              {% if r.logic %}<div class="excerpt" style="margin-top:6px;font-size:10px;">{{ r.logic }}</div>{% endif %}
            </div>
            {% endfor %}
          </div>
        </details>
        <details class="drawer">
          <summary>Remediation Playbook <span class="count-chip">{{ inc.remediation|length }}</span></summary>
          <div class="drawer-body">
            {% for r in inc.remediation %}
            <div class="rem-item">
              <span class="rem-tech">{{ r.id }}</span><span class="rem-cat">{{ r.category }}</span>
              <a href="{{ r.mitre_link }}" target="_blank" class="ioc-link" style="margin-left:10px;font-size:9px;">MITRE ATT&amp;CK &rarr;</a>
              <a href="{{ r.d3fend_link }}" target="_blank" class="ioc-link" style="font-size:9px;">D3FEND &rarr;</a>
              <ul>{% for step in r.steps %}<li>{{ step }}</li>{% endfor %}</ul>
            </div>
            {% endfor %}
          </div>
        </details>
        {% if inc.raw_events and inc.raw_events.events %}
        <details class="drawer">
          <summary>Raw Events <span class="count-chip">{{ inc.raw_events.shown }}/{{ inc.raw_events.total }}</span></summary>
          <div class="drawer-body">
            {% for ev in inc.raw_events.events %}
            <div class="rem-item">
              <span class="rem-tech">{{ ev.rule }}</span>
              <span class="rem-cat" style="background:var(--cyan);color:var(--bg);">EID {{ ev.event_id }}</span>
              <div style="color:var(--meta);font-size:10px;margin-top:4px;">{{ ev.timestamp }}</div>
              <div class="excerpt">{{ ev.raw }}</div>
            </div>
            {% endfor %}
          </div>
        </details>
        {% endif %}
      </div>
    </div>

  </div>
  {% endfor %}
  </div>"""

# Find and replace the old cases section
pat = re.compile(
    r'  <div id="cases">\n  \{%-?\s*for inc in incidents\s*-?%\}.*?\{%-?\s*endfor\s*-?%\}\n  </div>',
    re.DOTALL
)
m = pat.search(content)
if m:
    content = pat.sub(NEW_CASES_HTML, content, count=1)
    print("OK: case cards replaced with new grid design")
else:
    print("ERROR: old cases block not found — check the file structure")

# ── 4. ALSO ensure context_json is set (it should be already, but just in case) ─
if 'inc.context_json' not in content:
    old_raw_ev = "            inc.raw_events = get_raw_events(alerts_by_incident.get(inc.id, []))"
    new_raw_ev = (old_raw_ev + "\n"
        "            inc.context_json = {\n"
        "                'host': inc.host, 'source_ip': inc.source_ip, 'max_severity': inc.max_severity,\n"
        "                'start_time': str(inc.start_time), 'end_time': str(inc.end_time),\n"
        "                'alert_count': inc.alert_count, 'mitre_techniques': inc.mitre_techniques,\n"
        "                'rule_names': inc.rule_names, 'ai_summary': inc.ai_summary,\n"
        "            }")
    if old_raw_ev in content:
        content = content.replace(old_raw_ev, new_raw_ev, 1)
        print("OK: context_json added")
else:
    print("OK: context_json already present")

# ── 5. FIX THREATCON to use data-sev not .stamp-critical ──────────────
content = content.replace(
    "const critCount = document.querySelectorAll('.cell.glow').length;\n"
    "    const highCount = document.querySelectorAll('.stamp-high').length;",
    "const critCount = document.querySelectorAll('.case[data-sev=\"critical\"]').length;\n"
    "    const highCount = document.querySelectorAll('.case[data-sev=\"high\"]').length;",
    1
)
content = content.replace(
    "const crits = document.querySelectorAll('.stamp-critical').length;\n"
    "    const highs = document.querySelectorAll('.stamp-high').length;",
    "const crits = document.querySelectorAll('.case[data-sev=\"critical\"]').length;\n"
    "    const highs = document.querySelectorAll('.case[data-sev=\"high\"]').length;",
    1
)
print("OK: threatcon detection updated")

with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print("\nAll done. Run .\\dashboard.bat")