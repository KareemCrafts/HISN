import re, sys, os

# ── Read the new template the user provided ─────────────────────────
tpl_file = 'template_new.py'
if not os.path.exists(tpl_file):
    print(f"ERROR: {tpl_file} not found.")
    print("Copy your TEMPLATE__2_.py to C:\\Projects\\SOC-Copilot\\template_new.py first.")
    sys.exit(1)

with open(tpl_file, 'r', encoding='utf-8') as f:
    raw = f.read()

# Extract just the HTML string content
m = re.search(r'TEMPLATE\s*=\s*"""(.*?)"""', raw, re.DOTALL)
if not m:
    print("ERROR: could not find TEMPLATE = \"\"\"...\"\"\" in template_new.py")
    sys.exit(1)
html = m.group(1)
print(f"Read template: {len(html)} chars")

# ── 1. RENAME ─────────────────────────────────────────────────────────
html = html.replace('<title>SOC COPILOT // BLACK SITE</title>', '<title>HISN // UNIFIED THREAT INVESTIGATION</title>')
html = html.replace('data-text="SOC // COPILOT">SOC // COPILOT</h1>', 'data-text="HISN">HISN</h1>')
html = html.replace('DETECT &rarr; CORRELATE &rarr; TRIAGE &rarr; CONTAIN <span style="opacity:.5">// BLACK SITE TERMINAL</span>',
    'UNIFIED THREAT INVESTIGATION &amp; ANALYTICS TOOL <span style="opacity:.5">// YOUR ENTIRE INVESTIGATION, ALL IN ONE PLACE.</span>')
html = html.replace("// soc-copilot \u00b7 interactive shell", "// hisn \u00b7 interactive shell")
print("OK: renamed to HISN")

# ── 2. ADD MISSING CSS ────────────────────────────────────────────────
MISSING_CSS = """
  /* ── MISSING UTILITIES (added by rebuild) ─────────────────── */
  .tag-ok{display:inline-block;background:rgba(123,230,255,.08);color:var(--cyan);border:1px solid rgba(123,230,255,.25);padding:3px 10px;margin:3px 4px 0 0;font-size:11px;transition:all .15s;}
  .tag-ok:hover{background:rgba(123,230,255,.18);transform:translateY(-1px);}
  .tag-flag{display:inline-block;background:rgba(255,59,92,.1);color:var(--crimson);border:1px solid rgba(255,59,92,.4);padding:3px 10px;margin:3px 4px 0 0;font-size:11px;}
  .ioc-box{background:rgba(5,8,12,.7);border:1px solid var(--rule);border-left:3px solid var(--cyan);padding:12px 16px;margin-bottom:12px;font-size:12px;}
  .ioc-label{font-size:9px;letter-spacing:.3em;color:var(--cyan);text-transform:uppercase;display:block;margin-bottom:8px;}
  .ioc-muted{color:var(--meta);font-style:italic;font-size:11px;}
  .ioc-score{font-weight:700;font-size:13px;}
  .ioc-meta{color:var(--meta);margin-left:10px;font-size:11px;}
  .ioc-link{display:inline-block;margin-top:6px;color:var(--acid);font-size:11px;text-decoration:none;letter-spacing:.05em;position:relative;transition:color .15s;}
  .ioc-link::after{content:'';position:absolute;left:0;bottom:-2px;width:0;height:1px;background:var(--acid);transition:width .25s;}
  .ioc-link:hover{color:#EAFFF2;}
  .ioc-link:hover::after{width:100%;}
  .section-label{font-size:10px;letter-spacing:.32em;color:var(--meta);text-transform:uppercase;margin:24px 0 12px;padding:8px 0 8px 14px;position:relative;border-left:2px solid var(--acid);border-bottom:1px dashed var(--rule);display:flex;align-items:center;gap:10px;}
  .section-label::before{content:'◢';color:var(--acid);}
  .section-label::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--rule),transparent);}
  /* heatmap */
  .heatmap-row{display:flex;align-items:center;gap:14px;margin-bottom:10px;}
  .heatmap-host{width:170px;flex:0 0 170px;font-size:11px;color:var(--ink);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
  .heatmap-bar-wrap{flex:1;background:rgba(7,12,16,.6);border:1px solid var(--rule);height:18px;}
  .heatmap-bar{height:100%;background:linear-gradient(90deg,var(--acid-2),var(--acid));box-shadow:0 0 10px rgba(124,255,178,.4);transition:width .6s var(--ease);}
  .heatmap-count{width:60px;flex:0 0 60px;text-align:right;font-size:11px;color:var(--acid);font-weight:700;}
  /* AI widget */
  .ai-callout{position:fixed;right:90px;bottom:28px;z-index:92;display:flex;align-items:center;gap:10px;animation:calloutPulse 2s ease-in-out infinite;pointer-events:auto;}
  .ai-callout-inner{background:rgba(7,12,16,.95);border:1px solid var(--acid);padding:10px 14px;font-size:11px;letter-spacing:.1em;color:var(--acid);white-space:nowrap;box-shadow:0 0 20px rgba(124,255,178,.3);cursor:pointer;}
  .ai-callout-inner span{display:block;font-size:9px;color:var(--meta);margin-top:3px;letter-spacing:.05em;}
  .ai-callout-arrow{color:var(--acid);font-size:20px;animation:arrowBounce .8s ease-in-out infinite;}
  @keyframes calloutPulse{0%,100%{opacity:1}50%{opacity:.75}}
  @keyframes arrowBounce{0%,100%{transform:translateX(0)}50%{transform:translateX(6px)}}
  .ai-callout.hidden{display:none!important;}
  .ai-widget-toggle{width:54px;height:54px;border-radius:50%;background:var(--acid);color:#03130C;border:none;cursor:pointer;box-shadow:0 0 20px rgba(124,255,178,.5);font-size:14px;position:fixed;right:24px;bottom:24px;z-index:91;display:flex;align-items:center;justify-content:center;font-family:'JetBrains Mono',monospace;font-weight:700;}
  .ai-widget.expanded .ai-widget-toggle{display:none;}
  .ai-widget-panel{display:none;position:fixed;right:24px;bottom:90px;width:360px;height:500px;background:rgba(7,12,16,.97);border:1px solid var(--acid);box-shadow:0 10px 50px rgba(0,0,0,.6);backdrop-filter:blur(10px);flex-direction:column;z-index:90;min-width:300px;min-height:360px;}
  .ai-widget.expanded .ai-widget-panel{display:flex;}
  .ai-widget-header{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-bottom:1px solid var(--rule);cursor:move;flex:0 0 auto;user-select:none;}
  .ai-widget-title{font-size:10px;letter-spacing:.25em;color:var(--acid);text-transform:uppercase;}
  .ai-context-label{color:var(--cyan);margin-left:4px;font-size:9px;}
  .ai-context-banner{font-size:10px;padding:8px 14px;border-bottom:1px solid var(--rule);color:var(--amber);background:rgba(255,179,71,.06);flex:0 0 auto;}
  .ai-context-banner.has-context{color:var(--acid);background:rgba(124,255,178,.06);}
  .ai-widget-actions button{background:transparent;border:1px solid var(--rule);color:var(--meta);font-family:inherit;font-size:9px;padding:3px 8px;cursor:pointer;margin-left:6px;}
  .ai-widget-actions button:hover{color:var(--ink);border-color:var(--ink);}
  .ai-messages{flex:1;overflow-y:auto;padding:14px;font-size:12px;line-height:1.6;}
  .ai-msg{margin-bottom:14px;}
  .ai-msg.user{text-align:right;}
  .ai-msg.user .ai-bubble{background:rgba(123,230,255,.1);border:1px solid rgba(123,230,255,.25);display:inline-block;padding:8px 12px;border-radius:2px;text-align:left;max-width:90%;}
  .ai-msg.assistant .ai-bubble{background:rgba(124,255,178,.06);border:1px solid var(--rule);padding:10px 14px;border-radius:2px;}
  .ai-msg-label{font-size:9px;letter-spacing:.2em;color:var(--meta);text-transform:uppercase;margin-bottom:4px;display:block;}
  .ai-copy-btn{font-size:9px;color:var(--meta);background:none;border:1px solid var(--rule);padding:2px 6px;cursor:pointer;margin-top:6px;}
  .ai-copy-btn:hover{color:var(--acid);border-color:var(--acid);}
  .ai-typing{display:inline-flex;gap:4px;padding:4px 0;}
  .ai-typing span{width:6px;height:6px;border-radius:50%;background:var(--acid);animation:aiTypingBounce 1s infinite;}
  .ai-typing span:nth-child(2){animation-delay:.15s;}.ai-typing span:nth-child(3){animation-delay:.3s;}
  @keyframes aiTypingBounce{0%,80%,100%{transform:translateY(0);opacity:.4}40%{transform:translateY(-4px);opacity:1}}
  .ai-chips{display:flex;gap:6px;flex-wrap:wrap;padding:0 14px 10px;flex:0 0 auto;max-height:80px;overflow-y:auto;}
  .ai-chips button{font-size:9px;letter-spacing:.05em;background:transparent;border:1px solid var(--rule);color:var(--meta);padding:5px 10px;cursor:pointer;}
  .ai-chips button:hover{color:var(--acid);border-color:var(--acid);}
  .ai-input-row{display:flex;gap:8px;padding:12px 14px;border-top:1px solid var(--rule);flex:0 0 auto;}
  .ai-input-row input{flex:1;background:rgba(5,8,12,.85);border:1px solid var(--rule);color:var(--ink);padding:8px;font-family:inherit;font-size:12px;}
  .ai-input-row button{background:var(--acid);color:#03130C;border:none;padding:8px 14px;font-family:inherit;font-size:11px;font-weight:700;cursor:pointer;}
  .ai-resize-handle{position:absolute;top:0;left:0;width:14px;height:14px;cursor:nwse-resize;}
  pre.ai-code{background:#03060A;border:1px solid var(--rule);padding:10px;overflow-x:auto;font-size:11px;margin:8px 0;white-space:pre;}
  .ai-context-btn{margin:6px 0 10px;}
  /* settings panel */
  #settingsPanel .panel-close{position:absolute;top:14px;right:16px;background:transparent;border:1px solid var(--rule);color:var(--meta);font-family:inherit;font-size:11px;padding:2px 8px;cursor:pointer;}
  #settingsPanel .panel-close:hover{color:var(--crimson);border-color:var(--crimson);}
"""

html = html.replace('</style>', MISSING_CSS + '\n</style>', 1)
print("OK: missing CSS injected")

# ── 3. ADD SETTINGS BUTTON TO HUD ────────────────────────────────────
old_hud_end = (
    "    <div style=\"margin-top:6px; font-size:9px; opacity:.6;\">press "
    "<kbd style=\"border:1px solid var(--rule); padding:1px 5px;\">~</kbd> for shell</div>\n"
    "  </div>\n"
    "</header>"
)
new_hud_end = (
    "    <div style=\"margin-top:6px; font-size:9px; opacity:.6;\">press "
    "<kbd style=\"border:1px solid var(--rule); padding:1px 5px;\">~</kbd> for shell</div>\n"
    "    <button id=\"settingsBtn\" type=\"button\" style=\"margin-top:8px;background:transparent;"
    "border:1px solid var(--rule);color:var(--meta);font-family:inherit;font-size:9px;"
    "letter-spacing:.15em;text-transform:uppercase;padding:4px 10px;cursor:pointer;\">&#9881; API Keys (optional)</button>\n"
    "  </div>\n"
    "</header>"
)
if old_hud_end in html:
    html = html.replace(old_hud_end, new_hud_end, 1)
    print("OK: settings button added to HUD")
else:
    print("MISS: HUD end pattern not found")

# ── 4. ADD PHISHING TAB BUTTON ────────────────────────────────────────
old_tab = '<button class="tab-btn" data-tab="tab-docs">Document &amp; File Triage</button>'
new_tab = (old_tab +
    '\n    <button class="tab-btn" data-tab="tab-phishing">Email &amp; Phishing</button>')
if old_tab in html:
    html = html.replace(old_tab, new_tab, 1)
    print("OK: phishing tab button added")

# ── 5. ADD HEATMAP + AI CONTEXT BUTTON TO CASE CARDS ──────────────────
# Add heatmap before case files section
old_case_section = '<div class="section-label">Incident Case Files</div>'
new_case_section = (
    "\n  {% if host_stats %}\n"
    "  <div class=\"section-label\">Severity Heatmap &mdash; Top Hosts by Alert Volume</div>\n"
    "  {% for hs in host_stats %}\n"
    "  <div class=\"heatmap-row\">\n"
    "    <div class=\"heatmap-host\">{{ hs.host }}</div>\n"
    "    <div class=\"heatmap-bar-wrap\"><div class=\"heatmap-bar\" style=\"width:{{ hs.pct }}%;\"></div></div>\n"
    "    <div class=\"heatmap-count\">{{ hs.count }}</div>\n"
    "  </div>\n"
    "  {% endfor %}\n"
    "  {% endif %}\n\n"
    "  <div class=\"section-label\">Incident Case Files</div>"
)
if old_case_section in html:
    html = html.replace(old_case_section, new_case_section, 1)
    print("OK: heatmap added")

# Add data-context and AI button to case cards
old_case_div = ('<div class="case" style="--i:{{ loop.index }};" '
    'data-sev="{{ inc.max_severity }}" '
    'data-host="{{ (inc.host ~ \' \' ~ (inc.source_ip or \'\')) | lower }}">')
new_case_div = ('<div class="case" style="--i:{{ loop.index }};" '
    'data-sev="{{ inc.max_severity }}" '
    'data-host="{{ (inc.host ~ \' \' ~ (inc.source_ip or \'\')) | lower }}" '
    'data-context=\'{{ inc.context_json | tojson | e }}\'>')
if old_case_div in html:
    html = html.replace(old_case_div, new_case_div, 1)
    print("OK: data-context added to case divs")
else:
    print("MISS: case div pattern - trying simpler replace")
    html = html.replace(
        'data-host="{{ (inc.host ~ \' \' ~ (inc.source_ip or \'\')) | lower }}">',
        'data-host="{{ (inc.host ~ \' \' ~ (inc.source_ip or \'\')) | lower }}" data-context=\'{{ inc.context_json | tojson | e }}\'>',
        1
    )

# Add AI button to case-header
old_case_header_end = '</div>\n    </div>\n\n    {# ── BRIEFING'
new_case_header_end = ('</div>\n      <button type="button" class="pill ai-context-btn" '
    'data-label="CASE-{{ \"%03d\"|format(inc.case_number) }}" '
    'style="border-color:var(--cyan);color:var(--cyan);font-size:9px;padding:4px 10px;cursor:pointer;">'
    'Ask Hisn AI</button>\n    </div>\n\n    {# ── BRIEFING')
if '    </div>\n\n    {# ── BRIEFING' in html:
    html = html.replace('    </div>\n\n    {# ── BRIEFING', 
        '      <button type="button" class="pill ai-context-btn" '
        'data-label="CASE-{{ \'%03d\'|format(inc.case_number) }}" '
        'style="border-color:var(--cyan);color:var(--cyan);font-size:9px;padding:4px 10px;cursor:pointer;">'
        'Ask Hisn AI</button>\n    </div>\n\n    {# ── BRIEFING', 1)
    print("OK: AI button added to case cards")

# ── 6. ADD AI CALLOUT, AI WIDGET, SETTINGS PANEL HTML ─────────────────
INJECT_BEFORE_MAIN = """
<div id="aiCallout" class="ai-callout">
  <div class="ai-callout-inner" style="cursor:pointer;" id="aiCalloutOpenBtn">HISN AI<span>Click for AI investigation support</span></div>
  <div class="ai-callout-arrow">&#9658;</div>
  <button id="aiCalloutClose" type="button" style="position:absolute;top:-8px;right:-8px;background:var(--crimson);border:none;color:#fff;width:18px;height:18px;border-radius:50%;font-size:11px;cursor:pointer;line-height:1;padding:0;">&times;</button>
</div>

<div id="aiWidget" class="ai-widget">
  <button id="aiWidgetToggle" class="ai-widget-toggle" type="button" title="Hisn AI">AI</button>
  <div id="aiWidgetPanel" class="ai-widget-panel">
    <div id="aiResizeHandle" class="ai-resize-handle"></div>
    <div id="aiWidgetHeader" class="ai-widget-header">
      <span class="ai-widget-title">HISN AI<span id="aiContextLabel" class="ai-context-label"></span></span>
      <div class="ai-widget-actions">
        <button id="aiClearBtn" type="button">CLEAR</button>
        <button id="aiMinimizeBtn" type="button">_</button>
      </div>
    </div>
    <div id="aiContextBanner" class="ai-context-banner">No case selected — click "Ask Hisn AI" on a case, or ask a general question.</div>
    <div id="aiMessages" class="ai-messages"></div>
    <div id="aiChips" class="ai-chips"></div>
    <div class="ai-input-row">
      <input id="aiInput" type="text" placeholder="Ask Hisn AI...">
      <button id="aiSendBtn" type="button">Send</button>
    </div>
  </div>
</div>

<div id="settingsPanel" class="card" style="position:fixed;top:90px;right:28px;width:320px;z-index:70;display:none;">
  <button class="panel-close" type="button" id="settingsCloseBtn">&times; close</button>
  <div class="section-label" style="margin-top:0;">API Keys &mdash; Optional, Stored Locally</div>
  <div class="ioc-muted" style="margin-bottom:12px;">Everything works without keys &mdash; you'll just get a clickthrough link. Keys stay on this machine only.</div>
  <div class="kv">AbuseIPDB Key</div>
  <input id="keyAbuseIPDB" type="text" style="width:100%;background:rgba(5,8,12,.85);border:1px solid var(--rule);color:var(--acid);padding:8px;font-family:inherit;font-size:12px;margin-bottom:10px;" placeholder="optional">
  <div class="kv">VirusTotal Key</div>
  <input id="keyVirusTotal" type="text" style="width:100%;background:rgba(5,8,12,.85);border:1px solid var(--rule);color:var(--acid);padding:8px;font-family:inherit;font-size:12px;margin-bottom:14px;" placeholder="optional">
  <button id="settingsSaveBtn" class="browse-btn" type="button" style="width:100%;">Save</button>
  <div id="settingsMsg" class="ioc-muted" style="margin-top:10px;"></div>
</div>

"""

PHISHING_PANEL = """
  <div id="tab-phishing" class="tab-panel">
    <div class="subline" style="margin:0 0 18px;"><span class="ai-dot" style="background:var(--amber);box-shadow:0 0 10px var(--amber);"></span>EMAIL &amp; PHISHING INVESTIGATION &mdash; .EML &middot; .MSG &middot; SCREENSHOTS</div>
    <div class="dropzone simple" id="phishingDropzone" style="text-align:center;">
      <svg class="upload-icon" width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
      <p style="color:var(--meta);margin-top:8px;">Drop an .eml, .msg, or screenshot to begin investigation</p>
      <button class="browse-btn" type="button" id="phishingBrowseBtn">Choose Email or Screenshot</button>
      <input type="file" id="phishingFileInput" accept=".eml,.msg,.png,.jpg,.jpeg,.webp,.bmp,.gif,.tiff" style="display:none;">
    </div>
    <div class="error-text" id="phishingError"></div>
    <div id="phishingResults"></div>
  </div>

"""

if '<main>' in html:
    html = html.replace('<main>', INJECT_BEFORE_MAIN + '<main>', 1)
    print("OK: AI widget + settings panel HTML injected")

if '</main>' in html:
    html = html.replace('</main>', PHISHING_PANEL + '</main>', 1)
    print("OK: phishing panel HTML injected")

# ── 7. ADD FULL JS BEFORE CLOSING </script> ───────────────────────────
EXTRA_JS = r"""
  window.AI_GLOBAL_CONTEXT = {{ global_context_str | tojson }};

  // ── NULL-SAFE TAB SWITCH ─────────────────────────────────────────
  (function fixTabs(){
    var tbns = document.querySelectorAll('.tab-btn');
    var tpns = document.querySelectorAll('.tab-panel');
    tbns.forEach(function(btn){
      btn.addEventListener('click', function(){
        tbns.forEach(function(b){ b.classList.remove('active'); });
        btn.classList.add('active');
        tpns.forEach(function(p){ p.classList.remove('active'); });
        var tp = document.getElementById(btn.dataset.tab);
        if (tp) tp.classList.add('active');
      });
    });
  })();

  // ── SETTINGS PANEL ───────────────────────────────────────────────
  (function settingsPanel(){
    var btn = document.getElementById('settingsBtn');
    var panel = document.getElementById('settingsPanel');
    var closeBtn = document.getElementById('settingsCloseBtn');
    var abuseInput = document.getElementById('keyAbuseIPDB');
    var vtInput = document.getElementById('keyVirusTotal');
    var saveBtn = document.getElementById('settingsSaveBtn');
    var msg = document.getElementById('settingsMsg');
    if (!btn) return;
    function openPanel(){ panel.style.display='block'; fetch('/api/settings').then(function(r){ return r.json(); }).then(function(d){ abuseInput.value=d.abuseipdb||''; vtInput.value=d.virustotal||''; }); }
    function closePanel(){ panel.style.display='none'; }
    btn.addEventListener('click', function(e){ e.stopPropagation(); if(panel.style.display==='block') closePanel(); else openPanel(); });
    closeBtn.addEventListener('click', closePanel);
    document.addEventListener('click', function(e){ if(panel.style.display==='block' && !panel.contains(e.target) && e.target!==btn) closePanel(); });
    saveBtn.addEventListener('click', function(e){
      e.stopPropagation();
      fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({abuseipdb:abuseInput.value.trim(),virustotal:vtInput.value.trim()})})
        .then(function(r){ return r.json(); })
        .then(function(){ msg.textContent='Saved. Next analysis uses these automatically.'; toast('API keys saved locally'); });
    });
  })();

  // ── HISN AI WIDGET ────────────────────────────────────────────────
  (function aiWidget(){
    var widget=document.getElementById('aiWidget');
    var toggleBtn=document.getElementById('aiWidgetToggle');
    var panel=document.getElementById('aiWidgetPanel');
    var header=document.getElementById('aiWidgetHeader');
    var minimizeBtn=document.getElementById('aiMinimizeBtn');
    var clearBtn2=document.getElementById('aiClearBtn');
    var messagesEl=document.getElementById('aiMessages');
    var chipsEl=document.getElementById('aiChips');
    var aiInput=document.getElementById('aiInput');
    var sendBtn=document.getElementById('aiSendBtn');
    var resizeHandle=document.getElementById('aiResizeHandle');
    var contextLabel=document.getElementById('aiContextLabel');
    var contextBanner=document.getElementById('aiContextBanner');

    var state={};
    try{state=JSON.parse(sessionStorage.getItem('aiWidgetState')||'{}');}catch(e){state={};}
    state.messages=state.messages||[];
    state.context=state.context||{type:'none',data:null,label:''};
    state.expanded=state.expanded||false;
    state.pos=state.pos||null;

    function saveState(){sessionStorage.setItem('aiWidgetState',JSON.stringify(state));}

    var PRESETS=[
      {key:'summarize',label:'Summarize Investigation',contexts:['incident','document','email']},
      {key:'explain_alert',label:'Explain This Alert',contexts:['incident']},
      {key:'false_positive',label:'False Positive?',contexts:['incident','document']},
      {key:'next_steps',label:'Next Investigation Steps',contexts:['incident','document','email']},
      {key:'containment',label:'Containment Steps',contexts:['incident']},
      {key:'exec_summary',label:'Executive Summary',contexts:['incident','document','email']},
      {key:'analyst_report',label:'Full Analyst Report',contexts:['incident']},
      {key:'kql',label:'Generate KQL',contexts:['incident']},
      {key:'splunk',label:'Generate SPL',contexts:['incident']},
      {key:'sigma',label:'Generate Sigma Rule',contexts:['incident']},
      {key:'junior',label:'Explain to Junior Analyst',contexts:['incident','document']},
    ];

    function escHtml(s){ if(s==null)return''; return String(s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];}); }

    function renderChips(){
      var applicable=PRESETS.filter(function(p){ return p.contexts.includes(state.context.type); });
      chipsEl.innerHTML='';
      if(!applicable.length){ chipsEl.innerHTML='<span style="font-size:10px;color:var(--meta);padding:4px;">Select a case for suggestions, or ask below.</span>'; return; }
      applicable.forEach(function(p){
        var b=document.createElement('button'); b.type='button'; b.textContent=p.label; b.dataset.preset=p.key;
        b.addEventListener('click',function(){ sendMsg('',p.key); });
        chipsEl.appendChild(b);
      });
    }

    function renderCode(text){
      var parts=String(text).split('```'); var h='';
      parts.forEach(function(part,i){
        if(i%2===1){ var nl=part.indexOf('\n'); var body=nl>=0?part.slice(nl+1):part; h+='<pre class="ai-code"><code>'+escHtml(body)+'</code></pre>'; }
        else{ h+=escHtml(part).replace(/\n/g,'<br>'); }
      });
      return h;
    }

    function renderMessages(){
      messagesEl.innerHTML='';
      state.messages.forEach(function(m){
        var div=document.createElement('div'); div.className='ai-msg '+m.role;
        var label=m.role==='user'?'YOU':'HISN AI';
        div.innerHTML='<span class="ai-msg-label">'+label+'</span><div class="ai-bubble">'+renderCode(m.text)+'</div>';
        if(m.role==='assistant'){ var cp=document.createElement('button'); cp.className='ai-copy-btn'; cp.type='button'; cp.textContent='Copy'; cp.addEventListener('click',function(){ navigator.clipboard.writeText(m.text); }); div.appendChild(cp); }
        messagesEl.appendChild(div);
      });
      messagesEl.scrollTop=messagesEl.scrollHeight;
    }

    function updateBanner(){
      if(!contextBanner)return;
      if(state.context.type==='none'){ contextBanner.textContent='No case selected — click "Ask Hisn AI" on a case, or ask a general question.'; contextBanner.classList.remove('has-context'); }
      else{ var kind=state.context.type==='incident'?'Case':state.context.type==='email'?'Email':'Document'; contextBanner.textContent='Referencing: '+kind+' — '+(state.context.label||'unnamed'); contextBanner.classList.add('has-context'); }
    }

    function setContext(type,data,label){
      state.context={type:type,data:data,label:label};
      if(contextLabel) contextLabel.textContent=label?(' \u00b7 '+label):'';
      updateBanner(); renderChips(); saveState();
    }
    window.aiSetContext=setContext;

    function sendMsg(question,preset){
      var displayText=question;
      if(preset){ var pr=PRESETS.find(function(x){return x.key===preset;}); displayText=pr?pr.label:preset; }
      if(!displayText)return;
      state.messages.push({role:'user',text:displayText});
      renderMessages();
      var typingDiv=document.createElement('div'); typingDiv.className='ai-msg assistant';
      typingDiv.innerHTML='<span class="ai-msg-label">HISN AI</span><div class="ai-bubble"><div class="ai-typing"><span></span><span></span><span></span></div></div>';
      messagesEl.appendChild(typingDiv); messagesEl.scrollTop=messagesEl.scrollHeight;
      fetch('/ai-chat',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({context_type:state.context.type,context:state.context.data,question:question,preset:preset,global_context:window.AI_GLOBAL_CONTEXT||''})
      }).then(function(r){return r.json();}).then(function(d){
        typingDiv.remove();
        var answer=d.error?('Error: '+d.error):d.answer;
        state.messages.push({role:'assistant',text:answer});
        renderMessages(); saveState();
      }).catch(function(){
        typingDiv.remove();
        state.messages.push({role:'assistant',text:'Request failed. Check Ollama is running.'});
        renderMessages(); saveState();
      });
    }

    sendBtn.addEventListener('click',function(){ var q=aiInput.value.trim(); if(q){sendMsg(q,null);aiInput.value='';} });
    aiInput.addEventListener('keydown',function(e){if(e.key==='Enter')sendBtn.click();});
    clearBtn2.addEventListener('click',function(){state.messages=[];renderMessages();saveState();});

    function applyPos(){ if(state.pos){panel.style.left=state.pos.left+'px';panel.style.top=state.pos.top+'px';panel.style.right='auto';panel.style.bottom='auto';panel.style.width=state.pos.width+'px';panel.style.height=state.pos.height+'px';} }
    function ensurePos(){ if(!state.pos){var r=panel.getBoundingClientRect();state.pos={left:r.left,top:r.top,width:r.width,height:r.height};applyPos();saveState();} }
    function expand(){ widget.classList.add('expanded');state.expanded=true;applyPos();requestAnimationFrame(ensurePos);saveState(); }
    function collapse(){ widget.classList.remove('expanded');state.expanded=false;saveState(); }

    if(toggleBtn) toggleBtn.addEventListener('click',expand);
    if(minimizeBtn) minimizeBtn.addEventListener('click',collapse);

    var dragging=false,dragOffX=0,dragOffY=0;
    header.addEventListener('mousedown',function(e){ if(e.target.closest('button'))return; ensurePos(); dragging=true; var r=panel.getBoundingClientRect(); dragOffX=e.clientX-r.left; dragOffY=e.clientY-r.top; e.preventDefault(); });
    var resizing=false,rsX,rsY,rsW,rsH,rsL,rsT;
    if(resizeHandle) resizeHandle.addEventListener('mousedown',function(e){ ensurePos(); resizing=true; rsX=e.clientX;rsY=e.clientY;rsW=state.pos.width;rsH=state.pos.height;rsL=state.pos.left;rsT=state.pos.top; e.preventDefault();e.stopPropagation(); });
    document.addEventListener('mousemove',function(e){
      if(dragging){state.pos.left=e.clientX-dragOffX;state.pos.top=e.clientY-dragOffY;panel.style.left=state.pos.left+'px';panel.style.top=state.pos.top+'px';}
      if(resizing){var dx=rsX-e.clientX,dy=rsY-e.clientY;state.pos.width=Math.max(300,rsW+dx);state.pos.height=Math.max(320,rsH+dy);state.pos.left=rsL-dx;state.pos.top=rsT-dy;panel.style.width=state.pos.width+'px';panel.style.height=state.pos.height+'px';panel.style.left=state.pos.left+'px';panel.style.top=state.pos.top+'px';}
    });
    document.addEventListener('mouseup',function(){if(dragging){dragging=false;saveState();}if(resizing){resizing=false;saveState();}});

    if(state.expanded){widget.classList.add('expanded');applyPos();}
    if(contextLabel) contextLabel.textContent=state.context.label?(' \u00b7 '+state.context.label):'';
    updateBanner(); renderChips(); renderMessages();

    document.querySelectorAll('.ai-context-btn').forEach(function(btn2){
      btn2.addEventListener('click',function(){
        var cdata={};
        try{cdata=JSON.parse(btn2.dataset.context||'{}');}catch(e){}
        setContext('incident',cdata,btn2.dataset.label);
        if(!state.expanded&&toggleBtn)toggleBtn.click();
      });
    });
  })();

  // ── CALLOUT ─────────────────────────────────────────────────────────
  (function callout(){
    var calloutEl=document.getElementById('aiCallout');
    var toggleBtn=document.getElementById('aiWidgetToggle');
    function hideCallout(){ if(calloutEl){calloutEl.classList.add('hidden');sessionStorage.setItem('aiCalloutSeen','1');} }
    if(calloutEl && sessionStorage.getItem('aiCalloutSeen')) calloutEl.classList.add('hidden');
    var xBtn=document.getElementById('aiCalloutClose');
    var openBtn=document.getElementById('aiCalloutOpenBtn');
    if(xBtn) xBtn.addEventListener('click',function(e){ e.stopPropagation(); hideCallout(); });
    if(openBtn) openBtn.addEventListener('click',function(){ if(toggleBtn)toggleBtn.click(); });
  })();

  // ── PHISHING TAB ──────────────────────────────────────────────────
  var lastEmailResult=null;
  (function phishingTab(){
    var pdz=document.getElementById('phishingDropzone');
    var pbb=document.getElementById('phishingBrowseBtn');
    var pfi=document.getElementById('phishingFileInput');
    var per=document.getElementById('phishingError');
    var prs=document.getElementById('phishingResults');
    if(!pdz)return;
    pbb.addEventListener('click',function(){pfi.click();});
    pdz.addEventListener('dragover',function(e){e.preventDefault();pdz.style.borderColor='var(--amber)';});
    pdz.addEventListener('dragleave',function(){pdz.style.borderColor='';});
    pdz.addEventListener('drop',function(e){e.preventDefault();pdz.style.borderColor='';if(e.dataTransfer.files.length)phishScan(e.dataTransfer.files[0]);});
    pfi.addEventListener('change',function(){if(pfi.files.length)phishScan(pfi.files[0]);});
    function phishScan(file){
      var ext=file.name.split('.').pop().toLowerCase();
      var ok=['eml','msg','png','jpg','jpeg','webp','bmp','gif','tiff','tif'];
      if(!ok.includes(ext)){per.textContent='Choose a .eml, .msg, or image file.';return;}
      per.textContent=''; prs.innerHTML='<div class="empty"><span class="spinner" style="display:inline-block;margin-right:8px;"></span>Analyzing...</div>';
      var pfd=new FormData();pfd.append('file',file);
      fetch('/scan-email',{method:'POST',body:pfd}).then(function(r){return r.json();}).then(function(data){
        if(data.error){per.textContent=data.error;prs.innerHTML='';return;}
        lastEmailResult=data;
        prs.innerHTML=renderPhishingResult(data);
        if(window.aiSetContext)window.aiSetContext('email',data,data.filename||'Email');
        var ab=document.getElementById('phishingAiBtn');
        if(ab)ab.addEventListener('click',function(){if(window.aiSetContext)window.aiSetContext('email',lastEmailResult,lastEmailResult.filename||'Email');var wt=document.getElementById('aiWidgetToggle');if(wt)wt.click();});
        var cb=document.getElementById('copyIocsBtn');
        if(cb)cb.addEventListener('click',function(){if(lastEmailResult&&lastEmailResult.iocs)navigator.clipboard.writeText(JSON.stringify(lastEmailResult.iocs,null,2));});
      }).catch(function(){per.textContent='Scan failed.';prs.innerHTML='';});
    }
  })();

  function escapeHtml(s){if(s==null)return'';return String(s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}

  function renderPhishingResult(r){
    var rc=r.risk_score>=70?'var(--crimson)':r.risk_score>=40?'var(--amber)':r.risk_score>=20?'var(--gold)':'var(--acid)';
    var h='<div style="margin-top:20px;">';
    h+='<div class="ioc-box" style="border-left-color:'+rc+';margin-bottom:16px;">';
    h+='<span class="ioc-label">Risk Assessment</span>';
    h+='<div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap;">';
    h+='<div><span style="font-size:38px;font-weight:800;color:'+rc+';">'+r.risk_score+'</span><span style="color:'+rc+';font-size:13px;">/100</span>';
    h+='<span class="rem-cat" style="background:'+rc+';margin-left:12px;">'+escapeHtml(r.risk_label||'')+'</span></div>';
    h+='<div style="flex:1;">';
    (r.risk_factors||[]).forEach(function(f){h+='<span class="tag-flag" style="margin:2px;font-size:10px;">'+escapeHtml(f)+'</span>';});
    h+='</div></div></div>';
    if(r.analysis_method) h+='<div class="ioc-muted" style="margin-bottom:10px;">'+escapeHtml(r.analysis_method)+'</div>';
    if((r.phishing_techniques||[]).length){h+='<div class="section-label">Phishing Techniques</div><div style="margin-bottom:14px;">';r.phishing_techniques.forEach(function(t){h+='<span class="tag-flag">'+escapeHtml(t)+'</span> ';});h+='</div>';}
    var m=r.metadata||{};
    h+='<details class="drawer" open><summary>Email Metadata</summary><div class="drawer-body">';
    [['From (Display)',m.from_display],['From (Email)',m.from_email],['To',m.to],['CC',m.cc],['Reply-To',m.reply_to],['Subject',m.subject],['Date',m.date],['Message-ID',m.message_id],['Mailer',m.mailer]].forEach(function(kv){if(kv[1])h+='<div class="kv"><b>'+kv[0]+'</b> <span style="color:var(--ink);">'+escapeHtml(kv[1])+'</span></div>';});
    h+='</div></details>';
    var auth=r.authentication||{},spf=auth.spf||{},dkim=auth.dkim||{},dmarc=auth.dmarc||{};
    function ab2(res){var v=(res||'none').toLowerCase();return v==='pass'?'<span class="tag-ok">PASS</span>':v==='fail'||v==='softfail'?'<span class="tag-flag">'+v.toUpperCase()+'</span>':'<span style="color:var(--meta);font-size:10px;">'+v.toUpperCase()+'</span>';}
    h+='<details class="drawer" open><summary>Authentication</summary><div class="drawer-body">';
    h+='<div class="rem-item"><span class="rem-tech">SPF</span> '+ab2(spf.result)+(spf.domain?'<span class="ioc-meta"> '+escapeHtml(spf.domain)+'</span>':'')+'<ul><li>Verifies the sending server is authorised for the domain.</li></ul></div>';
    h+='<div class="rem-item"><span class="rem-tech">DKIM</span> '+ab2(dkim.result)+(dkim.domain?'<span class="ioc-meta"> '+escapeHtml(dkim.domain)+'</span>':'')+'<ul><li>Validates message integrity via cryptographic signature.</li></ul></div>';
    h+='<div class="rem-item"><span class="rem-tech">DMARC</span> '+ab2(dmarc.result)+(dmarc.policy?'<span class="ioc-meta"> Policy: '+escapeHtml(dmarc.policy)+'</span>':'')+'<ul><li>Enforces From-domain alignment. Fail = sender identity unverified.</li></ul></div>';
    h+='</div></details>';
    var c=r.security_checks||{};
    function chk2(label,val,desc,warn){var bg=val?(warn?'<span style="color:var(--amber);border:1px solid var(--amber);padding:1px 6px;font-size:9px;">WARN</span>':'<span class="tag-flag">FAIL</span>'):'<span class="tag-ok">PASS</span>';return '<div class="rem-item"><span class="rem-tech">'+label+'</span> '+bg+'<ul><li>'+escapeHtml(desc)+'</li></ul></div>';}
    h+='<details class="drawer" open><summary>Security Checks</summary><div class="drawer-body">';
    h+=chk2('External Sender',c.external_sender,'Sender is not from an internal domain.',true);
    h+=chk2('Reply-To Mismatch',c.reply_to_mismatch,'Reply-To domain differs from From domain.',false);
    h+=chk2('Display Name Spoofing',c.display_name_spoofing,'Display name impersonates a known brand.',false);
    h+=chk2('HTML Form',c.has_html_form,'HTML form detected - possible credential harvesting.',false);
    h+=chk2('JavaScript',c.has_javascript,'Active JavaScript found in HTML body.',true);
    h+=chk2('Tracking Pixel',c.has_tracking_pixel,'Tiny image used to track email opens.',true);
    h+=chk2('Remote Images',c.has_remote_images,'External images can leak recipient IP.',true);
    h+=chk2('Malformed Message-ID',c.invalid_message_id,'Message-ID does not conform to RFC 5322.',true);
    h+='</div></details>';
    if((r.received_chain||[]).length){
      h+='<details class="drawer"><summary>Delivery Path ('+r.received_chain.length+' hops)</summary><div class="drawer-body">';
      r.received_chain.forEach(function(hop,i){
        h+='<div class="rem-item"><span class="rem-tech">Hop '+(i+1)+'</span>';
        if(hop.from)h+='<div class="kv"><b>From</b> '+escapeHtml(hop.from)+'</div>';
        if(hop.by)h+='<div class="kv"><b>By</b> '+escapeHtml(hop.by)+'</div>';
        if(hop.ip)h+='<div class="kv"><b>IP</b> <span class="tag-ok">'+escapeHtml(hop.ip)+'</span> <a href="https://www.abuseipdb.com/check/'+encodeURIComponent(hop.ip)+'" target="_blank" class="ioc-link" style="font-size:10px;">AbuseIPDB</a> <a href="https://viz.greynoise.io/ip/'+encodeURIComponent(hop.ip)+'" target="_blank" class="ioc-link" style="font-size:10px;">GreyNoise</a></div>';
        if(hop.timestamp)h+='<div class="kv"><b>Time</b> '+escapeHtml(hop.timestamp)+(hop.delay_seconds!=null?' <span class="ioc-meta">+'+hop.delay_seconds+'s</span>':'')+'</div>';
        h+='</div>';
      });
      h+='</div></details>';
    }
    // URLs - only show tool links for SUSPICIOUS ones
    if((r.urls||[]).length){
      var sus_urls=r.urls.filter(function(u){return /login|verify|account|secure|update|confirm|password|credential|signin|reset/i.test(u);});
      var clean_urls=r.urls.filter(function(u){return !/login|verify|account|secure|update|confirm|password|credential|signin|reset/i.test(u);});
      h+='<details class="drawer"><summary>URLs ('+r.urls.length+' total'+(sus_urls.length?' · '+sus_urls.length+' suspicious':'')+')</summary><div class="drawer-body">';
      if(sus_urls.length){
        h+='<div style="margin-bottom:12px;"><span style="color:var(--crimson);font-size:10px;letter-spacing:.1em;">SUSPICIOUS URLS — INVESTIGATE THESE</span></div>';
        sus_urls.forEach(function(u){
          h+='<div class="rem-item"><span class="tag-flag">SUSPICIOUS</span> <span style="font-size:10px;word-break:break-all;color:var(--crimson);">'+escapeHtml(u.length>120?u.slice(0,120)+'...':u)+'</span>';
          h+='<div style="margin-top:6px;display:flex;gap:8px;flex-wrap:wrap;">';
          h+='<a href="https://www.virustotal.com/gui/search/'+encodeURIComponent(u)+'" target="_blank" class="ioc-link" style="font-size:10px;">VirusTotal</a>';
          h+='<a href="https://urlscan.io/scan/#'+encodeURIComponent(u)+'" target="_blank" class="ioc-link" style="font-size:10px;">URLScan</a>';
          h+='<a href="https://transparencyreport.google.com/safe-browsing/search?url='+encodeURIComponent(u)+'" target="_blank" class="ioc-link" style="font-size:10px;">Google Safe Browsing</a>';
          h+='<a href="https://otx.alienvault.com/indicator/url/'+encodeURIComponent(u)+'" target="_blank" class="ioc-link" style="font-size:10px;">OTX</a>';
          h+='<a href="https://phishtool.com/" target="_blank" class="ioc-link" style="font-size:10px;">PhishTool</a>';
          h+='</div></div>';
        });
      }
      if(clean_urls.length){
        h+='<div style="margin-top:'+(sus_urls.length?'12px':'0')+';"><span style="color:var(--meta);font-size:10px;">OTHER URLS ('+clean_urls.length+') — no suspicious keywords detected</span><div style="margin-top:6px;">';
        clean_urls.forEach(function(u){h+='<div style="font-size:10px;color:var(--meta);word-break:break-all;margin-bottom:3px;">'+escapeHtml(u.length>80?u.slice(0,80)+'...':u)+'</div>';});
        h+='</div></div>';
      }
      h+='</div></details>';
    }
    if((r.attachments||[]).length){
      h+='<details class="drawer"><summary>Attachments ('+r.attachments.length+')</summary><div class="drawer-body">';
      r.attachments.forEach(function(a){
        h+='<div class="rem-item"><span class="rem-tech">'+escapeHtml(a.filename)+'</span>'+(a.is_executable||a.has_macros?' <span class="tag-flag">HIGH RISK</span>':'');
        h+='<div class="kv"><b>SHA256</b> <span style="font-size:10px;">'+escapeHtml(a.sha256||'')+'</span></div>';
        if(a.has_macros)h+='<div class="kv" style="color:var(--amber);">May contain macros</div>';
        if(a.is_executable)h+='<div class="kv" style="color:var(--crimson);">Executable file type</div>';
        h+='<div style="margin-top:6px;display:flex;gap:8px;flex-wrap:wrap;">';
        h+='<a href="https://www.virustotal.com/gui/file/'+encodeURIComponent(a.sha256||'')+'" target="_blank" class="ioc-link" style="font-size:10px;">VirusTotal</a>';
        h+='<a href="https://bazaar.abuse.ch/browse.php?search=sha256%3A'+encodeURIComponent(a.sha256||'')+'" target="_blank" class="ioc-link" style="font-size:10px;">MalwareBazaar</a>';
        h+='<a href="https://www.hybrid-analysis.com/search?query='+encodeURIComponent(a.sha256||'')+'" target="_blank" class="ioc-link" style="font-size:10px;">Hybrid Analysis</a>';
        h+='<a href="https://tria.ge/s?q='+encodeURIComponent(a.sha256||'')+'" target="_blank" class="ioc-link" style="font-size:10px;">Triage</a>';
        h+='</div></div>';
      });
      h+='</div></details>';
    }
    var iocs=r.iocs||{};
    h+='<details class="drawer"><summary>IOC Summary</summary><div class="drawer-body">';
    if((iocs.ips||[]).length){h+='<div class="rem-item"><span class="rem-tech">IPs</span><div style="margin-top:4px;">';iocs.ips.forEach(function(x){h+='<span class="tag-ok">'+escapeHtml(x)+'</span> <a href="https://www.abuseipdb.com/check/'+encodeURIComponent(x)+'" target="_blank" class="ioc-link" style="font-size:10px;">AbuseIPDB</a> ';});h+='</div></div>';}
    if((iocs.domains||[]).length){h+='<div class="rem-item"><span class="rem-tech">Domains</span><div style="margin-top:4px;">';iocs.domains.forEach(function(x){h+='<span class="tag-ok">'+escapeHtml(x)+'</span> ';});h+='</div></div>';}
    if((iocs.emails||[]).length){h+='<div class="rem-item"><span class="rem-tech">Email Addresses</span><div style="margin-top:4px;">';iocs.emails.forEach(function(x){h+='<span class="tag-ok">'+escapeHtml(x)+'</span> ';});h+='</div></div>';}
    h+='<div style="margin-top:8px;"><button type="button" class="pill" id="copyIocsBtn" style="color:var(--acid);border-color:var(--acid);">Copy All IOCs</button></div>';
    h+='</div></details>';
    if((r.mitre_techniques||[]).length){
      h+='<details class="drawer"><summary>MITRE ATT&amp;CK Mapping</summary><div class="drawer-body">';
      r.mitre_techniques.forEach(function(t){var pts=t.split('.'),base=pts[0],sub=pts[1];var url=sub?'https://attack.mitre.org/techniques/'+base+'/'+sub+'/':'https://attack.mitre.org/techniques/'+base+'/';h+='<div class="rem-item"><span class="rem-tech">'+escapeHtml(t)+'</span> <a href="'+url+'" target="_blank" class="ioc-link" style="font-size:10px;">MITRE ATT&amp;CK</a></div>';});
      h+='</div></details>';
    }
    if((r.timeline||[]).length){
      h+='<details class="drawer"><summary>Timeline</summary><div class="drawer-body">';
      r.timeline.forEach(function(ev){h+='<div class="rem-item"><span class="rem-tech">'+escapeHtml(ev.event)+'</span><div class="kv">'+escapeHtml(ev.timestamp||'')+(ev.detail?' \u2014 '+escapeHtml(ev.detail):'')+'</div></div>';});
      h+='</div></details>';
    }
    if(r.raw_headers)h+='<details class="drawer"><summary>Raw Headers</summary><div class="drawer-body"><div class="excerpt">'+escapeHtml(r.raw_headers)+'</div></div></details>';
    h+='<div style="margin-top:18px;"><button type="button" class="browse-btn" id="phishingAiBtn">Ask Hisn AI About This Email</button></div>';
    h+='</div>';
    return h;
  }

  // ── FIX DOC AI BUTTON ──────────────────────────────────────────────
  (function fixDocAi(){
    var origSubmit = docForm ? docForm.onsubmit : null;
    // Patch renderDocResult to add AI button
    var _orig = typeof renderDocResult === 'function' ? renderDocResult : null;
    // The docForm already has its submit handler from the template.
    // We patch it here to also wire the AI button after render.
    var _docForm = document.getElementById('docForm');
    if (_docForm) {
      _docForm.addEventListener('submit', function() {
        setTimeout(function() {
          var ab = document.getElementById('docAiContextBtn');
          if (ab && window.aiSetContext) {
            ab.addEventListener('click', function() {
              if (window.lastDocResult) window.aiSetContext('document', window.lastDocResult, window.lastDocResult.filename||'Document');
              var wt = document.getElementById('aiWidgetToggle'); if(wt) wt.click();
            });
          }
        }, 2000);
      });
    }
  })();
"""

# Find closing </script> and inject before it
closing_script = '</script>\n</body>'
if closing_script in html:
    html = html.replace(closing_script, EXTRA_JS + '\n</script>\n</body>', 1)
    print("OK: extra JS injected")
else:
    # Try alternate
    html = html.replace('</script>', EXTRA_JS + '\n</script>', 1)
    print("OK: extra JS injected (alt)")

# ── 8. UPDATE THREATCON TO USE DATA-SEV ───────────────────────────────
old_threatcon = (
    "    const critCount = document.querySelectorAll('.cell.glow').length;\n"
    "    const highCount = document.querySelectorAll('.stamp-high').length;"
)
new_threatcon = (
    "    const critCount = document.querySelectorAll('.case[data-sev=\"critical\"]').length;\n"
    "    const highCount = document.querySelectorAll('.case[data-sev=\"high\"]').length;"
)
if old_threatcon in html:
    html = html.replace(old_threatcon, new_threatcon, 1)
    print("OK: threatcon detection updated")

old_load = (
    "    const crits = document.querySelectorAll('.stamp-critical').length;\n"
    "    const highs = document.querySelectorAll('.stamp-high').length;"
)
new_load = (
    "    const crits = document.querySelectorAll('.case[data-sev=\"critical\"]').length;\n"
    "    const highs = document.querySelectorAll('.case[data-sev=\"high\"]').length;"
)
if old_load in html:
    html = html.replace(old_load, new_load, 1)
    print("OK: load toast detection updated")

# ── 9. READ CURRENT app.py, REPLACE ONLY THE TEMPLATE VARIABLE ────────
with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    app_content = f.read()

# Find TEMPLATE = """ ... """ and replace it
tpl_pat = re.compile(r'\nTEMPLATE\s*=\s*""".*?"""', re.DOTALL)
new_template_block = '\nTEMPLATE = """\n' + html + '\n"""'
app_content, n = tpl_pat.subn(new_template_block, app_content, 1)
if n:
    print(f"OK: TEMPLATE replaced in app.py ({n} replacement)")
else:
    print("ERROR: TEMPLATE variable not found in app.py")
    sys.exit(1)

# Also ensure context_json is set in dashboard()
if 'inc.context_json' not in app_content:
    old_raw = "            inc.raw_events = get_raw_events(alerts_by_incident.get(inc.id, []))"
    new_raw = (old_raw + "\n"
        "            inc.context_json = {\n"
        "                'host': inc.host, 'source_ip': inc.source_ip, 'max_severity': inc.max_severity,\n"
        "                'start_time': str(inc.start_time), 'end_time': str(inc.end_time),\n"
        "                'alert_count': inc.alert_count, 'mitre_techniques': inc.mitre_techniques,\n"
        "                'rule_names': inc.rule_names, 'ai_summary': inc.ai_summary,\n"
        "            }")
    if old_raw in app_content:
        app_content = app_content.replace(old_raw, new_raw, 1)
        print("OK: context_json added to dashboard()")
else:
    print("OK: context_json already in dashboard()")

# Ensure host_stats is passed to template
if 'host_stats=host_stats' not in app_content:
    old_render = "            host_stats=host_stats,"
    if old_render not in app_content:
        app_content = app_content.replace(
            "            techniques_seen=len(tech_sev), matrix=matrix,",
            "            techniques_seen=len(tech_sev), matrix=matrix,\n            host_stats=host_stats,", 1)
        print("OK: host_stats added to render_template_string call")

# Ensure global_context_str is in render call
if 'global_context_str=global_context_str' not in app_content:
    app_content = app_content.replace(
        "            host_stats=host_stats,",
        "            host_stats=host_stats,\n            global_context_str=global_context_str,", 1)
    print("OK: global_context_str added to render call")

with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(app_content)

print("\nDone! Run .\\dashboard.bat")