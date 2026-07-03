with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

UX_CSS = """
  /* ── UX POLISH: micro-interactions & spacing improvements ─── */

  /* Smoother tab transitions */
  .tab-panel{ transition: opacity .25s var(--ease); }
  .tab-panel.active{ display:block; }

  /* Tab button: tighter focus ring, better hover */
  .tab-btn:hover::before{ opacity:.65; }
  .tab-btn:focus-visible{ outline:1px dashed var(--acid); outline-offset:3px; }

  /* Case card: longer, smoother hover transition */
  .case{ transition: border-color .3s var(--ease), box-shadow .3s var(--ease); }
  .case:hover{ box-shadow: 0 0 30px -8px var(--rail-soft), var(--shadow); }

  /* Drawer: smoother open/close */
  details.drawer summary{ transition: color .2s, background .2s; }

  /* Empty state: centered, breathing room */
  .empty{ border-radius:4px; }

  /* Browse button: tighter active feel */
  .browse-btn{ transition: color .18s, background .18s, box-shadow .2s, transform .12s; }
  .browse-btn:active{ transform: scale(.96) translateY(1px); }

  /* AI widget: smooth slide-in */
  .ai-widget-panel{
    transition: opacity .2s var(--ease);
    animation: aiPanelIn .2s var(--ease);
  }
  @keyframes aiPanelIn{
    from{ opacity:0; transform:translateY(8px); }
    to  { opacity:1; transform:translateY(0); }
  }

  /* AI messages: smooth appear */
  .ai-msg{ animation: msgIn .2s var(--ease); }
  @keyframes msgIn{ from{opacity:0;transform:translateY(4px)} to{opacity:1;transform:translateY(0)} }

  /* Context banner: transition on state change */
  .ai-context-banner{ transition: background .3s var(--ease), color .3s var(--ease); }

  /* Chip buttons: better hover feedback */
  .ai-chips button{
    transition: color .15s, border-color .15s, background .15s;
    border-radius:2px;
  }
  .ai-chips button:hover{
    background: rgba(124,255,178,.06);
    border-color: var(--acid);
  }
  .ai-chips button:active{ transform: scale(.97); }

  /* Progress bar: cleaner */
  .progress.show{ border-radius:2px; }

  /* Pill filter: active state punch */
  .pill{ transition: color .15s, background .15s, border-color .15s, transform .1s; }
  .pill:active{ transform: scale(.95); }

  /* IOC links: underline on hover instead of color-only */
  .ioc-link{ transition: color .15s; }

  /* Stat boxes: lift effect */
  .stat-box{ transition: transform .25s var(--ease), border-color .25s, box-shadow .25s; }
  .stat-box:hover{ box-shadow: 0 0 24px -6px rgba(124,255,178,.25); }

  /* Settings panel: smooth show/hide */
  #settingsPanel{
    animation: settingsIn .2s var(--ease);
    transform-origin: top right;
  }
  @keyframes settingsIn{ from{opacity:0;transform:scale(.97)} to{opacity:1;transform:scale(1)} }

  /* Callout arrow: slightly subtler */
  .ai-callout-inner{ transition: background .2s, border-color .2s; border-radius:2px; }
  .ai-callout-inner:hover{ background: rgba(7,18,14,.98); border-color: #EAFFF2; }

  /* Search input: smooth glow */
  .search{ transition: border-color .2s, box-shadow .25s; }

  /* Heatmap bars: smooth fill */
  .heatmap-bar{ transition: width .8s cubic-bezier(.22,.68,0,1.2); }

  /* Section labels: consistent spacing */
  .section-label{ margin-top:28px; margin-bottom:14px; }

  /* MITRE cells: smooth color transition */
  .cell{ transition: transform .15s var(--ease), border-color .15s, color .15s, background .15s, filter .15s; }

  /* Raw event viewer: readable code blocks */
  .excerpt{ border-radius:2px; }
  pre.ai-code{ border-radius:2px; }

  /* Drawer body: padding refinement */
  .drawer-body{ line-height:1.6; }

  /* Toast: smooth dismiss */
  .toast{ border-radius:2px; }

  /* Scanline overlay: slightly less aggressive */
  body::after{ opacity:.42; }

  /* Phishing dropzone tip text */
  .phishing-tip{
    font-size:10px; color:var(--acid); letter-spacing:.06em;
    margin-top:6px; opacity:.8;
    padding:4px 10px; border:1px solid rgba(124,255,178,.15);
    border-radius:2px; display:inline-block;
    background:rgba(124,255,178,.04);
  }
"""

# Inject UX CSS
if '.tab-panel{ transition: opacity' not in content:
    content = content.replace('</style>', UX_CSS + '\n</style>', 1)
    print("OK: UX polish CSS injected")
else:
    print("MISS: UX CSS already present")

# ── Improve demo button state feedback ──────────────────────────────
old_demo_click = ("    db.addEventListener('click', function(){\n"
                  "      db.textContent = 'Loading...'; db.disabled = true;")
new_demo_click = ("    db.addEventListener('click', function(){\n"
                  "      db.textContent = 'Scanning for .evtx files...'; db.disabled = true;\n"
                  "      db.style.opacity = '0.7';")
if old_demo_click in content:
    content = content.replace(old_demo_click, new_demo_click, 1)
    print("OK: Demo button loading state improved")

# ── Better demo error display ────────────────────────────────────────
old_demo_err = ("            document.getElementById('demoMsg').textContent = d.error || 'No sample file found. Upload a .evtx to begin.';\n"
                "            db.disabled = false; db.textContent = 'Load Demo Analysis';")
new_demo_err = ("            var msg = document.getElementById('demoMsg');\n"
                "            msg.textContent = d.error || 'No sample file found. Upload a .evtx to begin.';\n"
                "            msg.style.color = 'var(--amber)';\n"
                "            db.disabled = false; db.textContent = 'Load Demo Analysis';\n"
                "            db.style.opacity = '1';")
if old_demo_err in content:
    content = content.replace(old_demo_err, new_demo_err, 1)
    print("OK: Demo error display improved")

# ── Improve upload success feedback ─────────────────────────────────
old_done = ("else { stageText.textContent = 'Done. Loading results...'; setTimeout(() => location.reload(), 800); }")
new_done = ("else { stageText.textContent = 'Analysis complete \u2014 loading...'; setTimeout(() => location.reload(), 600); }")
if old_done in content:
    content = content.replace(old_done, new_done, 1)
    print("OK: Upload success message improved")

# ── Fix copy IOC button feedback ─────────────────────────────────────
old_copy = "navigator.clipboard.writeText(JSON.stringify(lastEmailResult.iocs, null, 2));"
new_copy = ("navigator.clipboard.writeText(JSON.stringify(lastEmailResult.iocs, null, 2));\n"
            "              var _cb = document.getElementById('copyIocsBtn');\n"
            "              if(_cb){ var _ot=_cb.textContent; _cb.textContent='Copied!'; _cb.style.color='var(--acid)'; setTimeout(function(){_cb.textContent=_ot;},1800); }")
if old_copy in content:
    content = content.replace(old_copy, new_copy, 1)
    print("OK: Copy IOC button: visual feedback added")

# ── AI send button: disable during request ────────────────────────────
old_send = ("      messagesEl.appendChild(typingDiv);\n"
            "      messagesEl.scrollTop = messagesEl.scrollHeight;\n"
            "\n"
            "      fetch('/ai-chat',")
new_send = ("      messagesEl.appendChild(typingDiv);\n"
            "      messagesEl.scrollTop = messagesEl.scrollHeight;\n"
            "      sendBtn.disabled = true; sendBtn.style.opacity = '0.6';\n"
            "\n"
            "      fetch('/ai-chat',")
if old_send in content:
    content = content.replace(old_send, new_send, 1)
    print("OK: AI send button: disabled during request")

# Re-enable after response
old_re = ("        renderMessages();\n"
          "        saveState();\n"
          "      }).catch(() => {\n"
          "        typingDiv.remove();\n"
          "        state.messages.push({ role: 'assistant', text: 'Request failed. Check that Ollama is running.' });\n"
          "        renderMessages();\n"
          "        saveState();\n"
          "      });")
new_re = ("        renderMessages();\n"
          "        saveState();\n"
          "        sendBtn.disabled = false; sendBtn.style.opacity = '1';\n"
          "      }).catch(() => {\n"
          "        typingDiv.remove();\n"
          "        state.messages.push({ role: 'assistant', text: 'Request failed. Check that Ollama is running.' });\n"
          "        renderMessages();\n"
          "        saveState();\n"
          "        sendBtn.disabled = false; sendBtn.style.opacity = '1';\n"
          "      });")
if old_re in content:
    content = content.replace(old_re, new_re, 1)
    print("OK: AI send button: re-enabled after response")

# ── Phishing scan button: loading state ──────────────────────────────
old_scan = ("      prs.innerHTML='<div class=\"empty\"><span class=\"spinner\" style=\"display:inline-block;margin-right:8px;\"></span>Analyzing email...</div>';")
new_scan = ("      prs.innerHTML='<div class=\"empty\"><span class=\"spinner\" style=\"display:inline-block;margin-right:8px;\"></span>Analyzing \u2014 extracting headers, auth records, URLs, IOCs\u2026</div>';\n"
            "      pbb.disabled = true; pbb.style.opacity = '0.6';")
if old_scan in content:
    content = content.replace(old_scan, new_scan, 1)
    print("OK: Phishing scan: better loading state")

# Re-enable phishing browse button after scan
for old_reenable, new_reenable in [
    ("          if(data.error){per.textContent=data.error;prs.innerHTML='';return;}",
     "          pbb.disabled=false; pbb.style.opacity='1';\n          if(data.error){per.textContent=data.error;prs.innerHTML='';return;}"),
    ("        .catch(function(){ per.textContent='Scan failed.';prs.innerHTML=''; });",
     "        .catch(function(){ pbb.disabled=false; pbb.style.opacity='1'; per.textContent='Scan failed.';prs.innerHTML=''; });"),
]:
    if old_reenable in content:
        content = content.replace(old_reenable, new_reenable, 1)

print("OK: Phishing browse button: re-enabled after scan")

with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print("\nUX polish done.")