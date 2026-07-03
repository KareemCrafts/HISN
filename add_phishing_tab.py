with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    app = f.read()

# ── ROUTE ──────────────────────────────────────────────────────────
ROUTE = '''
@app.route("/scan-email", methods=["POST"])
def scan_email_route():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "Please choose a file."}), 400
    if not f.filename.lower().endswith(".eml"):
        return jsonify({"error": "Unsupported file type. Upload a .eml file."}), 400
    path = os.path.join(DOC_UPLOAD_DIR, secure_filename(f.filename))
    f.save(path)
    from src.parsers.email_parser import parse_email_file
    result = parse_email_file(path)
    return jsonify(result)


'''

route_anchor = '@app.route("/report/incidents")'
if route_anchor in app and '/scan-email' not in app:
    app = app.replace(route_anchor, ROUTE + route_anchor, 1)
    print("Route added.")
else:
    print("Route already present or anchor not found.")

# ── TAB BUTTON ─────────────────────────────────────────────────────
btn_anchor = 'data-tab="tab-docs">Document &amp; File Triage</button>'
new_btn = btn_anchor + '\n    <button class="tab-btn" data-tab="tab-phishing">Email &amp; Phishing</button>'
if btn_anchor in app and 'tab-phishing' not in app:
    app = app.replace(btn_anchor, new_btn, 1)
    print("Tab button added.")

# ── TAB PANEL HTML ─────────────────────────────────────────────────
PANEL = '''
  <div id="tab-phishing" class="tab-panel">
    <div class="subline" style="margin:0 0 18px;"><span class="ai-dot" style="background:var(--amber);box-shadow:0 0 10px var(--amber);"></span>EMAIL &amp; PHISHING INVESTIGATION &mdash; STATIC ANALYSIS &mdash; .EML</div>
    <div class="dropzone simple" id="phishingDropzone" style="text-align:center;">
      <svg class="upload-icon" width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
      <p style="color:var(--meta);margin-top:8px;">Drop an .eml file here to begin investigation</p>
      <button class="browse-btn" type="button" id="phishingBrowseBtn">Choose .eml File</button>
      <input type="file" id="phishingFileInput" accept=".eml" style="display:none;">
    </div>
    <div class="error-text" id="phishingError"></div>
    <div id="phishingResults"></div>
  </div>

'''

panel_anchor = '\n\n</main>'
if panel_anchor in app and 'tab-phishing' not in app:
    app = app.replace(panel_anchor, PANEL + '\n\n</main>', 1)
    print("Tab panel added.")

# ── JAVASCRIPT ─────────────────────────────────────────────────────
PHISHING_JS = r"""
  // ── PHISHING TAB ──────────────────────────────────────────────
  var lastEmailResult = null;
  (function phishingTab(){
    var dz=document.getElementById('phishingDropzone');
    var bb=document.getElementById('phishingBrowseBtn');
    var fi=document.getElementById('phishingFileInput');
    var er=document.getElementById('phishingError');
    var re2=document.getElementById('phishingResults');
    if(!dz) return;
    bb.addEventListener('click',function(){fi.click();});
    dz.addEventListener('dragover',function(e){e.preventDefault();dz.style.borderColor='var(--amber)';});
    dz.addEventListener('dragleave',function(){dz.style.borderColor='';});
    dz.addEventListener('drop',function(e){e.preventDefault();dz.style.borderColor='';if(e.dataTransfer.files.length)scanEmail(e.dataTransfer.files[0]);});
    fi.addEventListener('change',function(){if(fi.files.length)scanEmail(fi.files[0]);});
    function scanEmail(file){
      if(!file.name.toLowerCase().endsWith('.eml')){er.textContent='Please choose a .eml file.';return;}
      er.textContent='';
      re2.innerHTML='<div class="empty"><span class="spinner" style="display:inline-block;margin-right:8px;"></span>Analyzing email headers, authentication, URLs and attachments...</div>';
      var fd=new FormData();fd.append('file',file);
      fetch('/scan-email',{method:'POST',body:fd}).then(function(r){return r.json();}).then(function(data){
        if(data.error){er.textContent=data.error;re2.innerHTML='';return;}
        lastEmailResult=data;
        re2.innerHTML=renderPhishingResult(data);
        if(window.aiSetContext)window.aiSetContext('email',data,data.filename||'Email');
        var ab=document.getElementById('phishingAiBtn');
        if(ab)ab.addEventListener('click',function(){
          if(window.aiSetContext)window.aiSetContext('email',lastEmailResult,lastEmailResult.filename||'Email');
          var t=document.getElementById('aiWidgetToggle');if(t)t.click();
        });
      }).catch(function(){er.textContent='Scan failed. Check server logs.';re2.innerHTML='';});
    }
  })();

  function renderPhishingResult(r){
    var riskColor=r.risk_score>=70?'var(--crimson)':r.risk_score>=40?'var(--amber)':r.risk_score>=20?'var(--gold)':'var(--acid)';
    var html='<div style="margin-top:20px;">';

    // Risk Banner
    html+='<div class="ioc-box" style="border-left-color:'+riskColor+';margin-bottom:16px;">'
      +'<span class="ioc-label">Risk Assessment \u2014 transparent scoring</span>'
      +'<div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap;">'
      +'<div><span style="font-size:38px;font-weight:800;color:'+riskColor+';font-family:\'JetBrains Mono\';">'+r.risk_score+'</span><span style="color:'+riskColor+';font-size:13px;">/100</span>'
      +'<span class="rem-cat" style="background:'+riskColor+';margin-left:12px;">'+escapeHtml(r.risk_label||'')+'</span></div>'
      +'<div style="flex:1;">'+(r.risk_factors||[]).map(function(f){return'<span class="tag-flag" style="margin:2px;font-size:10px;">'+escapeHtml(f)+'</span>';}).join('')+'</div>'
      +'</div></div>';

    // Techniques
    if((r.phishing_techniques||[]).length){
      html+='<div class="section-label">Phishing Techniques Detected</div>';
      html+='<div style="margin-bottom:14px;">'+r.phishing_techniques.map(function(t){return'<span class="tag-flag">'+escapeHtml(t)+'</span>';}).join('')+'</div>';
    }

    // Metadata
    var m=r.metadata||{};
    html+='<details class="remediation" open><summary>Email Metadata</summary>';
    [['From (Display)',m.from_display],['From (Email)',m.from_email],['To',m.to],['CC',m.cc],['Reply-To',m.reply_to],['Subject',m.subject],['Date',m.date],['Message-ID',m.message_id],['Mailer',m.mailer],['Priority',m.priority]].forEach(function(kv){
      if(kv[1])html+='<div class="kv"><b>'+kv[0]+':</b> <span style="color:var(--ink);">'+escapeHtml(kv[1])+'</span></div>';
    });
    html+='</details>';

    // Authentication
    var auth=r.authentication||{},spf=auth.spf||{},dkim=auth.dkim||{},dmarc=auth.dmarc||{};
    function authBadge(res){var r2=(res||'none').toLowerCase();return r2==='pass'?'<span class="tag-ok">PASS</span>':r2==='fail'||r2==='softfail'?'<span class="tag-flag">'+r2.toUpperCase()+'</span>':'<span class="ioc-muted">'+r2.toUpperCase()+'</span>';}
    html+='<details class="remediation" open><summary>Authentication Analysis \u2014 SPF / DKIM / DMARC</summary>';
    html+='<div class="rem-item"><span class="rem-tech">SPF</span> '+authBadge(spf.result)+(spf.domain?'<span class="ioc-meta"> '+escapeHtml(spf.domain)+'</span>':'')+'<ul><li>SPF checks whether the sending server is authorised for this domain. Fail = unauthorised server.</li></ul></div>';
    html+='<div class="rem-item"><span class="rem-tech">DKIM</span> '+authBadge(dkim.result)+(dkim.domain?'<span class="ioc-meta"> '+escapeHtml(dkim.domain)+'</span>':'')+'<ul><li>DKIM validates the message was not tampered with in transit using a cryptographic signature. Fail = invalid or missing signature.</li></ul></div>';
    html+='<div class="rem-item"><span class="rem-tech">DMARC</span> '+authBadge(dmarc.result)+(dmarc.policy?'<span class="ioc-meta"> Policy: '+escapeHtml(dmarc.policy)+'</span>':'')+'<ul><li>DMARC enforces alignment between SPF/DKIM and the visible From domain. Fail = sender identity cannot be verified.</li></ul></div>';
    html+='</details>';

    // Security Checks
    var c=r.security_checks||{};
    function chk(label,val,desc,warn){
      var badge2=val?(warn?'<span class="tag-flag" style="background:rgba(255,179,71,.1);color:var(--amber);border-color:rgba(255,179,71,.4);">WARN</span>':'<span class="tag-flag">FAIL</span>'):'<span class="tag-ok">PASS</span>';
      return '<div class="rem-item"><span class="rem-tech">'+label+'</span> '+badge2+'<ul><li>'+escapeHtml(desc)+'</li></ul></div>';
    }
    html+='<details class="remediation" open><summary>Security Checks</summary>';
    html+=chk('External Sender',c.external_sender,'Sender is not from an internal domain',true);
    html+=chk('Reply-To Mismatch',c.reply_to_mismatch,'Reply-To domain differs from From domain \u2014 replies may go to an attacker-controlled address',false);
    html+=chk('Display Name Spoofing',c.display_name_spoofing,'Display name impersonates a known brand while the actual sending domain does not match',false);
    html+=chk('HTML Form in Body',c.has_html_form,'HTML form detected \u2014 potential credential harvesting mechanism',false);
    html+=chk('JavaScript in Body',c.has_javascript,'Active JavaScript found in HTML body',true);
    html+=chk('Tracking Pixel',c.has_tracking_pixel,'Tiny image used to track whether the email was opened',true);
    html+=chk('Remote Images',c.has_remote_images,'Images loaded from external servers \u2014 can leak recipient IP and confirm email was opened',true);
    html+=chk('Malformed Message-ID',c.invalid_message_id,'Message-ID does not conform to RFC 5322 \u2014 common in bulk phishing tools',true);
    html+='</details>';

    // Delivery Chain
    if((r.received_chain||[]).length){
      html+='<details class="remediation"><summary>Email Delivery Path ('+r.received_chain.length+' hops)</summary>';
      r.received_chain.forEach(function(hop,i){
        html+='<div class="rem-item"><span class="rem-tech">Hop '+(i+1)+'</span>';
        if(hop.from) html+='<div class="kv"><b>From:</b> '+escapeHtml(hop.from)+'</div>';
        if(hop.by)   html+='<div class="kv"><b>By:</b> '+escapeHtml(hop.by)+'</div>';
        if(hop.ip)   html+='<div class="kv"><b>IP:</b> <span class="tag-ok">'+escapeHtml(hop.ip)+'</span> <a href="https://www.abuseipdb.com/check/'+escapeHtml(hop.ip)+'" target="_blank" class="ioc-link" style="font-size:10px;">AbuseIPDB &rarr;</a> <a href="https://viz.greynoise.io/ip/'+escapeHtml(hop.ip)+'" target="_blank" class="ioc-link" style="font-size:10px;margin-left:8px;">GreyNoise &rarr;</a></div>';
        if(hop.timestamp) html+='<div class="kv"><b>Time:</b> '+escapeHtml(hop.timestamp)+'</div>';
        if(hop.delay_seconds!=null) html+='<div class="kv"><b>Delay:</b> '+hop.delay_seconds+'s</div>';
        html+='</div>';
      });
      html+='</details>';
    }

    // URLs
    if((r.urls||[]).length){
      html+='<details class="remediation"><summary>Extracted URLs ('+r.urls.length+')</summary>';
      r.urls.forEach(function(u){
        var sus=/login|verify|account|secure|update|confirm|password|credential|signin|reset/i.test(u);
        html+='<div class="rem-item">'
          +(sus?'<span class="tag-flag">SUSPICIOUS</span> ':'')
          +'<span style="font-size:10px;color:'+(sus?'var(--crimson)':'var(--cyan)')+';word-break:break-all;">'+escapeHtml(u.length>100?u.slice(0,100)+'...':u)+'</span>'
          +'<div style="margin-top:4px;">'
          +'<a href="https://www.virustotal.com/gui/search/'+encodeURIComponent(u)+'" target="_blank" class="ioc-link" style="font-size:10px;">VirusTotal &rarr;</a>'
          +' <a href="https://urlscan.io/search/#'+encodeURIComponent(u)+'" target="_blank" class="ioc-link" style="font-size:10px;margin-left:8px;">URLScan &rarr;</a>'
          +' <a href="https://www.hybrid-analysis.com/search?query='+encodeURIComponent(u)+'" target="_blank" class="ioc-link" style="font-size:10px;margin-left:8px;">Hybrid Analysis &rarr;</a>'
          +'</div></div>';
      });
      html+='</details>';
    }

    // Attachments
    if((r.attachments||[]).length){
      html+='<details class="remediation"><summary>Attachments ('+r.attachments.length+')</summary>';
      r.attachments.forEach(function(a){
        var dan=a.is_executable||a.has_macros;
        html+='<div class="rem-item">'
          +'<span class="rem-tech">'+escapeHtml(a.filename)+'</span>'+(dan?'<span class="tag-flag" style="margin-left:8px;">HIGH RISK</span>':'')
          +'<div class="kv"><b>Size:</b> '+(a.size/1024).toFixed(1)+' KB &nbsp; <b>Type:</b> '+escapeHtml(a.mime_type||'')+'</div>'
          +'<div class="kv"><b>SHA256:</b> <span style="font-size:10px;">'+escapeHtml(a.sha256||'')+'</span></div>'
          +'<div class="kv"><b>MD5:</b> '+escapeHtml(a.md5||'')+'</div>'
          +(a.has_macros?'<div class="kv" style="color:var(--amber);">\u26a0 May contain macros</div>':'')
          +(a.is_executable?'<div class="kv" style="color:var(--crimson);">\u26a0 Executable file type</div>':'')
          +'<div style="margin-top:6px;">'
          +'<a href="https://www.virustotal.com/gui/file/'+escapeHtml(a.sha256||'')+'" target="_blank" class="ioc-link" style="font-size:10px;">VirusTotal &rarr;</a>'
          +' <a href="https://www.hybrid-analysis.com/search?query='+escapeHtml(a.sha256||'')+'" target="_blank" class="ioc-link" style="font-size:10px;margin-left:8px;">Hybrid Analysis &rarr;</a>'
          +' <a href="https://bazaar.abuse.ch/browse.php?search=sha256%3A'+escapeHtml(a.sha256||'')+'" target="_blank" class="ioc-link" style="font-size:10px;margin-left:8px;">MalwareBazaar &rarr;</a>'
          +'</div></div>';
      });
      html+='</details>';
    }

    // IOCs
    var iocs=r.iocs||{};
    html+='<details class="remediation"><summary>IOC Summary</summary>';
    if((iocs.ips||[]).length)     html+='<div class="rem-item"><span class="rem-tech">IPs</span><div style="margin-top:4px;">'+iocs.ips.map(function(x){return'<span class="tag-ok">'+escapeHtml(x)+'</span>';}).join('')+'</div></div>';
    if((iocs.domains||[]).length) html+='<div class="rem-item"><span class="rem-tech">Domains</span><div style="margin-top:4px;">'+iocs.domains.map(function(x){return'<span class="tag-ok">'+escapeHtml(x)+'</span>';}).join('')+'</div></div>';
    if((iocs.emails||[]).length)  html+='<div class="rem-item"><span class="rem-tech">Email Addresses</span><div style="margin-top:4px;">'+iocs.emails.map(function(x){return'<span class="tag-ok">'+escapeHtml(x)+'</span>';}).join('')+'</div></div>';
    if((iocs.hashes||[]).length)  html+='<div class="rem-item"><span class="rem-tech">Hashes</span><div style="margin-top:4px;">'+iocs.hashes.map(function(x){return'<span class="tag-ok" style="font-size:10px;">'+escapeHtml(x)+'</span>';}).join('')+'</div></div>';
    html+='<div style="margin-top:8px;"><button type="button" class="pill" onclick="navigator.clipboard.writeText(JSON.stringify('+JSON.stringify(JSON.stringify(iocs))+',null,2))" style="color:var(--acid);border-color:var(--acid);">Copy All IOCs</button></div>';
    html+='</details>';

    // MITRE
    if((r.mitre_techniques||[]).length){
      html+='<details class="remediation"><summary>MITRE ATT&CK Mapping</summary>';
      r.mitre_techniques.forEach(function(t){
        var parts=t.split('.'),base=parts[0],sub=parts[1];
        var url=sub?'https://attack.mitre.org/techniques/'+base+'/'+sub+'/':'https://attack.mitre.org/techniques/'+base+'/';
        html+='<div class="rem-item"><span class="rem-tech">'+escapeHtml(t)+'</span> <a href="'+url+'" target="_blank" class="ioc-link" style="font-size:10px;">MITRE ATT&CK &rarr;</a></div>';
      });
      html+='</details>';
    }

    // Timeline
    if((r.timeline||[]).length){
      html+='<details class="remediation"><summary>Email Timeline</summary>';
      r.timeline.forEach(function(e){
        html+='<div class="rem-item"><span class="rem-tech">'+escapeHtml(e.event)+'</span><div class="kv">'+escapeHtml(e.timestamp||'')+(e.detail?' \u2014 '+escapeHtml(e.detail):'')+'</div></div>';
      });
      html+='</details>';
    }

    // Raw Headers
    if(r.raw_headers){
      html+='<details class="remediation"><summary>Raw Headers (excerpt)</summary><div class="excerpt">'+escapeHtml(r.raw_headers)+'</div></details>';
    }

    html+='<div style="margin-top:18px;"><button type="button" class="browse-btn" id="phishingAiBtn">Ask Hisn AI About This Email</button></div>';
    html+='</div>';
    return html;
  }

"""

js_anchor = "  document.querySelectorAll('.cell.hit').forEach"
if js_anchor in app and 'phishingTab' not in app:
    app = app.replace(js_anchor, PHISHING_JS + '\n  ' + "document.querySelectorAll('.cell.hit').forEach", 1)
    print("Phishing JS added.")

with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(app)

print("Phishing tab fully injected.")