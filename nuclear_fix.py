import re

with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

script_start = content.rfind('<script>') + len('<script>')
script_end   = content.rfind('</script>')
pre    = content[:script_start]
script = content[script_start:script_end]
post   = content[script_end:]

print(f"Script block: {len(script.splitlines())} lines")

# 1. Kill every line inside the script that contains JetBrains (font CSS has no place in JS)
lines = script.split('\n')
bad = [i for i,l in enumerate(lines) if 'JetBrains' in l]
print(f"Lines with JetBrains in JS: {bad}")
for i in sorted(bad, reverse=True):
    print(f"  Removing line {i}: {lines[i][:80]}")
    lines.pop(i)
script = '\n'.join(lines)

# 2. Remove ALL phishing JS blocks (any version, old or new)
for pat in [
    re.compile(r'\n  // PHISHING TAB.*?(?=\n  document\.querySelectorAll)', re.DOTALL),
    re.compile(r'\n  // .{0,5}PHISHING TAB.*?(?=\n  document\.querySelectorAll)', re.DOTALL),
]:
    script, n = pat.subn('', script)
    if n: print(f"Removed phishing JS block ({n}).")

# 3. Remove duplicate escapeHtml — keep only the FIRST occurrence
esc_positions = [m.start() for m in re.finditer(r'function escapeHtml\b', script)]
print(f"escapeHtml occurrences: {len(esc_positions)}")
if len(esc_positions) > 1:
    for pos in reversed(esc_positions[1:]):
        # find the function block and remove it
        block_start = script.rfind('\n', 0, pos) 
        depth = 0; i = pos
        started = False
        while i < len(script):
            if script[i] == '{': depth += 1; started = True
            elif script[i] == '}':
                depth -= 1
                if started and depth == 0:
                    script = script[:block_start] + script[i+1:]
                    print("Removed duplicate escapeHtml.")
                    break
            i += 1

# 4. Remove duplicate renderPhishingResult — keep only FIRST occurrence
rpr_positions = [m.start() for m in re.finditer(r'function renderPhishingResult\b', script)]
print(f"renderPhishingResult occurrences: {len(rpr_positions)}")
if len(rpr_positions) > 1:
    for pos in reversed(rpr_positions[1:]):
        block_start = script.rfind('\n', 0, pos)
        depth = 0; i = pos; started = False
        while i < len(script):
            if script[i] == '{': depth += 1; started = True
            elif script[i] == '}':
                depth -= 1
                if started and depth == 0:
                    script = script[:block_start] + script[i+1:]
                    print("Removed duplicate renderPhishingResult.")
                    break
            i += 1

# 5. Inject clean phishing JS
CLEAN = r"""
  // PHISHING TAB
  var lastEmailResult = null;
  (function phishingTab(){
    var pdz = document.getElementById('phishingDropzone');
    var pbb = document.getElementById('phishingBrowseBtn');
    var pfi = document.getElementById('phishingFileInput');
    var per = document.getElementById('phishingError');
    var prs = document.getElementById('phishingResults');
    if (!pdz) return;
    pbb.addEventListener('click', function(){ pfi.click(); });
    pdz.addEventListener('dragover', function(e){ e.preventDefault(); pdz.style.borderColor='var(--amber)'; });
    pdz.addEventListener('dragleave', function(){ pdz.style.borderColor=''; });
    pdz.addEventListener('drop', function(e){
      e.preventDefault(); pdz.style.borderColor='';
      if (e.dataTransfer.files.length) phishScanFile(e.dataTransfer.files[0]);
    });
    pfi.addEventListener('change', function(){ if (pfi.files.length) phishScanFile(pfi.files[0]); });
    function phishScanFile(file) {
      if (!file.name.toLowerCase().endsWith('.eml')) { per.textContent='Please choose a .eml file.'; return; }
      per.textContent='';
      prs.innerHTML='<div class="empty"><span class="spinner" style="display:inline-block;margin-right:8px;"></span>Analyzing email...</div>';
      var pfd = new FormData(); pfd.append('file', file);
      fetch('/scan-email', { method:'POST', body:pfd })
        .then(function(r){ return r.json(); })
        .then(function(data){
          if (data.error){ per.textContent=data.error; prs.innerHTML=''; return; }
          lastEmailResult=data;
          prs.innerHTML=renderPhishingResult(data);
          if (window.aiSetContext) window.aiSetContext('email', data, data.filename||'Email');
          var ab=document.getElementById('phishingAiBtn');
          if (ab) ab.addEventListener('click', function(){
            if (window.aiSetContext) window.aiSetContext('email', lastEmailResult, lastEmailResult.filename||'Email');
            var wt=document.getElementById('aiWidgetToggle'); if(wt) wt.click();
          });
          var cb=document.getElementById('copyIocsBtn');
          if (cb) cb.addEventListener('click', function(){
            if (lastEmailResult && lastEmailResult.iocs)
              navigator.clipboard.writeText(JSON.stringify(lastEmailResult.iocs, null, 2));
          });
        })
        .catch(function(){ per.textContent='Scan failed.'; prs.innerHTML=''; });
    }
  })();

  function renderPhishingResult(r) {
    var riskColor = r.risk_score>=70?'var(--crimson)':r.risk_score>=40?'var(--amber)':r.risk_score>=20?'var(--gold)':'var(--acid)';
    var h = '<div style="margin-top:20px;">';
    h += '<div class="ioc-box" style="border-left-color:'+riskColor+';margin-bottom:16px;">';
    h += '<span class="ioc-label">Risk Assessment</span>';
    h += '<div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap;">';
    h += '<div><span style="font-size:38px;font-weight:800;color:'+riskColor+';">'+r.risk_score+'</span>';
    h += '<span style="color:'+riskColor+';font-size:13px;">/100</span>';
    h += '<span class="rem-cat" style="background:'+riskColor+';margin-left:12px;">'+escapeHtml(r.risk_label||'')+'</span></div>';
    h += '<div style="flex:1;">';
    (r.risk_factors||[]).forEach(function(f){ h+='<span class="tag-flag" style="margin:2px;font-size:10px;">'+escapeHtml(f)+'</span>'; });
    h += '</div></div></div>';
    if((r.phishing_techniques||[]).length){
      h+='<div class="section-label">Phishing Techniques Detected</div><div style="margin-bottom:14px;">';
      r.phishing_techniques.forEach(function(t){ h+='<span class="tag-flag">'+escapeHtml(t)+'</span> '; });
      h+='</div>';
    }
    var m=r.metadata||{};
    h+='<details class="remediation" open><summary>Email Metadata</summary>';
    [['From (Display)',m.from_display],['From (Email)',m.from_email],['To',m.to],['CC',m.cc],['Reply-To',m.reply_to],['Subject',m.subject],['Date',m.date],['Message-ID',m.message_id],['Mailer',m.mailer]].forEach(function(kv){
      if(kv[1]) h+='<div class="kv"><b>'+kv[0]+':</b> <span style="color:var(--ink);">'+escapeHtml(kv[1])+'</span></div>';
    });
    h+='</details>';
    var auth=r.authentication||{},spf=auth.spf||{},dkim=auth.dkim||{},dmarc=auth.dmarc||{};
    function ab2(res){ var v=(res||'none').toLowerCase(); return v==='pass'?'<span class="tag-ok">PASS</span>':v==='fail'||v==='softfail'?'<span class="tag-flag">'+v.toUpperCase()+'</span>':'<span class="ioc-muted">'+v.toUpperCase()+'</span>'; }
    h+='<details class="remediation" open><summary>Authentication Analysis</summary>';
    h+='<div class="rem-item"><span class="rem-tech">SPF</span> '+ab2(spf.result)+(spf.domain?'<span class="ioc-meta"> '+escapeHtml(spf.domain)+'</span>':'')+'<ul><li>Verifies the sending server is authorised for the domain.</li></ul></div>';
    h+='<div class="rem-item"><span class="rem-tech">DKIM</span> '+ab2(dkim.result)+(dkim.domain?'<span class="ioc-meta"> '+escapeHtml(dkim.domain)+'</span>':'')+'<ul><li>Validates message integrity via cryptographic signature.</li></ul></div>';
    h+='<div class="rem-item"><span class="rem-tech">DMARC</span> '+ab2(dmarc.result)+(dmarc.policy?'<span class="ioc-meta"> Policy: '+escapeHtml(dmarc.policy)+'</span>':'')+'<ul><li>Enforces From-domain alignment. Fail means sender identity unverified.</li></ul></div>';
    h+='</details>';
    var c=r.security_checks||{};
    function chk2(label,val,desc,warn){ var badge=val?(warn?'<span style="color:var(--amber);font-size:10px;border:1px solid var(--amber);padding:1px 6px;">WARN</span>':'<span class="tag-flag">FAIL</span>'):'<span class="tag-ok">PASS</span>'; return '<div class="rem-item"><span class="rem-tech">'+label+'</span> '+badge+'<ul><li>'+escapeHtml(desc)+'</li></ul></div>'; }
    h+='<details class="remediation" open><summary>Security Checks</summary>';
    h+=chk2('External Sender',c.external_sender,'Sender is not from an internal domain.',true);
    h+=chk2('Reply-To Mismatch',c.reply_to_mismatch,'Reply-To domain differs from From domain.',false);
    h+=chk2('Display Name Spoofing',c.display_name_spoofing,'Display name impersonates a known brand.',false);
    h+=chk2('HTML Form',c.has_html_form,'HTML form detected in body - possible credential harvesting.',false);
    h+=chk2('JavaScript',c.has_javascript,'Active JavaScript found in HTML body.',true);
    h+=chk2('Tracking Pixel',c.has_tracking_pixel,'Tiny image used to track if email was opened.',true);
    h+=chk2('Remote Images',c.has_remote_images,'External images can leak recipient IP.',true);
    h+=chk2('Malformed Message-ID',c.invalid_message_id,'Message-ID does not conform to RFC 5322.',true);
    h+='</details>';
    if((r.received_chain||[]).length){
      h+='<details class="remediation"><summary>Delivery Path ('+r.received_chain.length+' hops)</summary>';
      r.received_chain.forEach(function(hop,i){
        h+='<div class="rem-item"><span class="rem-tech">Hop '+(i+1)+'</span>';
        if(hop.from) h+='<div class="kv"><b>From:</b> '+escapeHtml(hop.from)+'</div>';
        if(hop.by)   h+='<div class="kv"><b>By:</b> '+escapeHtml(hop.by)+'</div>';
        if(hop.ip)   h+='<div class="kv"><b>IP:</b> <span class="tag-ok">'+escapeHtml(hop.ip)+'</span> <a href="https://www.abuseipdb.com/check/'+encodeURIComponent(hop.ip)+'" target="_blank" class="ioc-link" style="font-size:10px;">AbuseIPDB</a></div>';
        if(hop.timestamp) h+='<div class="kv"><b>Time:</b> '+escapeHtml(hop.timestamp)+'</div>';
        h+='</div>';
      });
      h+='</details>';
    }
    if((r.urls||[]).length){
      h+='<details class="remediation"><summary>Extracted URLs ('+r.urls.length+')</summary>';
      r.urls.forEach(function(u){
        var sus=/login|verify|account|secure|update|confirm|password|credential|signin|reset/i.test(u);
        h+='<div class="rem-item">'+(sus?'<span class="tag-flag">SUSPICIOUS</span> ':'')+
          '<span style="font-size:10px;word-break:break-all;color:'+(sus?'var(--crimson)':'var(--cyan)')+';">'+escapeHtml(u.length>100?u.slice(0,100)+'...':u)+'</span>'+
          '<div style="margin-top:4px;"><a href="https://www.virustotal.com/gui/search/'+encodeURIComponent(u)+'" target="_blank" class="ioc-link" style="font-size:10px;">VirusTotal</a> '+
          '<a href="https://urlscan.io/search/#'+encodeURIComponent(u)+'" target="_blank" class="ioc-link" style="font-size:10px;">URLScan</a></div></div>';
      });
      h+='</details>';
    }
    if((r.attachments||[]).length){
      h+='<details class="remediation"><summary>Attachments ('+r.attachments.length+')</summary>';
      r.attachments.forEach(function(a){
        h+='<div class="rem-item"><span class="rem-tech">'+escapeHtml(a.filename)+'</span>'+(a.is_executable||a.has_macros?' <span class="tag-flag">HIGH RISK</span>':'')+
          '<div class="kv"><b>SHA256:</b> <span style="font-size:10px;">'+escapeHtml(a.sha256||'')+'</span></div>'+
          (a.has_macros?'<div class="kv" style="color:var(--amber);">May contain macros</div>':'')+
          (a.is_executable?'<div class="kv" style="color:var(--crimson);">Executable file type</div>':'')+
          '<div style="margin-top:6px;"><a href="https://www.virustotal.com/gui/file/'+encodeURIComponent(a.sha256||'')+'" target="_blank" class="ioc-link" style="font-size:10px;">VirusTotal</a> '+
          '<a href="https://bazaar.abuse.ch/browse.php?search=sha256%3A'+encodeURIComponent(a.sha256||'')+'" target="_blank" class="ioc-link" style="font-size:10px;">MalwareBazaar</a></div></div>';
      });
      h+='</details>';
    }
    var iocs=r.iocs||{};
    h+='<details class="remediation"><summary>IOC Summary</summary>';
    if((iocs.ips||[]).length){ h+='<div class="rem-item"><span class="rem-tech">IPs</span><div style="margin-top:4px;">'; iocs.ips.forEach(function(x){ h+='<span class="tag-ok">'+escapeHtml(x)+'</span> '; }); h+='</div></div>'; }
    if((iocs.domains||[]).length){ h+='<div class="rem-item"><span class="rem-tech">Domains</span><div style="margin-top:4px;">'; iocs.domains.forEach(function(x){ h+='<span class="tag-ok">'+escapeHtml(x)+'</span> '; }); h+='</div></div>'; }
    if((iocs.emails||[]).length){ h+='<div class="rem-item"><span class="rem-tech">Emails</span><div style="margin-top:4px;">'; iocs.emails.forEach(function(x){ h+='<span class="tag-ok">'+escapeHtml(x)+'</span> '; }); h+='</div></div>'; }
    if((iocs.hashes||[]).length){ h+='<div class="rem-item"><span class="rem-tech">Hashes</span><div style="margin-top:4px;">'; iocs.hashes.forEach(function(x){ h+='<span class="tag-ok" style="font-size:10px;">'+escapeHtml(x)+'</span> '; }); h+='</div></div>'; }
    h+='<div style="margin-top:8px;"><button type="button" class="pill" id="copyIocsBtn" style="color:var(--acid);border-color:var(--acid);">Copy All IOCs</button></div></details>';
    if((r.mitre_techniques||[]).length){
      h+='<details class="remediation"><summary>MITRE ATT&amp;CK Mapping</summary>';
      r.mitre_techniques.forEach(function(t){ var pts=t.split('.'),base=pts[0],sub=pts[1]; var url=sub?'https://attack.mitre.org/techniques/'+base+'/'+sub+'/':'https://attack.mitre.org/techniques/'+base+'/'; h+='<div class="rem-item"><span class="rem-tech">'+escapeHtml(t)+'</span> <a href="'+url+'" target="_blank" class="ioc-link" style="font-size:10px;">MITRE ATT&amp;CK</a></div>'; });
      h+='</details>';
    }
    if((r.timeline||[]).length){
      h+='<details class="remediation"><summary>Timeline</summary>';
      r.timeline.forEach(function(ev){ h+='<div class="rem-item"><span class="rem-tech">'+escapeHtml(ev.event)+'</span><div class="kv">'+escapeHtml(ev.timestamp||'')+(ev.detail?' \u2014 '+escapeHtml(ev.detail):'')+'</div></div>'; });
      h+='</details>';
    }
    if(r.raw_headers) h+='<details class="remediation"><summary>Raw Headers</summary><div class="excerpt">'+escapeHtml(r.raw_headers)+'</div></details>';
    h+='<div style="margin-top:18px;"><button type="button" class="browse-btn" id="phishingAiBtn">Ask Hisn AI About This Email</button></div>';
    h+='</div>';
    return h;
  }
"""

anchor = "\n  document.querySelectorAll('.cell.hit').forEach"
if anchor in script:
    script = script.replace(anchor, CLEAN + '\n' + anchor, 1)
    print("Clean phishing JS injected.")
else:
    print("ERROR: .cell.hit anchor not found.")

# Verify no more JetBrains in JS
remaining = [i for i,l in enumerate(script.split('\n')) if 'JetBrains' in l]
print(f"Remaining JetBrains lines in JS: {remaining}")

# Verify function counts
print(f"escapeHtml count: {script.count('function escapeHtml')}")
print(f"renderPhishingResult count: {script.count('function renderPhishingResult')}")

new_content = pre + script + post
with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(new_content)
print("Done. Run dashboard.bat and open F12 console to verify no errors.")