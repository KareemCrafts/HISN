import re

with open('src/dashboard/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Remove broken phishing JS block
before = content.count('phishingTab')
phish_pat = re.compile(r'\n  // .{0,10}PHISHING TAB.{0,200}?(?=\n  document\.querySelectorAll)', re.DOTALL)
m = phish_pat.search(content)
if m:
    content = content[:m.start()] + content[m.end():]
    print(f"Removed phishing JS block ({m.end()-m.start()} chars).")
else:
    print("WARNING: phishing block pattern not found — trying alternate approach.")
    # Fallback: find between known markers
    start_marker = '\n  // '
    end_marker = "\n  document.querySelectorAll('.cell.hit').forEach"
    si = content.rfind(start_marker, 0, content.find(end_marker))
    ei = content.find(end_marker)
    if si != -1 and ei != -1 and 'phishingTab' in content[si:ei]:
        content = content[:si] + content[ei:]
        print("Removed via fallback method.")
    else:
        print("ERROR: could not locate phishing block.")

after = content.count('phishingTab')
print(f"phishingTab occurrences: {before} -> {after}")

CLEAN_JS = """
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
      if (!file.name.toLowerCase().endsWith('.eml')) { per.textContent = 'Please choose a .eml file.'; return; }
      per.textContent = '';
      prs.innerHTML = '<div class="empty"><span class="spinner" style="display:inline-block;margin-right:8px;"></span>Analyzing email...</div>';
      var fd = new FormData(); fd.append('file', file);
      fetch('/scan-email', { method: 'POST', body: fd })
        .then(function(r){ return r.json(); })
        .then(function(data){
          if (data.error) { per.textContent = data.error; prs.innerHTML = ''; return; }
          lastEmailResult = data;
          prs.innerHTML = renderPhishingResult(data);
          if (window.aiSetContext) window.aiSetContext('email', data, data.filename || 'Email');
          var ab = document.getElementById('phishingAiBtn');
          if (ab) ab.addEventListener('click', function(){
            if (window.aiSetContext) window.aiSetContext('email', lastEmailResult, lastEmailResult.filename || 'Email');
            var wt = document.getElementById('aiWidgetToggle'); if (wt) wt.click();
          });
          var cb = document.getElementById('copyIocsBtn');
          if (cb) cb.addEventListener('click', function(){
            if (lastEmailResult && lastEmailResult.iocs) {
              navigator.clipboard.writeText(JSON.stringify(lastEmailResult.iocs, null, 2));
              toast('IOCs copied.');
            }
          });
        })
        .catch(function(){ per.textContent = 'Scan failed.'; prs.innerHTML = ''; });
    }
  })();

  function renderPhishingResult(r) {
    var riskColor = r.risk_score >= 70 ? 'var(--crimson)' : r.risk_score >= 40 ? 'var(--amber)' : r.risk_score >= 20 ? 'var(--gold)' : 'var(--acid)';
    var h = '<div style="margin-top:20px;">';

    h += '<div class="ioc-box" style="border-left-color:' + riskColor + ';margin-bottom:16px;">';
    h += '<span class="ioc-label">Risk Assessment</span>';
    h += '<div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap;">';
    h += '<div><span style="font-size:38px;font-weight:800;color:' + riskColor + ';">' + r.risk_score + '</span>';
    h += '<span style="color:' + riskColor + ';font-size:13px;">/100</span>';
    h += '<span class="rem-cat" style="background:' + riskColor + ';margin-left:12px;">' + escapeHtml(r.risk_label || '') + '</span></div>';
    h += '<div style="flex:1;">';
    (r.risk_factors || []).forEach(function(f){ h += '<span class="tag-flag" style="margin:2px;font-size:10px;">' + escapeHtml(f) + '</span>'; });
    h += '</div></div></div>';

    if ((r.phishing_techniques || []).length) {
      h += '<div class="section-label">Phishing Techniques Detected</div><div style="margin-bottom:14px;">';
      r.phishing_techniques.forEach(function(t){ h += '<span class="tag-flag">' + escapeHtml(t) + '</span> '; });
      h += '</div>';
    }

    var m = r.metadata || {};
    h += '<details class="remediation" open><summary>Email Metadata</summary>';
    var mfields = [['From (Display)', m.from_display], ['From (Email)', m.from_email], ['To', m.to], ['CC', m.cc], ['Reply-To', m.reply_to], ['Subject', m.subject], ['Date', m.date], ['Message-ID', m.message_id], ['Mailer', m.mailer]];
    mfields.forEach(function(kv){ if (kv[1]) h += '<div class="kv"><b>' + kv[0] + ':</b> <span style="color:var(--ink);">' + escapeHtml(kv[1]) + '</span></div>'; });
    h += '</details>';

    var auth = r.authentication || {}, spf = auth.spf || {}, dkim = auth.dkim || {}, dmarc = auth.dmarc || {};
    function authBadge(res) {
      var v = (res || 'none').toLowerCase();
      if (v === 'pass') return '<span class="tag-ok">PASS</span>';
      if (v === 'fail' || v === 'softfail') return '<span class="tag-flag">' + v.toUpperCase() + '</span>';
      return '<span class="ioc-muted">' + v.toUpperCase() + '</span>';
    }
    h += '<details class="remediation" open><summary>Authentication Analysis</summary>';
    h += '<div class="rem-item"><span class="rem-tech">SPF</span> ' + authBadge(spf.result) + (spf.domain ? '<span class="ioc-meta"> ' + escapeHtml(spf.domain) + '</span>' : '') + '<ul><li>Verifies the sending server is authorised for the domain. Fail = unauthorised server.</li></ul></div>';
    h += '<div class="rem-item"><span class="rem-tech">DKIM</span> ' + authBadge(dkim.result) + (dkim.domain ? '<span class="ioc-meta"> ' + escapeHtml(dkim.domain) + '</span>' : '') + '<ul><li>Validates message integrity. Fail = signature missing or invalid.</li></ul></div>';
    h += '<div class="rem-item"><span class="rem-tech">DMARC</span> ' + authBadge(dmarc.result) + (dmarc.policy ? '<span class="ioc-meta"> Policy: ' + escapeHtml(dmarc.policy) + '</span>' : '') + '<ul><li>Enforces From-domain alignment. Fail = sender identity unverified.</li></ul></div>';
    h += '</details>';

    var c = r.security_checks || {};
    function chk(label, val, desc, warn) {
      var badge = val ? (warn ? '<span style="color:var(--amber);font-size:10px;">WARN</span>' : '<span class="tag-flag">FAIL</span>') : '<span class="tag-ok">PASS</span>';
      return '<div class="rem-item"><span class="rem-tech">' + label + '</span> ' + badge + '<ul><li>' + escapeHtml(desc) + '</li></ul></div>';
    }
    h += '<details class="remediation" open><summary>Security Checks</summary>';
    h += chk('External Sender', c.external_sender, 'Sender is not from an internal domain.', true);
    h += chk('Reply-To Mismatch', c.reply_to_mismatch, 'Reply-To domain differs from From domain — replies may reach an attacker.', false);
    h += chk('Display Name Spoofing', c.display_name_spoofing, 'Display name impersonates a known brand while sending domain does not match.', false);
    h += chk('HTML Form in Body', c.has_html_form, 'HTML form detected — potential credential harvesting.', false);
    h += chk('JavaScript in Body', c.has_javascript, 'Active JavaScript found in HTML body.', true);
    h += chk('Tracking Pixel', c.has_tracking_pixel, 'Tiny image used to track if email was opened.', true);
    h += chk('Remote Images', c.has_remote_images, 'External images can confirm email was opened and leak recipient IP.', true);
    h += chk('Malformed Message-ID', c.invalid_message_id, 'Message-ID does not conform to RFC 5322 — common in bulk phishing tools.', true);
    h += '</details>';

    if ((r.received_chain || []).length) {
      h += '<details class="remediation"><summary>Email Delivery Path (' + r.received_chain.length + ' hops)</summary>';
      r.received_chain.forEach(function(hop, i) {
        h += '<div class="rem-item"><span class="rem-tech">Hop ' + (i + 1) + '</span>';
        if (hop.from) h += '<div class="kv"><b>From:</b> ' + escapeHtml(hop.from) + '</div>';
        if (hop.by)   h += '<div class="kv"><b>By:</b> ' + escapeHtml(hop.by) + '</div>';
        if (hop.ip)   h += '<div class="kv"><b>IP:</b> <span class="tag-ok">' + escapeHtml(hop.ip) + '</span> <a href="https://www.abuseipdb.com/check/' + encodeURIComponent(hop.ip) + '" target="_blank" class="ioc-link" style="font-size:10px;">AbuseIPDB</a> <a href="https://viz.greynoise.io/ip/' + encodeURIComponent(hop.ip) + '" target="_blank" class="ioc-link" style="font-size:10px;margin-left:8px;">GreyNoise</a></div>';
        if (hop.timestamp) h += '<div class="kv"><b>Time:</b> ' + escapeHtml(hop.timestamp) + '</div>';
        if (hop.delay_seconds != null) h += '<div class="kv"><b>Delay:</b> ' + hop.delay_seconds + 's</div>';
        h += '</div>';
      });
      h += '</details>';
    }

    if ((r.urls || []).length) {
      h += '<details class="remediation"><summary>Extracted URLs (' + r.urls.length + ')</summary>';
      r.urls.forEach(function(u) {
        var sus = /login|verify|account|secure|update|confirm|password|credential|signin|reset/i.test(u);
        h += '<div class="rem-item">';
        if (sus) h += '<span class="tag-flag">SUSPICIOUS</span> ';
        h += '<span style="font-size:10px;color:' + (sus ? 'var(--crimson)' : 'var(--cyan)') + ';word-break:break-all;">' + escapeHtml(u.length > 100 ? u.slice(0, 100) + '...' : u) + '</span>';
        h += '<div style="margin-top:4px;"><a href="https://www.virustotal.com/gui/search/' + encodeURIComponent(u) + '" target="_blank" class="ioc-link" style="font-size:10px;">VirusTotal</a> ';
        h += '<a href="https://urlscan.io/search/#' + encodeURIComponent(u) + '" target="_blank" class="ioc-link" style="font-size:10px;">URLScan</a></div></div>';
      });
      h += '</details>';
    }

    if ((r.attachments || []).length) {
      h += '<details class="remediation"><summary>Attachments (' + r.attachments.length + ')</summary>';
      r.attachments.forEach(function(a) {
        h += '<div class="rem-item"><span class="rem-tech">' + escapeHtml(a.filename) + '</span>';
        if (a.is_executable || a.has_macros) h += ' <span class="tag-flag">HIGH RISK</span>';
        h += '<div class="kv"><b>Size:</b> ' + (a.size / 1024).toFixed(1) + ' KB</div>';
        h += '<div class="kv"><b>SHA256:</b> <span style="font-size:10px;">' + escapeHtml(a.sha256 || '') + '</span></div>';
        if (a.has_macros) h += '<div class="kv" style="color:var(--amber);">May contain macros</div>';
        if (a.is_executable) h += '<div class="kv" style="color:var(--crimson);">Executable file type</div>';
        h += '<div style="margin-top:6px;"><a href="https://www.virustotal.com/gui/file/' + encodeURIComponent(a.sha256 || '') + '" target="_blank" class="ioc-link" style="font-size:10px;">VirusTotal</a> ';
        h += '<a href="https://bazaar.abuse.ch/browse.php?search=sha256%3A' + encodeURIComponent(a.sha256 || '') + '" target="_blank" class="ioc-link" style="font-size:10px;">MalwareBazaar</a></div></div>';
      });
      h += '</details>';
    }

    var iocs = r.iocs || {};
    h += '<details class="remediation"><summary>IOC Summary</summary>';
    if ((iocs.ips || []).length)     { h += '<div class="rem-item"><span class="rem-tech">IPs</span><div style="margin-top:4px;">'; iocs.ips.forEach(function(x){ h += '<span class="tag-ok">' + escapeHtml(x) + '</span> '; }); h += '</div></div>'; }
    if ((iocs.domains || []).length) { h += '<div class="rem-item"><span class="rem-tech">Domains</span><div style="margin-top:4px;">'; iocs.domains.forEach(function(x){ h += '<span class="tag-ok">' + escapeHtml(x) + '</span> '; }); h += '</div></div>'; }
    if ((iocs.emails || []).length)  { h += '<div class="rem-item"><span class="rem-tech">Email Addresses</span><div style="margin-top:4px;">'; iocs.emails.forEach(function(x){ h += '<span class="tag-ok">' + escapeHtml(x) + '</span> '; }); h += '</div></div>'; }
    if ((iocs.hashes || []).length)  { h += '<div class="rem-item"><span class="rem-tech">Hashes</span><div style="margin-top:4px;">'; iocs.hashes.forEach(function(x){ h += '<span class="tag-ok" style="font-size:10px;">' + escapeHtml(x) + '</span> '; }); h += '</div></div>'; }
    h += '<div style="margin-top:8px;"><button type="button" class="pill" id="copyIocsBtn" style="color:var(--acid);border-color:var(--acid);">Copy All IOCs</button></div>';
    h += '</details>';

    if ((r.mitre_techniques || []).length) {
      h += '<details class="remediation"><summary>MITRE ATT&amp;CK Mapping</summary>';
      r.mitre_techniques.forEach(function(t) {
        var pts = t.split('.'), base = pts[0], sub = pts[1];
        var url = sub ? 'https://attack.mitre.org/techniques/' + base + '/' + sub + '/' : 'https://attack.mitre.org/techniques/' + base + '/';
        h += '<div class="rem-item"><span class="rem-tech">' + escapeHtml(t) + '</span> <a href="' + url + '" target="_blank" class="ioc-link" style="font-size:10px;">MITRE ATT&amp;CK</a></div>';
      });
      h += '</details>';
    }

    if ((r.timeline || []).length) {
      h += '<details class="remediation"><summary>Email Timeline</summary>';
      r.timeline.forEach(function(ev) {
        h += '<div class="rem-item"><span class="rem-tech">' + escapeHtml(ev.event) + '</span>';
        h += '<div class="kv">' + escapeHtml(ev.timestamp || '') + (ev.detail ? ' \u2014 ' + escapeHtml(ev.detail) : '') + '</div></div>';
      });
      h += '</details>';
    }

    if (r.raw_headers) {
      h += '<details class="remediation"><summary>Raw Headers (excerpt)</summary><div class="excerpt">' + escapeHtml(r.raw_headers) + '</div></details>';
    }

    h += '<div style="margin-top:18px;"><button type="button" class="browse-btn" id="phishingAiBtn">Ask Hisn AI About This Email</button></div>';
    h += '</div>';
    return h;
  }

"""

anchor = "\n  document.querySelectorAll('.cell.hit').forEach"
if anchor in content:
    content = content.replace(anchor, CLEAN_JS + anchor, 1)
    print("Clean phishing JS injected.")
else:
    print("ERROR: .cell.hit anchor not found.")

with open('src/dashboard/app.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print("Done.")