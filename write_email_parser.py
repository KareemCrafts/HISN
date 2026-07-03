content = r'''# src/parsers/email_parser.py
import email
import email.policy
import hashlib
import re
from email.utils import parsedate_to_datetime, parseaddr


def _sha256(data): return hashlib.sha256(data).hexdigest()
def _md5(data):    return hashlib.md5(data).hexdigest()
def _sha1(data):   return hashlib.sha1(data).hexdigest()

def _extract_urls(text):
    return list(set(re.findall(r'https?://[^\s<>"\'{}|\\^`\[\]]+', text or '')))

def _extract_ips(text):
    raw = re.findall(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b', text or '')
    return list(set(ip for ip in raw if not ip.startswith(('10.','192.168.','172.','127.','0.'))))

def _parse_auth(headers):
    hdr = headers.get('Authentication-Results','') or headers.get('ARC-Authentication-Results','') or ''
    def _get(key):
        m = re.search(key + r'=(\w+)', hdr, re.I)
        return m.group(1).lower() if m else 'none'
    spf  = {'result': _get('spf'),  'domain': None}
    dkim = {'result': _get('dkim'), 'domain': None, 'selector': None}
    dmarc= {'result': _get('dmarc'),'policy': None}
    d = re.search(r'smtp\.mailfrom=([^\s;]+)', hdr, re.I)
    if d: spf['domain'] = d.group(1)
    d = re.search(r'header\.i=@?([^\s;]+)', hdr, re.I)
    if d: dkim['domain'] = d.group(1)
    d = re.search(r'header\.s=([^\s;]+)', hdr, re.I)
    if d: dkim['selector'] = d.group(1)
    d = re.search(r'p=(\w+)', hdr, re.I)
    if d: dmarc['policy'] = d.group(1)
    return spf, dkim, dmarc

def _parse_chain(msg):
    chain = []
    received = msg.get_all('Received') or []
    prev_ts = None
    for raw in reversed(received):
        hop = {'from': None, 'by': None, 'ip': None, 'timestamp': None, 'delay_seconds': None}
        m = re.search(r'from\s+(\S+)', raw, re.I);   hop['from'] = m.group(1) if m else None
        m = re.search(r'by\s+(\S+)', raw, re.I);     hop['by']   = m.group(1) if m else None
        m = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', raw)
        if m: hop['ip'] = m.group(1)
        m = re.search(r';\s*(.+)$', raw, re.M)
        if m:
            try:
                ts = parsedate_to_datetime(m.group(1).strip())
                hop['timestamp'] = ts.isoformat()
                if prev_ts is not None:
                    hop['delay_seconds'] = int(ts.timestamp() - prev_ts)
                prev_ts = ts.timestamp()
            except Exception:
                pass
        chain.append(hop)
    return chain

def _security_checks(msg, from_display, from_email, reply_to, body_html):
    from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ''
    reply_domain = reply_to.split('@')[-1].lower() if reply_to and '@' in reply_to else ''
    brands = ['microsoft','google','apple','amazon','paypal','facebook','netflix','linkedin','dropbox','docusign','dhl','fedex','irs','usps']
    disp = from_display.lower()
    spoofing = any(b in disp for b in brands) and not any(b in from_domain for b in brands)
    html = body_html or ''
    return {
        'external_sender': bool(from_domain),
        'reply_to_mismatch': bool(reply_domain and reply_domain != from_domain),
        'display_name_spoofing': spoofing,
        'has_html_form': '<form' in html.lower(),
        'has_javascript': '<script' in html.lower() or 'javascript:' in html.lower(),
        'has_tracking_pixel': bool(re.search(r'<img[^>]+(?:width=["\']?1["\']?|height=["\']?1["\']?)', html, re.I)),
        'has_remote_images': bool(re.search(r'<img[^>]+src=["\']https?://', html, re.I)),
        'invalid_message_id': not bool(re.match(r'<[^@>]+@[^@>]+>', msg.get('Message-ID',''))),
    }

def _risk_score(checks, spf, dkim, dmarc, urls, attachments):
    score = 0; factors = []
    if spf['result'] in ('fail','softfail'):  score+=20; factors.append(f"SPF {spf['result']} (+20)")
    if dkim['result'] == 'fail':              score+=15; factors.append('DKIM fail (+15)')
    if dmarc['result'] == 'fail':             score+=10; factors.append('DMARC fail (+10)')
    if checks.get('reply_to_mismatch'):        score+=20; factors.append('Reply-To mismatch (+20)')
    if checks.get('display_name_spoofing'):    score+=25; factors.append('Display name spoofing (+25)')
    if checks.get('external_sender'):          score+=5;  factors.append('External sender (+5)')
    sus = sum(1 for u in urls if re.search(r'login|verify|account|secure|update|confirm|password|credential|signin|reset',u,re.I))
    if sus: add=min(30,sus*10); score+=add; factors.append(f'{sus} suspicious URL(s) (+{add})')
    if checks.get('has_html_form'):            score+=15; factors.append('Credential harvesting form (+15)')
    if checks.get('has_javascript'):           score+=10; factors.append('JavaScript in body (+10)')
    for a in attachments:
        if a.get('is_executable'): score+=30; factors.append(f"Executable attachment: {a['filename']} (+30)"); break
        if a.get('has_macros'):    score+=25; factors.append(f"Macro-enabled file: {a['filename']} (+25)"); break
    return min(100,score), factors

def _phishing_techniques(checks, spf, urls, attachments, body_text):
    t = []
    bt = (body_text or '').lower()
    if checks.get('display_name_spoofing') or spf['result'] in ('fail','softfail'): t.append('Spoofing')
    if checks.get('reply_to_mismatch'):   t.append('Reply-To Hijacking')
    if urls:                              t.append('Malicious Link')
    if checks.get('has_html_form') or any(w in bt for w in ['password','login','sign in','verify your','credential']): t.append('Credential Harvesting')
    if any(w in bt for w in ['invoice','payment','wire transfer','bank account']): t.append('Invoice Fraud / BEC')
    if any(a.get('has_macros') for a in attachments):     t.append('Malicious Attachment (Macro)')
    if any(a.get('is_executable') for a in attachments):  t.append('Malicious Attachment (Executable)')
    if any(w in bt for w in ['urgent','immediately','action required','suspended','verify now']): t.append('Urgency / Pressure Tactics')
    if any(w in bt for w in ['gift card','amazon gift','itunes']): t.append('Gift Card Scam')
    if any(w in bt for w in ['mfa','authenticator','two-factor','2fa','verification code']): t.append('Fake MFA Request')
    return t

def _mitre(techniques, attachments):
    m = {'T1566'}
    if attachments:        m.add('T1566.001')
    if 'Malicious Link' in techniques or 'Credential Harvesting' in techniques: m.add('T1566.002')
    if 'Spoofing' in techniques or 'Reply-To Hijacking' in techniques: m.add('T1656')
    if 'Credential Harvesting' in techniques: m.add('T1598')
    if attachments:        m.add('T1204.002')
    return sorted(m)


def parse_email_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            raw = f.read()
    except Exception as e:
        return {'error': str(e)}
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as e:
        return {'error': f'Failed to parse email: {e}'}

    from_raw = msg.get('From','')
    from_display, from_email = parseaddr(from_raw)
    _, reply_to = parseaddr(msg.get('Reply-To',''))
    _, return_path = parseaddr(msg.get('Return-Path',''))

    metadata = {
        'from_display': from_display or '',
        'from_email': from_email or from_raw,
        'to': msg.get('To',''),
        'cc': msg.get('CC','') or msg.get('Cc',''),
        'bcc': msg.get('BCC','') or msg.get('Bcc',''),
        'reply_to': reply_to or msg.get('Reply-To',''),
        'return_path': return_path,
        'subject': msg.get('Subject',''),
        'date': msg.get('Date',''),
        'message_id': msg.get('Message-ID',''),
        'mime_version': msg.get('MIME-Version',''),
        'mailer': msg.get('X-Mailer','') or msg.get('User-Agent',''),
        'priority': msg.get('X-Priority','') or msg.get('Importance',''),
        'organization': msg.get('Organization',''),
    }

    body_text = ''; body_html = ''; attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get('Content-Disposition',''))
            if ct == 'text/plain' and 'attachment' not in cd:
                try: body_text = part.get_content()
                except: body_text = ''
            elif ct == 'text/html' and 'attachment' not in cd:
                try: body_html = part.get_content()
                except: body_html = ''
            elif 'attachment' in cd or part.get_filename():
                fname = part.get_filename() or 'unknown'
                try:
                    data = part.get_payload(decode=True) or b''
                    ext = ('.' + fname.rsplit('.',1)[-1].lower()) if '.' in fname else ''
                    attachments.append({
                        'filename': fname, 'extension': ext, 'size': len(data),
                        'mime_type': ct,
                        'sha256': _sha256(data), 'md5': _md5(data), 'sha1': _sha1(data),
                        'has_macros': ext in ('.doc','.docm','.xls','.xlsm','.ppt','.pptm'),
                        'is_executable': ext in ('.exe','.bat','.cmd','.ps1','.vbs','.js','.jar','.scr'),
                        'is_compressed': ext in ('.zip','.rar','.7z','.gz','.tar'),
                    })
                except: pass
    else:
        try: body_text = msg.get_content()
        except: body_text = ''

    headers_dict = {}
    for k,v in msg.items():
        headers_dict[k] = v

    spf, dkim, dmarc = _parse_auth(headers_dict)
    chain = _parse_chain(msg)

    combined = (body_text or '') + (body_html or '')
    urls = _extract_urls(combined)
    all_hdr_text = '\n'.join(f'{k}: {v}' for k,v in msg.items())
    ips = _extract_ips(all_hdr_text)

    checks = _security_checks(msg, from_display, from_email, reply_to, body_html)
    risk_score, risk_factors = _risk_score(checks, spf, dkim, dmarc, urls, attachments)
    techniques = _phishing_techniques(checks, spf, urls, attachments, body_text)
    mitre = _mitre(techniques, attachments)

    domains = list(set(re.findall(r'https?://([^/\s?#]+)', ' '.join(urls))))
    emails_found = list(set(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', combined)))

    iocs = {'ips': ips, 'domains': domains, 'urls': urls, 'emails': emails_found, 'hashes': [a['sha256'] for a in attachments]}

    timeline = []
    date_str = metadata.get('date','')
    if date_str:
        try:
            timeline.append({'event': 'Email Created / Sent', 'timestamp': parsedate_to_datetime(date_str).isoformat(), 'detail': ''})
        except: pass
    for i, hop in enumerate(chain):
        if hop.get('timestamp'):
            label = 'Mail Relay' if i < len(chain)-1 else 'Inbox Delivery'
            timeline.append({'event': label, 'timestamp': hop['timestamp'], 'detail': hop.get('by','') or ''})

    risk_label = 'CRITICAL' if risk_score>=70 else 'HIGH' if risk_score>=40 else 'MEDIUM' if risk_score>=20 else 'LOW'
    fname = filepath.replace('\\','/').split('/')[-1]

    return {
        'filename': fname,
        'metadata': metadata,
        'authentication': {'spf': spf, 'dkim': dkim, 'dmarc': dmarc},
        'received_chain': chain,
        'urls': urls,
        'attachments': attachments,
        'ips': ips,
        'iocs': iocs,
        'security_checks': checks,
        'phishing_techniques': techniques,
        'mitre_techniques': mitre,
        'risk_score': risk_score,
        'risk_label': risk_label,
        'risk_factors': risk_factors,
        'body_text_excerpt': (body_text or '')[:600],
        'timeline': timeline,
        'raw_headers': all_hdr_text[:2500],
    }
'''

with open('src/parsers/email_parser.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print("email_parser.py written.")