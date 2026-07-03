content = r'''# src/parsers/email_parser.py
import email
import email.policy
import hashlib
import re
import os
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

def _security_checks(msg_obj, from_display, from_email, reply_to, body_html):
    from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ''
    reply_domain = reply_to.split('@')[-1].lower() if reply_to and '@' in reply_to else ''
    brands = ['microsoft','google','apple','amazon','paypal','facebook','netflix','linkedin','dropbox','docusign','dhl','fedex','irs','usps']
    disp = (from_display or '').lower()
    spoofing = any(b in disp for b in brands) and not any(b in from_domain for b in brands)
    html = body_html or ''
    msg_id = (msg_obj.get('Message-ID','') if msg_obj and hasattr(msg_obj,'get') else '') or ''
    return {
        'external_sender': bool(from_domain),
        'reply_to_mismatch': bool(reply_domain and reply_domain != from_domain),
        'display_name_spoofing': spoofing,
        'has_html_form': '<form' in html.lower(),
        'has_javascript': '<script' in html.lower() or 'javascript:' in html.lower(),
        'has_tracking_pixel': bool(re.search(r'<img[^>]+(?:width=["\']?1["\']?|height=["\']?1["\']?)', html, re.I)),
        'has_remote_images': bool(re.search(r'<img[^>]+src=["\']https?://', html, re.I)),
        'invalid_message_id': not bool(re.match(r'<[^@>]+@[^@>]+>', msg_id)),
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

def _build_result(fname, metadata, auth_tuple, chain, urls, attachments, ips, body_text, body_html, headers_text, extra_flags=None):
    spf, dkim, dmarc = auth_tuple
    from_display = metadata.get('from_display','')
    from_email   = metadata.get('from_email','')
    reply_to     = metadata.get('reply_to','')
    checks = _security_checks(None, from_display, from_email, reply_to, body_html)
    if extra_flags:
        checks.update(extra_flags)
    risk_score, risk_factors = _risk_score(checks, spf, dkim, dmarc, urls, attachments)
    techniques = _phishing_techniques(checks, spf, urls, attachments, body_text)
    mitre = _mitre(techniques, attachments)
    domains = list(set(re.findall(r'https?://([^/\s?#]+)', ' '.join(urls))))
    emails_found = list(set(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', (body_text or '')+(body_html or ''))))
    iocs = {'ips': ips, 'domains': domains, 'urls': urls, 'emails': emails_found, 'hashes': [a['sha256'] for a in attachments]}
    timeline = []
    date_str = metadata.get('date','')
    if date_str:
        try: timeline.append({'event': 'Email Created / Sent', 'timestamp': parsedate_to_datetime(date_str).isoformat(), 'detail': ''})
        except: timeline.append({'event': 'Email Created / Sent', 'timestamp': str(date_str), 'detail': ''})
    for i, hop in enumerate(chain):
        if hop.get('timestamp'):
            label = 'Mail Relay' if i < len(chain)-1 else 'Inbox Delivery'
            timeline.append({'event': label, 'timestamp': hop['timestamp'], 'detail': hop.get('by','') or ''})
    risk_label = 'CRITICAL' if risk_score>=70 else 'HIGH' if risk_score>=40 else 'MEDIUM' if risk_score>=20 else 'LOW'
    return {
        'filename': fname,
        'metadata': metadata,
        'authentication': {'spf': spf, 'dkim': dkim, 'dmarc': dmarc},
        'received_chain': chain,
        'urls': urls, 'attachments': attachments, 'ips': ips, 'iocs': iocs,
        'security_checks': checks,
        'phishing_techniques': techniques,
        'mitre_techniques': mitre,
        'risk_score': risk_score, 'risk_label': risk_label, 'risk_factors': risk_factors,
        'body_text_excerpt': (body_text or '')[:600],
        'timeline': timeline,
        'raw_headers': (headers_text or '')[:2500],
    }


def parse_email_file(filepath):
    try:
        with open(filepath, 'rb') as f: raw = f.read()
    except Exception as e: return {'error': str(e)}
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as e: return {'error': f'Failed to parse email: {e}'}

    from_raw = msg.get('From','')
    from_display, from_email = parseaddr(from_raw)
    _, reply_to = parseaddr(msg.get('Reply-To',''))
    _, return_path = parseaddr(msg.get('Return-Path',''))

    metadata = {
        'from_display': from_display or '', 'from_email': from_email or from_raw,
        'to': msg.get('To',''), 'cc': msg.get('CC','') or msg.get('Cc',''),
        'bcc': msg.get('BCC','') or msg.get('Bcc',''),
        'reply_to': reply_to or msg.get('Reply-To',''), 'return_path': return_path,
        'subject': msg.get('Subject',''), 'date': msg.get('Date',''),
        'message_id': msg.get('Message-ID',''), 'mime_version': msg.get('MIME-Version',''),
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
                fname2 = part.get_filename() or 'unknown'
                try:
                    data = part.get_payload(decode=True) or b''
                    ext = ('.' + fname2.rsplit('.',1)[-1].lower()) if '.' in fname2 else ''
                    attachments.append({
                        'filename': fname2, 'extension': ext, 'size': len(data),
                        'mime_type': ct, 'sha256': _sha256(data), 'md5': _md5(data), 'sha1': _sha1(data),
                        'has_macros': ext in ('.doc','.docm','.xls','.xlsm','.ppt','.pptm'),
                        'is_executable': ext in ('.exe','.bat','.cmd','.ps1','.vbs','.js','.jar','.scr'),
                        'is_compressed': ext in ('.zip','.rar','.7z','.gz','.tar'),
                    })
                except: pass
    else:
        try: body_text = msg.get_content()
        except: body_text = ''

    headers_dict = {k: v for k, v in msg.items()}
    spf, dkim, dmarc = _parse_auth(headers_dict)
    chain = _parse_chain(msg)
    combined = (body_text or '') + (body_html or '')
    urls = _extract_urls(combined)
    all_hdr_text = '\n'.join(f'{k}: {v}' for k, v in msg.items())
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
        try: timeline.append({'event': 'Email Created / Sent', 'timestamp': parsedate_to_datetime(date_str).isoformat(), 'detail': ''})
        except: pass
    for i, hop in enumerate(chain):
        if hop.get('timestamp'):
            label = 'Mail Relay' if i < len(chain)-1 else 'Inbox Delivery'
            timeline.append({'event': label, 'timestamp': hop['timestamp'], 'detail': hop.get('by','') or ''})
    risk_label = 'CRITICAL' if risk_score>=70 else 'HIGH' if risk_score>=40 else 'MEDIUM' if risk_score>=20 else 'LOW'
    fname = filepath.replace('\\','/').split('/')[-1]
    return {
        'filename': fname, 'metadata': metadata,
        'authentication': {'spf': spf, 'dkim': dkim, 'dmarc': dmarc},
        'received_chain': chain, 'urls': urls, 'attachments': attachments, 'ips': ips, 'iocs': iocs,
        'security_checks': checks, 'phishing_techniques': techniques, 'mitre_techniques': mitre,
        'risk_score': risk_score, 'risk_label': risk_label, 'risk_factors': risk_factors,
        'body_text_excerpt': (body_text or '')[:600], 'timeline': timeline, 'raw_headers': all_hdr_text[:2500],
    }


def parse_msg_file(filepath):
    try:
        import extract_msg as emsg
    except ImportError:
        return {'error': 'extract-msg not installed. Run: pip install extract-msg'}
    try:
        msg = emsg.Message(filepath)
        from_raw = msg.sender or ''
        from_display = ''
        from_email = from_raw
        if '<' in from_raw and '>' in from_raw:
            parts = from_raw.rsplit('<', 1)
            from_display = parts[0].strip().strip('"')
            from_email = parts[1].rstrip('>').strip()
        metadata = {
            'from_display': from_display, 'from_email': from_email,
            'to': msg.to or '', 'cc': msg.cc or '', 'bcc': '',
            'reply_to': '', 'return_path': '',
            'subject': msg.subject or '',
            'date': str(msg.date) if msg.date else '',
            'message_id': '', 'mime_version': '', 'mailer': '', 'priority': '', 'organization': '',
        }
        body_text = msg.body or ''
        body_html = ''
        try: body_html = msg.htmlBody or ''
        except: pass
        attachments = []
        for att in (msg.attachments or []):
            try:
                data = att.data or b''
                fname2 = getattr(att, 'longFilename', None) or getattr(att, 'shortFilename', None) or 'unknown'
                ext = ('.' + fname2.rsplit('.',1)[-1].lower()) if '.' in fname2 else ''
                attachments.append({
                    'filename': fname2, 'extension': ext, 'size': len(data),
                    'mime_type': getattr(att, 'mimetype', '') or '',
                    'sha256': _sha256(data), 'md5': _md5(data), 'sha1': _sha1(data),
                    'has_macros': ext in ('.doc','.docm','.xls','.xlsm','.ppt','.pptm'),
                    'is_executable': ext in ('.exe','.bat','.cmd','.ps1','.vbs','.js','.jar','.scr'),
                    'is_compressed': ext in ('.zip','.rar','.7z','.gz','.tar'),
                })
            except: pass
        headers_text = ''
        headers_dict = {}
        try:
            import email as _email
            hdr_str = str(msg.header) if hasattr(msg, 'header') and msg.header else ''
            headers_text = hdr_str
            parsed = _email.message_from_string(hdr_str)
            headers_dict = {k: v for k, v in parsed.items()}
        except: pass
        spf, dkim, dmarc = _parse_auth(headers_dict)
        combined = (body_text or '') + (body_html or '')
        urls = _extract_urls(combined)
        ips = _extract_ips(headers_text)
        checks = _security_checks(None, from_display, from_email, metadata.get('reply_to',''), body_html)
        risk_score, risk_factors = _risk_score(checks, spf, dkim, dmarc, urls, attachments)
        techniques = _phishing_techniques(checks, spf, urls, attachments, body_text)
        mitre = _mitre(techniques, attachments)
        domains = list(set(re.findall(r'https?://([^/\s?#]+)', ' '.join(urls))))
        emails_found = list(set(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', combined)))
        iocs = {'ips': ips, 'domains': domains, 'urls': urls, 'emails': emails_found, 'hashes': [a['sha256'] for a in attachments]}
        timeline = []
        if metadata.get('date'):
            timeline.append({'event': 'Email Created / Sent', 'timestamp': str(metadata['date']), 'detail': ''})
        risk_label = 'CRITICAL' if risk_score>=70 else 'HIGH' if risk_score>=40 else 'MEDIUM' if risk_score>=20 else 'LOW'
        fname = filepath.replace('\\','/').split('/')[-1]
        return {
            'filename': fname, 'metadata': metadata,
            'authentication': {'spf': spf, 'dkim': dkim, 'dmarc': dmarc},
            'received_chain': [], 'urls': urls, 'attachments': attachments, 'ips': ips, 'iocs': iocs,
            'security_checks': checks, 'phishing_techniques': techniques, 'mitre_techniques': mitre,
            'risk_score': risk_score, 'risk_label': risk_label, 'risk_factors': risk_factors,
            'body_text_excerpt': (body_text or '')[:600], 'timeline': timeline, 'raw_headers': headers_text[:2500],
        }
    except Exception as e:
        return {'error': f'Failed to parse .msg file: {e}'}


def parse_screenshot(filepath):
    text = ''
    method = ''
    try:
        from PIL import Image
        import pytesseract
        img = Image.open(filepath)
        text = pytesseract.image_to_string(img)
        method = 'OCR (pytesseract)'
    except ImportError:
        pass
    except Exception as e:
        pass

    if not text.strip():
        try:
            import base64, requests as _req
            with open(filepath, 'rb') as f: img_b64 = base64.b64encode(f.read()).decode()
            resp = _req.post('http://localhost:11434/api/generate', json={
                'model': 'llava', 'stream': False,
                'prompt': 'Extract ALL text visible in this email screenshot. Include every word, URL, email address, sender name, subject line, and any suspicious indicators. Output only the extracted text.',
                'images': [img_b64]
            }, timeout=60)
            if resp.status_code == 200:
                text = resp.json().get('response','')
                method = 'Ollama llava vision'
        except: pass

    if not text.strip():
        return {
            'error': 'Could not extract text from screenshot. '
                     'Install Tesseract OCR: winget install UB-Mannheim.TesseractOCR '
                     'then restart terminal. Or pull vision model: ollama pull llava'
        }

    urls = _extract_urls(text)
    ips  = _extract_ips(text)
    emails_found = list(set(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', text)))

    bt = text.lower()
    risk_score = 0; risk_factors = []
    sus_urls = sum(1 for u in urls if re.search(r'login|verify|account|secure|update|confirm|password|credential|signin|reset',u,re.I))
    if sus_urls: add=min(30,sus_urls*10); risk_score+=add; risk_factors.append(f'{sus_urls} suspicious URL(s) (+{add})')
    if any(w in bt for w in ['urgent','action required','suspended','verify now','immediately']): risk_score+=15; risk_factors.append('Urgency language (+15)')
    if any(w in bt for w in ['password','login','credential','verify your']): risk_score+=20; risk_factors.append('Credential keywords (+20)')
    if any(w in bt for w in ['invoice','payment','wire transfer']): risk_score+=15; risk_factors.append('Financial keywords (+15)')
    if emails_found: risk_score+=5; risk_factors.append('Email addresses found (+5)')

    techniques = []
    if sus_urls: techniques.append('Malicious Link')
    if any(w in bt for w in ['password','credential','login']): techniques.append('Credential Harvesting')
    if any(w in bt for w in ['urgent','action required']): techniques.append('Urgency / Pressure Tactics')
    if any(w in bt for w in ['invoice','payment','wire']): techniques.append('Invoice Fraud / BEC')

    mitre = ['T1566', 'T1566.002'] if sus_urls else ['T1566']
    iocs = {'ips': ips, 'domains': list(set(re.findall(r'https?://([^/\s?#]+)', ' '.join(urls)))), 'urls': urls, 'emails': emails_found, 'hashes': []}
    risk_label = 'CRITICAL' if risk_score>=70 else 'HIGH' if risk_score>=40 else 'MEDIUM' if risk_score>=20 else 'LOW'
    fname = filepath.replace('\\','/').split('/')[-1]

    subject_m = re.search(r'subject[:\s]+(.+)', text, re.I)
    from_m    = re.search(r'from[:\s]+(.+)', text, re.I)

    return {
        'filename': fname,
        'analysis_method': f'Screenshot — text extracted via {method}',
        'metadata': {
            'from_display': from_m.group(1).strip()[:80] if from_m else '',
            'from_email': '', 'to': '', 'cc': '', 'bcc': '', 'reply_to': '', 'return_path': '',
            'subject': subject_m.group(1).strip()[:120] if subject_m else '',
            'date': '', 'message_id': '', 'mime_version': '', 'mailer': '', 'priority': '', 'organization': '',
        },
        'authentication': {
            'spf':  {'result': 'unknown (screenshot)', 'domain': None},
            'dkim': {'result': 'unknown (screenshot)', 'domain': None, 'selector': None},
            'dmarc':{'result': 'unknown (screenshot)', 'policy': None},
        },
        'received_chain': [], 'urls': urls, 'attachments': [], 'ips': ips, 'iocs': iocs,
        'security_checks': {
            'external_sender': bool(emails_found), 'reply_to_mismatch': False, 'display_name_spoofing': False,
            'has_html_form': False, 'has_javascript': False, 'has_tracking_pixel': False,
            'has_remote_images': False, 'invalid_message_id': True,
        },
        'phishing_techniques': techniques, 'mitre_techniques': mitre,
        'risk_score': min(100, risk_score), 'risk_label': risk_label, 'risk_factors': risk_factors,
        'body_text_excerpt': text[:600], 'timeline': [], 'raw_headers': '',
    }


IMAGE_EXTS = {'.png', '.jpg', '.jpeg', '.webp', '.bmp', '.gif', '.tiff', '.tif'}

def parse_file(filepath):
    ext = ('.' + filepath.rsplit('.', 1)[-1].lower()) if '.' in filepath else ''
    if ext == '.eml':   return parse_email_file(filepath)
    if ext == '.msg':   return parse_msg_file(filepath)
    if ext in IMAGE_EXTS: return parse_screenshot(filepath)
    return {'error': f'Unsupported file type: {ext}. Supported: .eml, .msg, .png, .jpg, .jpeg, .webp, .bmp'}
'''

with open('src/parsers/email_parser.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print("email_parser.py v2 written.")