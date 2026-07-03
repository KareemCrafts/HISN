# src/parsers/email_parser.py
import email
import email.policy
import hashlib
import re
import os
from email.utils import parsedate_to_datetime, parseaddr

_SHA256  = lambda d: hashlib.sha256(d).hexdigest()
_MD5     = lambda d: hashlib.md5(d).hexdigest()
_SHA1    = lambda d: hashlib.sha1(d).hexdigest()
_URL_RE  = re.compile(r"https?://\S+")
_IP_RE   = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_MAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_PRIV    = ("10.", "192.168.", "172.", "127.", "0.", "::1", "169.254.")

def _extract_urls(text):
    if not text: return []
    raw = _URL_RE.findall(text)
    out = []
    for u in raw:
        while u and u[-1] in ".,;:)'\"}>]":
            u = u[:-1]
        if u and len(u) > 8:
            out.append(u)
    return list(set(out))

def _extract_ips(text):
    if not text: return []
    return list(set(ip for ip in _IP_RE.findall(text)
                    if not any(ip.startswith(p) for p in _PRIV)))

def _parse_auth(headers):
    hdr = headers.get("Authentication-Results","") or headers.get("ARC-Authentication-Results","") or ""
    def _get(key):
        m = re.search(key + r"=(\w+)", hdr, re.I)
        return m.group(1).lower() if m else "none"
    spf   = {"result": _get("spf"),  "domain": None}
    dkim  = {"result": _get("dkim"), "domain": None, "selector": None}
    dmarc = {"result": _get("dmarc"), "policy": None}
    m = re.search(r"smtp\.mailfrom=([^\s;]+)", hdr, re.I)
    if m: spf["domain"] = m.group(1)
    m = re.search(r"header\.i=@?([^\s;]+)", hdr, re.I)
    if m: dkim["domain"] = m.group(1)
    m = re.search(r"header\.s=([^\s;]+)", hdr, re.I)
    if m: dkim["selector"] = m.group(1)
    m = re.search(r"\bp=(\w+)", hdr, re.I)
    if m: dmarc["policy"] = m.group(1)
    return spf, dkim, dmarc

def _parse_chain(msg):
    chain = []
    prev_ts = None
    for raw in reversed(msg.get_all("Received") or []):
        hop = {"from": None, "by": None, "ip": None, "timestamp": None, "delay_seconds": None}
        m = re.search(r"from\s+(\S+)", raw, re.I)
        if m: hop["from"] = m.group(1)
        m = re.search(r"by\s+(\S+)", raw, re.I)
        if m: hop["by"] = m.group(1)
        m = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", raw)
        if m: hop["ip"] = m.group(1)
        m = re.search(r";\s*(.+)$", raw, re.M)
        if m:
            try:
                ts = parsedate_to_datetime(m.group(1).strip())
                hop["timestamp"] = ts.isoformat()
                if prev_ts is not None:
                    hop["delay_seconds"] = int(ts.timestamp() - prev_ts)
                prev_ts = ts.timestamp()
            except Exception:
                pass
        chain.append(hop)
    return chain

def _security_checks(from_display, from_email, reply_to, body_html, msg_id):
    from_domain  = from_email.split("@")[-1].lower() if "@" in from_email else ""
    reply_domain = reply_to.split("@")[-1].lower() if reply_to and "@" in reply_to else ""
    brands = ["microsoft","google","apple","amazon","paypal","facebook",
              "netflix","linkedin","dropbox","docusign","dhl","fedex","irs","usps"]
    spoofing = any(b in (from_display or "").lower() for b in brands) and \
               not any(b in from_domain for b in brands)
    html = body_html or ""
    return {
        "external_sender":      bool(from_domain),
        "reply_to_mismatch":    bool(reply_domain and reply_domain != from_domain),
        "display_name_spoofing": spoofing,
        "has_html_form":        "<form" in html.lower(),
        "has_javascript":       "<script" in html.lower() or "javascript:" in html.lower(),
        "has_tracking_pixel":   bool(re.search(r"<img[^>]+(?:width=[\"']?1[\"']?|height=[\"']?1[\"']?)", html, re.I)),
        "has_remote_images":    bool(re.search(r"<img[^>]+src=[\"']https?://", html, re.I)),
        "invalid_message_id":   not bool(re.match(r"<[^@>]+@[^@>]+>", msg_id or "")),
    }

def _risk_score(checks, spf, dkim, dmarc, urls, attachments):
    score = 0; factors = []
    if spf["result"] in ("fail","softfail"):  score+=20; factors.append(f"SPF {spf['result']} (+20)")
    if dkim["result"] == "fail":              score+=15; factors.append("DKIM fail (+15)")
    if dmarc["result"] == "fail":             score+=10; factors.append("DMARC fail (+10)")
    if checks.get("reply_to_mismatch"):        score+=20; factors.append("Reply-To mismatch (+20)")
    if checks.get("display_name_spoofing"):    score+=25; factors.append("Display name spoofing (+25)")
    if checks.get("external_sender"):          score+=5;  factors.append("External sender (+5)")
    sus = sum(1 for u in urls if re.search(r"login|verify|account|secure|update|confirm|password|credential|signin|reset", u, re.I))
    if sus: add=min(30,sus*10); score+=add; factors.append(f"{sus} suspicious URL(s) (+{add})")
    if checks.get("has_html_form"):            score+=15; factors.append("Credential harvesting form (+15)")
    if checks.get("has_javascript"):           score+=10; factors.append("JavaScript in body (+10)")
    for a in attachments:
        if a.get("is_executable"): score+=30; factors.append(f"Executable: {a['filename']} (+30)"); break
        if a.get("has_macros"):    score+=25; factors.append(f"Macro file: {a['filename']} (+25)"); break
    return min(100, score), factors

def _phishing_techniques(checks, spf, urls, attachments, body_text):
    t = []; bt = (body_text or "").lower()
    if checks.get("display_name_spoofing") or spf["result"] in ("fail","softfail"): t.append("Spoofing")
    if checks.get("reply_to_mismatch"):   t.append("Reply-To Hijacking")
    if urls:                              t.append("Malicious Link")
    if checks.get("has_html_form") or any(w in bt for w in ["password","login","sign in","verify your","credential"]): t.append("Credential Harvesting")
    if any(w in bt for w in ["invoice","payment","wire transfer","bank account"]): t.append("Invoice Fraud / BEC")
    if any(a.get("has_macros") for a in attachments):     t.append("Malicious Attachment (Macro)")
    if any(a.get("is_executable") for a in attachments):  t.append("Malicious Attachment (Executable)")
    if any(w in bt for w in ["urgent","immediately","action required","suspended","verify now"]): t.append("Urgency / Pressure Tactics")
    if any(w in bt for w in ["gift card","amazon gift","itunes"]): t.append("Gift Card Scam")
    if any(w in bt for w in ["mfa","authenticator","two-factor","2fa","verification code"]): t.append("Fake MFA Request")
    return t

def _mitre(techniques, attachments):
    m = {"T1566"}
    if attachments: m.add("T1566.001")
    if "Malicious Link" in techniques or "Credential Harvesting" in techniques: m.add("T1566.002")
    if "Spoofing" in techniques or "Reply-To Hijacking" in techniques: m.add("T1656")
    if "Credential Harvesting" in techniques: m.add("T1598")
    if attachments: m.add("T1204.002")
    return sorted(m)

def _parse_body_parts(msg):
    body_text = ""; body_html = ""; attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition",""))
            if ct == "text/plain" and "attachment" not in cd:
                try: body_text = part.get_content()
                except Exception: body_text = ""
            elif ct == "text/html" and "attachment" not in cd:
                try: body_html = part.get_content()
                except Exception: body_html = ""
            elif "attachment" in cd or part.get_filename():
                fname = part.get_filename() or "unknown"
                try:
                    data = part.get_payload(decode=True) or b""
                    ext = ("." + fname.rsplit(".",1)[-1].lower()) if "." in fname else ""
                    attachments.append({
                        "filename": fname, "extension": ext, "size": len(data), "mime_type": ct,
                        "sha256": _SHA256(data), "md5": _MD5(data), "sha1": _SHA1(data),
                        "has_macros":    ext in (".doc",".docm",".xls",".xlsm",".ppt",".pptm"),
                        "is_executable": ext in (".exe",".bat",".cmd",".ps1",".vbs",".js",".jar",".scr"),
                        "is_compressed": ext in (".zip",".rar",".7z",".gz",".tar"),
                    })
                except Exception: pass
    else:
        try: body_text = msg.get_content()
        except Exception: body_text = ""
    return body_text, body_html, attachments

def _build_result(fname, meta, spf, dkim, dmarc, chain, urls, attachments, ips, body_text, body_html, hdr_text):
    checks = _security_checks(meta.get("from_display",""), meta.get("from_email",""),
                               meta.get("reply_to",""), body_html, meta.get("message_id",""))
    risk_score, risk_factors = _risk_score(checks, spf, dkim, dmarc, urls, attachments)
    techniques = _phishing_techniques(checks, spf, urls, attachments, body_text)
    mitre = _mitre(techniques, attachments)
    domains = list(set(re.findall(r"https?://([^/\s?#]+)", " ".join(urls))))
    emails_found = list(set(_MAIL_RE.findall((body_text or "") + (body_html or ""))))
    iocs = {"ips": ips, "domains": domains, "urls": urls, "emails": emails_found,
            "hashes": [a["sha256"] for a in attachments]}
    timeline = []
    date_str = meta.get("date","")
    if date_str:
        try: timeline.append({"event": "Email Created / Sent", "timestamp": parsedate_to_datetime(date_str).isoformat(), "detail": ""})
        except Exception: timeline.append({"event": "Email Created / Sent", "timestamp": str(date_str), "detail": ""})
    for i, hop in enumerate(chain):
        if hop.get("timestamp"):
            label = "Mail Relay" if i < len(chain)-1 else "Inbox Delivery"
            timeline.append({"event": label, "timestamp": hop["timestamp"], "detail": hop.get("by","") or ""})
    risk_label = "CRITICAL" if risk_score>=70 else "HIGH" if risk_score>=40 else "MEDIUM" if risk_score>=20 else "LOW"
    _r = {
        "filename": fname, "metadata": meta,
        "authentication": {"spf": spf, "dkim": dkim, "dmarc": dmarc},
        "received_chain": chain, "urls": urls, "attachments": attachments, "ips": ips, "iocs": iocs,
        "security_checks": checks, "phishing_techniques": techniques, "mitre_techniques": mitre,
        "risk_score": risk_score, "risk_label": risk_label, "risk_factors": risk_factors,
        "body_text_excerpt": (body_text or "")[:600], "timeline": timeline,
        "raw_headers": (hdr_text or "")[:2500],
    }
    try:
        from src.detection.hisn_engine import analyze_email as _ae
        _eng = _ae(metadata=meta, authentication={'spf':spf,'dkim':dkim,'dmarc':dmarc},
            urls=urls, attachments=attachments, body_text=body_text, body_html=body_html,
            security_checks=checks, received_chain=chain)
        _r.update({'risk_score':_eng['score'],'risk_label':_eng['label'],
            'risk_factors':_eng['risk_factors'],'phishing_techniques':_eng['phishing_techniques'],
            'mitre_techniques':_eng['mitre_techniques'],'findings':_eng['findings'],
            'verdict_summary':_eng['verdict_summary'],'confidence':_eng['confidence']})
    except Exception:
        import traceback; traceback.print_exc()
    return _r

def parse_email_file(filepath):
    try:
        with open(filepath, "rb") as f: raw = f.read()
    except Exception as e: return {"error": str(e)}
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as e: return {"error": f"Failed to parse email: {e}"}
    from_raw = msg.get("From","")
    from_display, from_email = parseaddr(from_raw)
    _, reply_to    = parseaddr(msg.get("Reply-To",""))
    _, return_path = parseaddr(msg.get("Return-Path",""))
    meta = {
        "from_display": from_display or "", "from_email": from_email or from_raw,
        "to":           msg.get("To",""), "cc": msg.get("CC","") or msg.get("Cc",""),
        "bcc":          msg.get("BCC","") or msg.get("Bcc",""),
        "reply_to":     reply_to or msg.get("Reply-To",""), "return_path": return_path,
        "subject":      msg.get("Subject",""), "date": msg.get("Date",""),
        "message_id":   msg.get("Message-ID",""), "mime_version": msg.get("MIME-Version",""),
        "mailer":       msg.get("X-Mailer","") or msg.get("User-Agent",""),
        "priority":     msg.get("X-Priority","") or msg.get("Importance",""),
        "organization": msg.get("Organization",""),
    }
    body_text, body_html, attachments = _parse_body_parts(msg)
    headers_dict = {k: v for k, v in msg.items()}
    spf, dkim, dmarc = _parse_auth(headers_dict)
    chain = _parse_chain(msg)
    combined = (body_text or "") + (body_html or "")
    urls = _extract_urls(combined)
    hdr_text = "\n".join(f"{k}: {v}" for k, v in msg.items())
    ips = _extract_ips(hdr_text)
    fname = filepath.replace("\\","/").split("/")[-1]
    return _build_result(fname, meta, spf, dkim, dmarc, chain, urls, attachments, ips, body_text, body_html, hdr_text)

def parse_msg_file(filepath):
    try:
        import extract_msg as emsg
    except ImportError:
        return {"error": "extract-msg not installed. Run: pip install extract-msg"}
    try:
        msg = emsg.Message(filepath)
        from_raw = msg.sender or ""
        from_display = ""; from_email = from_raw
        if "<" in from_raw and ">" in from_raw:
            parts = from_raw.rsplit("<", 1)
            from_display = parts[0].strip().strip('"')
            from_email   = parts[1].rstrip(">").strip()
        meta = {
            "from_display": from_display, "from_email": from_email,
            "to": msg.to or "", "cc": msg.cc or "", "bcc": "",
            "reply_to": "", "return_path": "",
            "subject":    msg.subject or "",
            "date":       str(msg.date) if msg.date else "",
            "message_id": "", "mime_version": "", "mailer": "", "priority": "", "organization": "",
        }
        body_text = msg.body or ""; body_html = ""
        try: body_html = msg.htmlBody or ""
        except Exception: pass
        attachments = []
        for att in (msg.attachments or []):
            try:
                data  = att.data or b""
                fname2 = getattr(att,"longFilename",None) or getattr(att,"shortFilename",None) or "unknown"
                ext   = ("." + fname2.rsplit(".",1)[-1].lower()) if "." in fname2 else ""
                attachments.append({
                    "filename": fname2, "extension": ext, "size": len(data),
                    "mime_type": getattr(att,"mimetype","") or "",
                    "sha256": _SHA256(data), "md5": _MD5(data), "sha1": _SHA1(data),
                    "has_macros":    ext in (".doc",".docm",".xls",".xlsm",".ppt",".pptm"),
                    "is_executable": ext in (".exe",".bat",".cmd",".ps1",".vbs",".js",".jar",".scr"),
                    "is_compressed": ext in (".zip",".rar",".7z",".gz",".tar"),
                })
            except Exception: pass
        hdr_text = ""; headers_dict = {}
        try:
            import email as _em
            hdr_str = str(msg.header) if hasattr(msg,"header") and msg.header else ""
            hdr_text = hdr_str
            parsed = _em.message_from_string(hdr_str)
            headers_dict = {k: v for k, v in parsed.items()}
        except Exception: pass
        spf, dkim, dmarc = _parse_auth(headers_dict)
        combined = (body_text or "") + (body_html or "")
        urls = _extract_urls(combined)
        ips  = _extract_ips(hdr_text)
        fname = filepath.replace("\\","/").split("/")[-1]
        return _build_result(fname, meta, spf, dkim, dmarc, [], urls, attachments, ips, body_text, body_html, hdr_text)
    except Exception as e:
        return {"error": f"Failed to parse .msg: {e}"}

def parse_screenshot(filepath):
    text = ""; method = ""
    try:
        from PIL import Image
        import pytesseract
        for _p in [
            "C:\\Program Files\\Tesseract-OCR\\tesseract.exe",
            "C:\\Program Files (x86)\\Tesseract-OCR\\tesseract.exe",
            os.path.join("C:\\Users", os.environ.get("USERNAME",""), "AppData\\Local\\Programs\\Tesseract-OCR\\tesseract.exe"),
        ]:
            if os.path.exists(_p):
                pytesseract.pytesseract.tesseract_cmd = _p
                break
        img  = Image.open(filepath)
        text = pytesseract.image_to_string(img)
        method = "OCR (pytesseract)"
    except ImportError: pass
    except Exception: pass

    if not text.strip():
        try:
            import base64, requests as _req
            with open(filepath, "rb") as f: img_b64 = base64.b64encode(f.read()).decode()
            resp = _req.post("http://localhost:11434/api/generate", json={
                "model": "llava", "stream": False,
                "prompt": "Extract ALL text from this email screenshot. Include sender, subject, URLs, and any suspicious content. Output plain text only.",
                "images": [img_b64]
            }, timeout=60)
            if resp.status_code == 200:
                text = resp.json().get("response",""); method = "Ollama llava vision"
        except Exception: pass

    if not text.strip():
        return {"error": "Could not extract text. Install Tesseract: winget install UB-Mannheim.TesseractOCR then restart terminal. Or: ollama pull llava"}

    urls = _extract_urls(text); ips = _extract_ips(text)
    emails_found = list(set(_MAIL_RE.findall(text)))
    bt = text.lower(); risk_score = 0; risk_factors = []
    sus = sum(1 for u in urls if re.search(r"login|verify|account|secure|update|confirm|password|credential|signin|reset", u, re.I))
    if sus: add=min(30,sus*10); risk_score+=add; risk_factors.append(f"{sus} suspicious URL(s) (+{add})")
    if any(w in bt for w in ["urgent","action required","suspended","verify now","immediately"]): risk_score+=15; risk_factors.append("Urgency language (+15)")
    if any(w in bt for w in ["password","login","credential","verify your"]): risk_score+=20; risk_factors.append("Credential keywords (+20)")
    if any(w in bt for w in ["invoice","payment","wire transfer"]): risk_score+=15; risk_factors.append("Financial keywords (+15)")
    if emails_found: risk_score+=5; risk_factors.append("Email addresses found (+5)")
    techniques = []
    if sus:                                             techniques.append("Malicious Link")
    if any(w in bt for w in ["password","credential","login"]): techniques.append("Credential Harvesting")
    if any(w in bt for w in ["urgent","action required"]): techniques.append("Urgency / Pressure Tactics")
    if any(w in bt for w in ["invoice","payment","wire"]): techniques.append("Invoice Fraud / BEC")
    mitre = ["T1566","T1566.002"] if sus else ["T1566"]
    iocs = {"ips": ips, "domains": list(set(re.findall(r"https?://([^/\s?#]+)"," ".join(urls)))),
            "urls": urls, "emails": emails_found, "hashes": []}
    risk_label = "CRITICAL" if risk_score>=70 else "HIGH" if risk_score>=40 else "MEDIUM" if risk_score>=20 else "LOW"
    fname = filepath.replace("\\","/").split("/")[-1]
    sm = re.search(r"subject[:\s]+(.+)", text, re.I); fm = re.search(r"from[:\s]+(.+)", text, re.I)
    return {
        "filename": fname, "analysis_method": f"Screenshot via {method}",
        "metadata": {
            "from_display": fm.group(1).strip()[:80] if fm else "",
            "from_email": "", "to": "", "cc": "", "bcc": "", "reply_to": "", "return_path": "",
            "subject": sm.group(1).strip()[:120] if sm else "",
            "date": "", "message_id": "", "mime_version": "", "mailer": "", "priority": "", "organization": "",
        },
        "authentication": {
            "spf":  {"result": "unknown (screenshot)", "domain": None},
            "dkim": {"result": "unknown (screenshot)", "domain": None, "selector": None},
            "dmarc":{"result": "unknown (screenshot)", "policy": None},
        },
        "received_chain": [], "urls": urls, "attachments": [], "ips": ips, "iocs": iocs,
        "security_checks": {
            "external_sender": bool(emails_found), "reply_to_mismatch": False,
            "display_name_spoofing": False, "has_html_form": False,
            "has_javascript": False, "has_tracking_pixel": False,
            "has_remote_images": False, "invalid_message_id": True,
        },
        "phishing_techniques": techniques, "mitre_techniques": mitre,
        "risk_score": min(100, risk_score), "risk_label": risk_label, "risk_factors": risk_factors,
        "body_text_excerpt": text[:600], "timeline": [], "raw_headers": "",
    }

_IMAGE_EXTS = {".png",".jpg",".jpeg",".webp",".bmp",".gif",".tiff",".tif"}

def parse_file(filepath):
    ext = ("." + filepath.rsplit(".",1)[-1].lower()) if "." in filepath else ""
    if ext == ".eml":       return parse_email_file(filepath)
    if ext == ".msg":       return parse_msg_file(filepath)
    if ext in _IMAGE_EXTS:  return parse_screenshot(filepath)
    return {"error": f"Unsupported: {ext}. Use .eml, .msg, or an image."}
