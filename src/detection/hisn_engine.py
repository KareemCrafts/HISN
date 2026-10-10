# src/detection/hisn_engine.py
import re

KNOWN_BRANDS = [
    "microsoft","google","apple","amazon","paypal","facebook","netflix","linkedin",
    "dropbox","docusign","dhl","fedex","irs","usps","ups","chase","wellsfargo",
    "office365","outlook","onedrive","sharepoint","teams","zoom","adobe","salesforce",
]

URL_SHORTENERS = [
    "bit.ly","tinyurl.com","t.co","ow.ly","short.io","buff.ly","rebrand.ly",
    "is.gd","cutt.ly","lnkd.in","tiny.cc","adf.ly","linktr.ee","rb.gy",
]

FREE_PROVIDERS = [
    "gmail.com","yahoo.com","hotmail.com","outlook.com","protonmail.com",
    "aol.com","icloud.com","mail.com","yandex.com","gmx.com","zoho.com",
]

SUSPICIOUS_URL_KW = [
    "login","verify","account","secure","update","confirm","password","credential",
    "signin","reset","validate","security","authenticate","billing","payment","invoice",
]

URGENCY_RE = [
    r"\burgent\b", r"\bimmediately\b", r"\baction required\b",
    r"\baccount.{0,12}(suspend|clos|terminat|deactivat|lock)",
    r"\bverify.{0,12}(now|immediately|today|account)",
    r"\bexpired?\b", r"\bsuspended\b",
    r"\bact.{0,6}now\b", r"\bconfirm.{0,12}identit",
]

PDF_HIGH_RISK = {
    "/JavaScript": ("Executes JavaScript within the PDF.", 38),
    "/JS":         ("Alias for /JavaScript.", 38),
    "/Launch":     ("Launches external application.", 32),
    "/AA":         ("Automatic Action trigger.", 26),
    "/XFA":        ("XML Forms Architecture.", 22),
    "/RichMedia":  ("Embeds rich media.", 18),
}

PDF_MEDIUM_RISK = {
    "/EmbeddedFile": ("Contains embedded files.", 20),
    "/OpenAction":   ("Executes action on open.", 14),
    "/AcroForm":     ("Interactive form.", 10),
    "/Encrypt":      ("Encrypted PDF.", 10),
}

MACRO_DANGEROUS_APIS = [
    "shell","createobject","wscript","powershell","urldownloadtofile",
    "winhttp","xmlhttp","regwrite","filesystemobject","getobject","winexec",
]

MACRO_AUTO_EXEC = [
    "autoopen","auto_open","autoexec","workbook_open","document_open",
    "auto_close","document_close","workbook_activate",
]


def _score_to_label(score):
    if score >= 75: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 25: return "MEDIUM"
    if score >= 8:  return "LOW"
    return "INFORMATIONAL"


def analyze_email(metadata, authentication, urls, attachments,
                  body_text, body_html, security_checks, received_chain):
    findings = []
    body = ((body_text or "") + " " + (body_html or "")).lower()
    subject = (metadata.get("subject") or "").lower()

    spf   = (authentication.get("spf")   or {}).get("result", "none").lower()
    dkim  = (authentication.get("dkim")  or {}).get("result", "none").lower()
    dmarc = (authentication.get("dmarc") or {}).get("result", "none").lower()

    from_display = (metadata.get("from_display") or "").lower()
    from_email   = (metadata.get("from_email")   or "").lower()
    from_domain  = from_email.split("@")[-1] if "@" in from_email else ""
    reply_to     = (metadata.get("reply_to")     or "").lower()
    reply_domain = reply_to.split("@")[-1] if "@" in reply_to else ""
    sc = security_checks or {}
    urls = urls or []
    attachments = attachments or []

    auth_failures = 0
    if spf in ("fail", "softfail"):
        pts = 20 if spf == "fail" else 12
        findings.append({"id":"AUTH-001","cat":"Authentication","sev":"HIGH",
            "title":f"SPF {spf.upper()}","detail":"Sending server not authorized.","score":pts,"mitre":["T1566","T1656"]})
        auth_failures += 1
    if dkim == "fail":
        findings.append({"id":"AUTH-002","cat":"Authentication","sev":"HIGH",
            "title":"DKIM Signature Invalid","detail":"Cryptographic signature invalid.","score":18,"mitre":["T1566","T1656"]})
        auth_failures += 1
    if dmarc == "fail":
        findings.append({"id":"AUTH-003","cat":"Authentication","sev":"HIGH",
            "title":"DMARC Policy Failed","detail":"From domain alignment failed.","score":12,"mitre":["T1566","T1656"]})
        auth_failures += 1
    if auth_failures == 3:
        findings.append({"id":"AUTH-004","cat":"Authentication","sev":"CRITICAL",
            "title":"Complete Authentication Failure","detail":"SPF, DKIM, and DMARC all failed.","score":20,"mitre":["T1566","T1656"]})

    impersonated_brand = None
    for brand in KNOWN_BRANDS:
        if brand in from_display and brand not in from_domain:
            impersonated_brand = brand
            findings.append({"id":"SENDER-001","cat":"Sender Deception","sev":"CRITICAL",
                "title":f"Brand Impersonation — {brand.title()}",
                "detail":f"Display name contains {brand} but sending domain is unrelated.",
                "score":30,"mitre":["T1656","T1566","T1598"]})
            break

    if reply_domain and reply_domain != from_domain:
        findings.append({"id":"SENDER-002","cat":"Sender Deception","sev":"HIGH",
            "title":"Reply-To Hijacking",
            "detail":f"Replies go to {reply_domain}, not {from_domain}.",
            "score":22,"mitre":["T1566","T1598"]})

    if sc.get("external_sender") and from_domain and from_domain not in FREE_PROVIDERS:
        findings.append({"id":"SE-EXT","cat":"Sender","sev":"LOW",
            "title":"External Sender","detail":f"Email from external domain {from_domain}.",
            "score":5,"mitre":["T1566"]})

    sus_url_count = 0
    for url in urls[:30]:
        ul = url.lower()
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ul):
            findings.append({"id":"URL-001","cat":"Malicious URL","sev":"CRITICAL",
                "title":"IP-Address URL","detail":f"Raw IP URL: {url[:70]}","score":28,"mitre":["T1566.002"]})
        for sh in URL_SHORTENERS:
            if sh in ul:
                findings.append({"id":"URL-002","cat":"Malicious URL","sev":"HIGH",
                    "title":f"URL Shortener — {sh}","detail":f"Hides destination: {url[:60]}","score":15,"mitre":["T1566.002"]})
                break
        sus_kws = [kw for kw in SUSPICIOUS_URL_KW if kw in ul]
        if sus_kws:
            sus_url_count += 1
            findings.append({"id":"URL-003","cat":"Malicious URL","sev":"HIGH",
                "title":f"Suspicious URL Keywords ({', '.join(sus_kws[:3])})",
                "detail":f"Phishing keywords in URL: {url[:80]}","score":min(10+len(sus_kws)*3,20),"mitre":["T1566.002","T1598"]})

    if sc.get("has_html_form"):
        pts = 35 if sus_url_count > 0 else 22
        findings.append({"id":"CRED-001","cat":"Credential Harvesting","sev":"HIGH",
            "title":"HTML Form in Email Body","detail":"Embedded form to capture credentials.","score":pts,"mitre":["T1598","T1539"]})

    urgency_hits = sum(1 for p in URGENCY_RE if re.search(p, body + " " + subject, re.IGNORECASE))
    if urgency_hits >= 1:
        findings.append({"id":"SE-001","cat":"Social Engineering","sev":"MEDIUM",
            "title":f"Urgency Tactics ({urgency_hits} indicator{'s' if urgency_hits>1 else ''})",
            "detail":"Artificial urgency to bypass critical thinking.","score":min(10+urgency_hits*2,22),"mitre":["T1566"]})

    if sc.get("has_javascript"):
        findings.append({"id":"ACTIVE-001","cat":"Active Content","sev":"HIGH",
            "title":"JavaScript in Email Body","detail":"JS embedded in HTML email.","score":20,"mitre":["T1566","T1204.001"]})

    for att in attachments:
        fname = att.get("filename","unknown")
        if att.get("is_executable"):
            findings.append({"id":"ATT-001","cat":"Malicious Attachment","sev":"CRITICAL",
                "title":f"Executable Attachment — {fname}","detail":"Executable file attached.","score":55,"mitre":["T1566.001","T1204.002"]})
        elif att.get("has_macros"):
            findings.append({"id":"ATT-002","cat":"Malicious Attachment","sev":"HIGH",
                "title":f"Macro-Enabled Document — {fname}","detail":"Macro-enabled Office file.","score":42,"mitre":["T1566.001","T1204.002"]})
        elif att.get("is_compressed"):
            findings.append({"id":"ATT-003","cat":"Suspicious Attachment","sev":"MEDIUM",
                "title":f"Archive Attachment — {fname}","detail":"Compressed archive attached.","score":14,"mitre":["T1566.001"]})

    if sc.get("invalid_message_id"):
        findings.append({"id":"HDR-001","cat":"Header Anomaly","sev":"LOW",
            "title":"Malformed Message-ID","detail":"Non-RFC-5322 Message-ID.","score":6,"mitre":["T1566"]})

    if sc.get("has_tracking_pixel"):
        findings.append({"id":"TRACK-001","cat":"Tracking","sev":"LOW",
            "title":"Email Tracking Pixel","detail":"Pixel confirms email open, leaks IP.","score":5,"mitre":["T1598"]})

    raw = sum(f["score"] for f in findings)
    ids = set(f["id"] for f in findings)
    cats = set(f["cat"] for f in findings)
    if "Authentication" in cats and "Sender Deception" in cats: raw += 10
    if "Credential Harvesting" in cats and "Malicious URL" in cats: raw += 10
    if "ATT-001" in ids or "ATT-002" in ids: raw += 8

    score = min(100, raw)
    mins = []
    if auth_failures == 3:               mins.append(50)
    if auth_failures >= 1 and impersonated_brand: mins.append(55)
    if "ATT-001" in ids:                 mins.append(62)
    if "ATT-002" in ids:                 mins.append(52)
    if "CRED-001" in ids:                mins.append(40)
    if "URL-001" in ids:                 mins.append(45)
    if impersonated_brand:               mins.append(35)
    if auth_failures >= 1:               mins.append(25)
    if "SENDER-002" in ids:              mins.append(25)
    if mins: score = max(score, max(mins))
    score = min(100, score)

    label = _score_to_label(score)
    mitre = set(["T1566"])
    for f in findings: mitre.update(f.get("mitre",[]))

    tech = []
    if "SENDER-001" in ids: tech.append("Brand Impersonation")
    if "AUTH-001" in ids or "AUTH-002" in ids: tech.append("Spoofing")
    if "SENDER-002" in ids: tech.append("Reply-To Hijacking")
    if "CRED-001" in ids: tech.append("Credential Harvesting")
    if "ATT-001" in ids: tech.append("Malicious Attachment (Executable)")
    if "ATT-002" in ids: tech.append("Malicious Attachment (Macro)")
    if "SE-001" in ids: tech.append("Urgency / Pressure Tactics")
    if re.search(r"invoice|payment|wire transfer|bank account", body): tech.append("Invoice Fraud / BEC")

    if score >= 75:
        verdict = "HIGH CONFIDENCE MALICIOUS — Do not interact with any content. Escalate to SOC."
        if impersonated_brand:
            verdict = f"HIGH CONFIDENCE PHISHING — Impersonates {impersonated_brand.title()}. Do not click links or open attachments."
    elif score >= 50:
        verdict = "LIKELY MALICIOUS — Treat all links and attachments as hostile."
    elif score >= 25:
        verdict = "SUSPICIOUS — Verify sender out-of-band before acting."
    elif score >= 8:
        verdict = "LOW RISK — Minor indicators. Exercise standard caution."
    else:
        verdict = "CLEAN — No significant threat indicators."

    risk_factors = [f"{f['title']} (+{f['score']})" for f in sorted(findings, key=lambda x: x["score"], reverse=True)[:6]]
    confidence = "HIGH" if len(findings) >= 4 else "MEDIUM" if len(findings) >= 2 else "LOW"

    return {
        "score": score, "label": label, "findings": findings,
        "mitre_techniques": sorted(mitre), "phishing_techniques": tech,
        "verdict_summary": verdict, "confidence": confidence,
        "risk_factors": risk_factors,
    }


def analyze_document(filename, file_type, macros_found, macro_streams,
                     suspicious_keywords, dangerous_tags, text_indicators,
                     sha256="", body_text_excerpt="", raw_macro_code=""):
    findings = []
    kws = [str(k).lower() for k in (suspicious_keywords or [])]
    macro_text = " ".join(kws)

    if file_type == "pdf":
        tag_map = {e.get("tag",""): e.get("count",1) for e in (dangerous_tags or [])}
        for obj, (expl, pts) in PDF_HIGH_RISK.items():
            if obj in tag_map:
                findings.append({"id":f"PDF-H{obj}","cat":"Malicious PDF Object","sev":"CRITICAL",
                    "title":f"High-Risk PDF Object: {obj}","detail":f"{expl} Found {tag_map[obj]} instance(s).","score":pts,"mitre":["T1566.001","T1204.002"]})
        for obj, (expl, pts) in PDF_MEDIUM_RISK.items():
            if obj in tag_map:
                findings.append({"id":f"PDF-M{obj}","cat":"Suspicious PDF Object","sev":"MEDIUM",
                    "title":f"Suspicious PDF Object: {obj}","detail":expl,"score":pts,"mitre":["T1566.001"]})
        has_js   = any(o in tag_map for o in ["/JavaScript","/JS"])
        has_auto = any(o in tag_map for o in ["/OpenAction","/AA"])
        if has_js and has_auto:
            findings.append({"id":"PDF-COMPOUND","cat":"Malicious PDF Object","sev":"CRITICAL",
                "title":"Auto-Executing JavaScript","detail":"PDF executes JS code on open without user interaction.","score":38,"mitre":["T1566.001","T1059"]})

    if file_type == "office" and macros_found:
        findings.append({"id":"MACRO-001","cat":"Macro","sev":"HIGH",
            "title":"VBA Macros Present","detail":"Document contains VBA macros.","score":28,"mitre":["T1566.001","T1204.002"]})
        auto_found = [kw for kw in MACRO_AUTO_EXEC if kw in macro_text]
        if auto_found:
            findings.append({"id":"MACRO-002","cat":"Macro","sev":"CRITICAL",
                "title":f"Auto-Execute Trigger — {auto_found[0]}","detail":"Macro runs automatically on open.","score":42,"mitre":["T1566.001","T1547"]})
        apis_found = [api for api in MACRO_DANGEROUS_APIS if api in macro_text]
        if apis_found:
            findings.append({"id":"MACRO-003","cat":"Macro","sev":"CRITICAL",
                "title":f"Dangerous API Calls ({', '.join(apis_found[:3])})","detail":"Macro invokes high-risk Windows APIs.","score":45,"mitre":["T1059.001","T1105"]})
        dl_kws = ["urldownload","winhttp","xmlhttp","downloadstring","downloadfile"]
        if any(k in macro_text for k in dl_kws):
            findings.append({"id":"MACRO-004","cat":"Macro","sev":"CRITICAL",
                "title":"Macro Downloads External Payload","detail":"Macro contains network download functionality.","score":52,"mitre":["T1105","T1566.001"]})

    raw = sum(f["score"] for f in findings)
    ids = set(f["id"] for f in findings)
    if "MACRO-003" in ids and "MACRO-004" in ids: raw += 15
    if "MACRO-002" in ids and "MACRO-003" in ids: raw += 12
    if "PDF-COMPOUND" in ids: raw += 10

    score = min(100, raw)
    mins = []
    if macros_found:                     mins.append(30)
    if "MACRO-002" in ids:               mins.append(62)
    if "MACRO-003" in ids:               mins.append(65)
    if "MACRO-004" in ids:               mins.append(75)
    if "PDF-COMPOUND" in ids:            mins.append(68)
    if any("PDF-H" in i for i in ids):  mins.append(55)
    if mins: score = max(score, max(mins))
    score = min(100, score)

    label = _score_to_label(score)
    mitre = set()
    for f in findings: mitre.update(f.get("mitre",[]))

    if score >= 75:
        verdict = f"HIGH CONFIDENCE MALICIOUS — Do not open. Submit to sandbox immediately."
    elif score >= 50:
        verdict = f"LIKELY MALICIOUS — Treat as hostile until verified."
    elif score >= 25:
        verdict = f"SUSPICIOUS — Manual review recommended."
    elif score >= 8:
        verdict = f"LOW RISK — Minor indicators. Exercise caution."
    else:
        verdict = f"CLEAN — No significant threat indicators."

    risk_factors = [f"{f['title']} (+{f['score']})" for f in sorted(findings, key=lambda x: x["score"], reverse=True)[:6]]
    confidence = "HIGH" if len(findings) >= 3 else "MEDIUM" if len(findings) >= 1 else "LOW"

    return {
        "score": score, "label": label, "findings": findings,
        "mitre_techniques": sorted(mitre), "verdict_summary": verdict,
        "confidence": confidence, "risk_factors": risk_factors,
    }
