import os
os.makedirs('src/detection', exist_ok=True)

code = r'''# src/detection/hisn_engine.py
# HISN Threat Detection Engine
# Rule-based detection modeled after Proofpoint, Microsoft Defender for Office 365,
# Mimecast, VirusTotal Intelligence, and Falcon Sandbox.
# LLM never decides what is malicious — detection is purely deterministic rule-based.
import re

# ──────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────

KNOWN_BRANDS = [
    "microsoft","google","apple","amazon","paypal","facebook","netflix","linkedin",
    "dropbox","docusign","dhl","fedex","irs","usps","ups","chase","wellsfargo",
    "citibank","bankofamerica","office365","outlook","onedrive","sharepoint",
    "teams","zoom","adobe","salesforce","twitter","instagram","binance","coinbase",
    "blockchain","coinbase","kraken","robinhood","venmo","zelle","cashapp",
]

URL_SHORTENERS = [
    "bit.ly","tinyurl.com","t.co","ow.ly","short.io","buff.ly","rebrand.ly",
    "is.gd","cutt.ly","lnkd.in","tiny.cc","adf.ly","linktr.ee","trib.al",
    "rb.gy","shorturl.at","clck.ru","qps.ru","x.co","v.gd",
]

FREE_PROVIDERS = [
    "gmail.com","yahoo.com","hotmail.com","outlook.com","protonmail.com",
    "aol.com","icloud.com","mail.com","yandex.com","gmx.com","zoho.com",
    "proton.me","tutanota.com","guerrillamail.com","mailinator.com",
]

URGENCY_RE = [
    r"\burgent\b", r"\bimmediately\b", r"\baction required\b",
    r"\baccount.{0,12}(suspend|clos|terminat|deactivat|lock)",
    r"\bverify.{0,12}(now|immediately|today|account)",
    r"\bexpired?\b", r"\bsuspended\b",
    r"\bunusual.{0,18}activit", r"\bsecurity.{0,12}alert\b",
    r"\blast.{0,6}(chance|warning|notice|reminder)",
    r"\bwithin.{0,12}(24|48|72).{0,6}hour",
    r"\bact.{0,6}now\b", r"\bconfirm.{0,12}identit",
    r"\breview.{0,12}(required|needed|immediately)",
    r"\baccount.{0,12}will.{0,12}(be.{0,6}deleted|expire|clos)",
]

CREDENTIAL_RE = [
    r"\bpassword\b", r"\bsign.?in\b", r"\blog.?in\b",
    r"\bverify.{0,12}(account|email|identit)",
    r"\benter.{0,18}credential", r"\bupdate.{0,12}(payment|billing|account)",
    r"\bconfirm.{0,12}(account|payment|information|detail)",
    r"\byour.{0,18}(account|password).{0,18}(has been|will be)",
    r"\bclick.{0,12}(here|below|link).{0,12}(verify|confirm|secure|reset)",
]

SUSPICIOUS_URL_KW = [
    "login","verify","account","secure","update","confirm","password","credential",
    "signin","reset","validate","security","authenticate","authorization","billing",
    "payment","invoice","urgent","webscr","cmd=","ebayisapi","banking","myaccount",
]

MACRO_AUTO_EXEC = [
    "autoopen","auto_open","autoexec","auto_exec","workbook_open",
    "document_open","auto_close","document_close","workbook_activate",
    "worksheet_activate","auto_new","document_new",
]

MACRO_DANGEROUS_APIS = [
    "shell","createobject","wscript","powershell","urldownloadtofile",
    "winhttp","xmlhttp","regwrite","regread","environ","filesystemobject",
    "getobject","executefile","winexec","shellexecute","createprocess",
    "wmi","wbemscripting","openprocess","virtualalloc","writefile",
]

MACRO_DOWNLOAD_KW = [
    "urldownload","winhttp","xmlhttp","downloadstring","downloadfile",
    "http.get","wget","curl","bitsadmin","certutil",
]

MACRO_OBFUSC_RE = [
    r"chr\s*\(\s*\d",
    r"[A-Za-z0-9+/]{60,}={0,2}",
    r"split\(.{0,40}\)\.join",
    r"replace\(.{0,30}\)\.replace",
    r"strreverse",
    r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}",
]

PDF_HIGH_RISK = {
    "/JavaScript": ("Executes JavaScript within the PDF. Used to exploit reader vulnerabilities.", 38),
    "/JS":         ("Alias for /JavaScript. Executes code on open.", 38),
    "/Launch":     ("Launches external application. Core mechanism for PDF malware droppers.", 32),
    "/AA":         ("Automatic Action — triggers code without user interaction.", 26),
    "/XFA":        ("XML Forms Architecture — executes scripts, submits data remotely.", 22),
    "/RichMedia":  ("Embeds rich media (Flash). No legitimate use in modern PDFs.", 18),
}

PDF_MEDIUM_RISK = {
    "/EmbeddedFile": ("Contains embedded files. PDFs can drop and execute malicious files.", 20),
    "/OpenAction":   ("Executes action when PDF opens. Commonly chains to /JavaScript.", 14),
    "/AcroForm":     ("Interactive form. Can exfiltrate data to remote servers.", 10),
    "/Encrypt":      ("Encrypted PDF. Encryption hides malicious content from scanners.", 10),
    "/SubmitForm":   ("Submits form data to remote URL. Potential data exfiltration.", 8),
    "/GoToR":        ("Redirects to external resource. Can be used for phishing redirects.", 5),
}


# ──────────────────────────────────────────────────────────
# SHARED HELPERS
# ──────────────────────────────────────────────────────────

def _score_to_label(score):
    if score >= 75: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 25: return "MEDIUM"
    if score >= 8:  return "LOW"
    return "INFORMATIONAL"


def _sev(score):
    if score >= 35: return "CRITICAL"
    if score >= 20: return "HIGH"
    if score >= 10: return "MEDIUM"
    return "LOW"


# ──────────────────────────────────────────────────────────
# EMAIL DETECTION ENGINE
# ──────────────────────────────────────────────────────────

def analyze_email(metadata, authentication, urls, attachments,
                  body_text, body_html, security_checks, received_chain):
    findings = []
    body = ((body_text or "") + " " + (body_html or "")).lower()
    body_html_lower = (body_html or "").lower()
    subject = (metadata.get("subject") or "").lower()

    spf_obj   = (authentication.get("spf")   or {})
    dkim_obj  = (authentication.get("dkim")  or {})
    dmarc_obj = (authentication.get("dmarc") or {})
    spf   = spf_obj.get("result",  "none").lower()
    dkim  = dkim_obj.get("result", "none").lower()
    dmarc = dmarc_obj.get("result","none").lower()

    from_display = (metadata.get("from_display") or "").lower()
    from_email   = (metadata.get("from_email")   or "").lower()
    from_domain  = from_email.split("@")[-1] if "@" in from_email else ""
    reply_to     = (metadata.get("reply_to")     or "").lower()
    reply_domain = reply_to.split("@")[-1] if "@" in reply_to else ""
    sc = security_checks or {}
    urls = urls or []
    attachments = attachments or []

    auth_failures = 0

    # ── AUTHENTICATION ────────────────────────────────────
    if spf in ("fail", "softfail"):
        pts = 20 if spf == "fail" else 12
        findings.append({"id":"AUTH-001","cat":"Authentication","sev":"HIGH",
            "title":f"SPF {spf.upper()}",
            "detail":"Sending server not authorized for this domain. Strong indicator of spoofing.",
            "score":pts,"mitre":["T1566","T1656"]})
        auth_failures += 1

    if dkim == "fail":
        findings.append({"id":"AUTH-002","cat":"Authentication","sev":"HIGH",
            "title":"DKIM Signature Invalid",
            "detail":"Cryptographic signature is invalid or missing — message may have been tampered with.",
            "score":18,"mitre":["T1566","T1656"]})
        auth_failures += 1

    if dmarc == "fail":
        findings.append({"id":"AUTH-003","cat":"Authentication","sev":"HIGH",
            "title":"DMARC Policy Failed",
            "detail":"From domain does not align with authenticated domain. Sender identity unverified.",
            "score":12,"mitre":["T1566","T1656"]})
        auth_failures += 1

    if auth_failures == 3:
        findings.append({"id":"AUTH-004","cat":"Authentication","sev":"CRITICAL",
            "title":"Complete Authentication Failure (SPF + DKIM + DMARC)",
            "detail":"All three email authentication mechanisms failed. No verifiable sender identity.",
            "score":20,"mitre":["T1566","T1656"]})

    # ── SENDER INTELLIGENCE ───────────────────────────────
    impersonated_brand = None
    for brand in KNOWN_BRANDS:
        if brand in from_display and brand not in from_domain:
            impersonated_brand = brand
            findings.append({"id":"SENDER-001","cat":"Sender Deception","sev":"CRITICAL",
                "title":f"Brand Impersonation — {brand.title()}",
                "detail":(f"Display name contains '{brand}' but sending domain '{from_domain}' "
                          f"is unrelated. Classic phishing display-name spoofing."),
                "score":30,"mitre":["T1656","T1566","T1598"]})
            break

    if reply_domain and reply_domain != from_domain and reply_domain not in FREE_PROVIDERS:
        findings.append({"id":"SENDER-002","cat":"Sender Deception","sev":"HIGH",
            "title":"Reply-To Hijacking",
            "detail":(f"Replies go to '{reply_domain}', not '{from_domain}'. "
                      f"Core Business Email Compromise technique to intercept replies."),
            "score":22,"mitre":["T1566","T1598"]})

    if from_domain in FREE_PROVIDERS and (impersonated_brand or auth_failures >= 1):
        findings.append({"id":"SENDER-003","cat":"Sender Deception","sev":"HIGH",
            "title":f"Free Email Provider — {from_domain}",
            "detail":"Legitimate organizations do not send impersonation or spoofed emails from personal accounts.",
            "score":14,"mitre":["T1566","T1656"]})

    # ── URL ANALYSIS ──────────────────────────────────────
    sus_url_count = 0
    for url in urls[:30]:
        ul = url.lower()

        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ul):
            findings.append({"id":"URL-001","cat":"Malicious URL","sev":"CRITICAL",
                "title":"IP-Address URL (No Domain)",
                "detail":f"URL uses raw IP instead of domain: {url[:70]}. Indicates malicious infrastructure.",
                "score":28,"mitre":["T1566.002","T1204.001"]})

        for sh in URL_SHORTENERS:
            if sh in ul:
                findings.append({"id":"URL-002","cat":"Malicious URL","sev":"HIGH",
                    "title":f"URL Shortener — {sh}",
                    "detail":f"Short URL hides true destination: {url[:60]}. Used to bypass URL reputation filters.",
                    "score":15,"mitre":["T1566.002"]})
                break

        sus_kws = [kw for kw in SUSPICIOUS_URL_KW if kw in ul]
        if sus_kws:
            sus_url_count += 1
            pts = min(10 + len(sus_kws) * 3, 20)
            findings.append({"id":"URL-003","cat":"Malicious URL",
                "sev":"HIGH" if pts >= 15 else "MEDIUM",
                "title":f"Credential-Phishing URL Keywords ({', '.join(sus_kws[:3])})",
                "detail":f"URL contains phishing-associated terms: {url[:80]}",
                "score":pts,"mitre":["T1566.002","T1598.003","T1539"]})

        if "xn--" in ul:
            findings.append({"id":"URL-004","cat":"Malicious URL","sev":"CRITICAL",
                "title":"Punycode / Homograph Attack",
                "detail":f"Punycode URL impersonates legitimate domain visually: {url[:80]}",
                "score":35,"mitre":["T1566.002","T1656"]})

        if ul.startswith("http://") and sus_kws:
            findings.append({"id":"URL-005","cat":"Malicious URL","sev":"HIGH",
                "title":"Credential Page Over Unencrypted HTTP",
                "detail":f"Phishing URL uses plaintext HTTP: {url[:70]}",
                "score":12,"mitre":["T1566.002","T1539"]})

    # ── CREDENTIAL HARVESTING ─────────────────────────────
    if sc.get("has_html_form"):
        pts = 35 if sus_url_count > 0 else 22
        findings.append({"id":"CRED-001","cat":"Credential Harvesting","sev":"HIGH",
            "title":"HTML Form in Email Body",
            "detail":"Embedded HTML form to capture credentials. Legitimate services never do this.",
            "score":pts,"mitre":["T1598","T1539","T1566.002"]})

    cred_hits = sum(1 for p in CREDENTIAL_RE if re.search(p, body + " " + subject, re.IGNORECASE))
    if cred_hits >= 2:
        findings.append({"id":"CRED-002","cat":"Credential Harvesting","sev":"MEDIUM",
            "title":f"Credential-Harvesting Language ({cred_hits} patterns)",
            "detail":"Email body contains language consistent with credential phishing.",
            "score":min(8 + cred_hits * 3, 18),"mitre":["T1598","T1539"]})

    # ── URGENCY / SOCIAL ENGINEERING ─────────────────────
    urgency_hits = sum(1 for p in URGENCY_RE if re.search(p, body + " " + subject, re.IGNORECASE))
    if urgency_hits >= 1:
        pts = min(10 + urgency_hits * 2, 22)
        findings.append({"id":"SE-001","cat":"Social Engineering","sev":"MEDIUM",
            "title":f"Urgency / Pressure Tactics ({urgency_hits} indicator{'s' if urgency_hits>1 else ''})",
            "detail":"Artificial urgency to bypass critical thinking. Core phishing and BEC technique.",
            "score":pts,"mitre":["T1566"]})

    # ── ACTIVE CONTENT ────────────────────────────────────
    if sc.get("has_javascript"):
        findings.append({"id":"ACTIVE-001","cat":"Active Content","sev":"HIGH",
            "title":"JavaScript in Email Body",
            "detail":"JavaScript embedded in HTML email. Legitimate emails never contain JS. Can execute code on open.",
            "score":20,"mitre":["T1566","T1204.001","T1059"]})

    # ── ATTACHMENTS ───────────────────────────────────────
    for att in attachments:
        fname = att.get("filename","unknown")
        ext   = (att.get("extension") or "").lower()

        if att.get("is_executable"):
            findings.append({"id":"ATT-001","cat":"Malicious Attachment","sev":"CRITICAL",
                "title":f"Executable Attachment — {fname}",
                "detail":f"'{fname}' is an executable. Running it immediately executes attacker code.",
                "score":55,"mitre":["T1566.001","T1204.002","T1059"]})

        elif att.get("has_macros"):
            findings.append({"id":"ATT-002","cat":"Malicious Attachment","sev":"HIGH",
                "title":f"Macro-Enabled Office Document — {fname}",
                "detail":f"'{fname}' can execute macros. Most macro-bearing attachments in phishing emails are malicious.",
                "score":42,"mitre":["T1566.001","T1204.002","T1059.001"]})

        elif att.get("is_compressed"):
            findings.append({"id":"ATT-003","cat":"Suspicious Attachment","sev":"MEDIUM",
                "title":f"Archive Attachment — {fname}",
                "detail":f"'{fname}' is a compressed archive. Commonly used to bypass gateway scanning.",
                "score":14,"mitre":["T1566.001","T1027"]})

        # Double extension check
        base = fname.rsplit(".",1)[0] if "." in fname else fname
        EXEC_EXTS = {".exe",".bat",".cmd",".ps1",".vbs",".js",".jar",".scr",".com",".hta",".msi"}
        if any(base.lower().endswith(e.lstrip(".")) for e in EXEC_EXTS):
            findings.append({"id":"ATT-004","cat":"Malicious Attachment","sev":"CRITICAL",
                "title":f"Double Extension — {fname}",
                "detail":f"'{fname}' uses a double extension to disguise an executable as a safe file.",
                "score":50,"mitre":["T1566.001","T1036.007","T1204.002"]})

    # ── HEADER ANOMALIES ──────────────────────────────────
    if sc.get("invalid_message_id"):
        findings.append({"id":"HDR-001","cat":"Header Anomaly","sev":"LOW",
            "title":"Malformed Message-ID",
            "detail":"Non-RFC-5322-compliant Message-ID. Bulk phishing tools generate non-standard headers.",
            "score":6,"mitre":["T1566"]})

    if sc.get("has_tracking_pixel"):
        findings.append({"id":"TRACK-001","cat":"Tracking","sev":"LOW",
            "title":"Email Tracking Pixel",
            "detail":"1x1 pixel confirms email was opened and leaks recipient IP and timestamp.",
            "score":5,"mitre":["T1598"]})

    # ── SCORE + MINIMUMS ──────────────────────────────────
    raw = sum(f["score"] for f in findings)

    # Compound bonuses
    cats = set(f["cat"] for f in findings)
    ids  = set(f["id"]  for f in findings)
    if "Authentication" in cats and "Sender Deception" in cats: raw += 10
    if "Credential Harvesting" in cats and "Malicious URL" in cats: raw += 10
    if "ATT-001" in ids or "ATT-002" in ids: raw += 8

    score = min(100, raw)

    # Minimum floors — a confirmed malicious indicator cannot score LOW
    mins = []
    if auth_failures == 3:               mins.append(50)
    if auth_failures >= 1 and impersonated_brand: mins.append(55)
    if "ATT-001" in ids:                 mins.append(62)
    if "ATT-002" in ids:                 mins.append(52)
    if "ATT-004" in ids:                 mins.append(62)
    if "CRED-001" in ids:                mins.append(40)
    if "URL-001" in ids:                 mins.append(45)
    if "URL-004" in ids:                 mins.append(60)
    if impersonated_brand:               mins.append(35)
    if auth_failures >= 1:               mins.append(25)
    if urgency_hits >= 2 and sus_url_count >= 1: mins.append(40)
    if mins: score = max(score, max(mins))
    score = min(100, score)

    label = _score_to_label(score)

    # ── MITRE ─────────────────────────────────────────────
    mitre = set(["T1566"])
    for f in findings:
        mitre.update(f.get("mitre",[]))

    # ── PHISHING TECHNIQUES ───────────────────────────────
    tech = []
    if "SENDER-001" in ids: tech.append("Brand Impersonation")
    if "AUTH-001" in ids or "AUTH-002" in ids: tech.append("Spoofing")
    if "SENDER-002" in ids: tech.append("Reply-To Hijacking")
    if "CRED-001" in ids or "CRED-002" in ids: tech.append("Credential Harvesting")
    if "ATT-001" in ids: tech.append("Malicious Attachment (Executable)")
    if "ATT-002" in ids: tech.append("Malicious Attachment (Macro)")
    if "ATT-003" in ids: tech.append("Archive Delivery")
    if "SE-001" in ids: tech.append("Urgency / Pressure Tactics")
    if "URL-001" in ids: tech.append("IP-Based Infrastructure")
    if "URL-002" in ids: tech.append("URL Shortener")
    if "URL-004" in ids: tech.append("Homograph / Punycode Attack")
    if "ACTIVE-001" in ids: tech.append("Active JavaScript")
    if re.search(r"invoice|payment|wire transfer|bank account", body): tech.append("Invoice Fraud / BEC")
    if re.search(r"gift card|amazon gift|itunes|steam card", body): tech.append("Gift Card Scam")

    verdict = _email_verdict(score, label, impersonated_brand, findings)
    confidence = "HIGH" if len(findings) >= 4 else "MEDIUM" if len(findings) >= 2 else "LOW"

    risk_factors = [
        f"{f['title']} (+{f['score']})"
        for f in sorted(findings, key=lambda x: x["score"], reverse=True)[:6]
    ]

    return {
        "score": score, "label": label, "findings": findings,
        "mitre_techniques": sorted(mitre), "phishing_techniques": tech,
        "verdict_summary": verdict, "confidence": confidence,
        "risk_factors": risk_factors,
    }


def _email_verdict(score, label, brand, findings):
    ids = set(f["id"] for f in findings)
    if score >= 75:
        if brand:
            return (f"HIGH CONFIDENCE PHISHING — This email impersonates {brand.title()} while failing "
                    f"email authentication and employing multiple deception techniques. Do not click links "
                    f"or open attachments. Report to your security team immediately.")
        if "ATT-001" in ids:
            return ("MALWARE DELIVERY — This email carries an executable attachment. Do not open the file. "
                    "Isolate this message and submit the attachment to a sandbox for analysis.")
        return ("HIGH CONFIDENCE MALICIOUS — Multiple correlated indicators confirm this email is hostile. "
                "Do not interact with any content. Escalate to SOC.")
    elif score >= 50:
        return ("LIKELY MALICIOUS — Significant phishing indicators present. Treat all links and attachments "
                "as potentially hostile. Verify the sender out-of-band before taking any action.")
    elif score >= 25:
        return ("SUSPICIOUS — Notable risk indicators warrant caution. Verify sender identity through an "
                "independent channel before acting on any requests in this email.")
    elif score >= 8:
        return "LOW RISK — Minor indicators found. Exercise standard caution."
    return "CLEAN — No significant threat indicators detected."


# ──────────────────────────────────────────────────────────
# DOCUMENT DETECTION ENGINE
# ──────────────────────────────────────────────────────────

def analyze_document(filename, file_type, macros_found, macro_streams,
                     suspicious_keywords, dangerous_tags, text_indicators,
                     sha256="", body_text_excerpt="", raw_macro_code=""):
    findings = []
    kws = [str(k).lower() for k in (suspicious_keywords or [])]
    macro_text = " ".join(kws) + " " + (raw_macro_code or "").lower()

    # ── PDF ───────────────────────────────────────────────
    if file_type == "pdf":
        tag_map = {}
        for entry in (dangerous_tags or []):
            tag_map[entry.get("tag","")] = entry.get("count",1)

        for obj, (expl, pts) in PDF_HIGH_RISK.items():
            if obj in tag_map:
                findings.append({"id":f"PDF-H{obj}","cat":"Malicious PDF Object","sev":"CRITICAL",
                    "title":f"High-Risk PDF Object: {obj}",
                    "detail":f"{expl} Found {tag_map[obj]} instance(s).",
                    "score":pts,"mitre":["T1566.001","T1204.002","T1059"]})

        for obj, (expl, pts) in PDF_MEDIUM_RISK.items():
            if obj in tag_map:
                findings.append({"id":f"PDF-M{obj}","cat":"Suspicious PDF Object","sev":"MEDIUM",
                    "title":f"Suspicious PDF Object: {obj}",
                    "detail":f"{expl} Found {tag_map[obj]} instance(s).",
                    "score":pts,"mitre":["T1566.001","T1204.002"]})

        has_js   = any(o in tag_map for o in ["/JavaScript","/JS"])
        has_auto = any(o in tag_map for o in ["/OpenAction","/AA"])
        if has_js and has_auto:
            findings.append({"id":"PDF-COMPOUND","cat":"Malicious PDF Object","sev":"CRITICAL",
                "title":"Auto-Executing JavaScript (JS + OpenAction/AA)",
                "detail":"PDF will silently execute JavaScript code when opened — no user interaction required.",
                "score":38,"mitre":["T1566.001","T1204.002","T1059"]})

        has_launch = "/Launch" in tag_map
        has_emb    = "/EmbeddedFile" in tag_map
        if has_launch and has_emb:
            findings.append({"id":"PDF-DROPPER","cat":"Malicious PDF Object","sev":"CRITICAL",
                "title":"PDF Dropper Pattern (Launch + EmbeddedFile)",
                "detail":"PDF contains both an embedded file and a Launch action — classic dropper behavior.",
                "score":42,"mitre":["T1566.001","T1204.002","T1105"]})

    # ── OFFICE MACROS ─────────────────────────────────────
    if file_type == "office":
        if macros_found:
            findings.append({"id":"MACRO-001","cat":"Macro","sev":"HIGH",
                "title":"VBA Macros Present",
                "detail":"Document contains VBA macros — the most common initial access vector in targeted attacks.",
                "score":28,"mitre":["T1566.001","T1204.002","T1059.001"]})

            # Auto-execution
            auto_found = [kw for kw in MACRO_AUTO_EXEC
                          if kw in macro_text or kw in " ".join(str(s).lower() for s in (macro_streams or []))]
            if auto_found:
                findings.append({"id":"MACRO-002","cat":"Macro","sev":"CRITICAL",
                    "title":f"Auto-Execute Trigger — {auto_found[0]}",
                    "detail":f"Macro runs automatically on open via '{auto_found[0]}'. No user interaction required.",
                    "score":42,"mitre":["T1566.001","T1204.002","T1059.001","T1547"]})

            # Dangerous API calls
            apis_found = list(set(api for api in MACRO_DANGEROUS_APIS if api in macro_text))
            if apis_found:
                findings.append({"id":"MACRO-003","cat":"Macro","sev":"CRITICAL",
                    "title":f"Dangerous API Calls ({', '.join(apis_found[:4])})",
                    "detail":f"Macro invokes high-risk Windows APIs capable of executing commands, modifying registry, or spawning processes.",
                    "score":45,"mitre":["T1059.001","T1059.003","T1105","T1547"]})

            # Download/stager
            dl_found = [kw for kw in MACRO_DOWNLOAD_KW if kw in macro_text]
            if dl_found:
                findings.append({"id":"MACRO-004","cat":"Macro","sev":"CRITICAL",
                    "title":f"Macro Downloads External Payload",
                    "detail":f"Macro contains network download functionality ({dl_found[0]}). Indicates a dropper/stager.",
                    "score":52,"mitre":["T1105","T1059.001","T1566.001"]})

            # Obfuscation
            obf_found = [p for p in MACRO_OBFUSC_RE
                         if re.search(p, macro_text, re.IGNORECASE)]
            if obf_found:
                findings.append({"id":"MACRO-005","cat":"Macro","sev":"HIGH",
                    "title":"Obfuscated Macro Code",
                    "detail":"Macro uses string encoding, character manipulation, or Base64 to evade detection.",
                    "score":26,"mitre":["T1027","T1059.001"]})

            # Shell/exec specific
            if any(x in macro_text for x in ["shell(","shell (","wscript.shell","createobject(\"wscript"]):
                findings.append({"id":"MACRO-006","cat":"Macro","sev":"CRITICAL",
                    "title":"Shell Execution in Macro",
                    "detail":"Macro explicitly calls system shell (cmd.exe/WScript). Immediate code execution capability.",
                    "score":48,"mitre":["T1059.003","T1059.001","T1204.002"]})

    # ── EMBEDDED INDICATORS ───────────────────────────────
    indicators = text_indicators or {}
    emb_urls = indicators.get("urls",[])
    emb_ips  = indicators.get("ips",[])
    emb_flags = indicators.get("flags",[])

    sus_urls_found = [u for u in emb_urls
                      if any(kw in u.lower() for kw in SUSPICIOUS_URL_KW)]
    if sus_urls_found:
        findings.append({"id":"EMBED-001","cat":"Embedded Indicator","sev":"MEDIUM",
            "title":f"Suspicious Embedded URL(s) — {len(sus_urls_found)} found",
            "detail":f"Document contains URLs with phishing-associated keywords: {sus_urls_found[0][:80]}",
            "score":14,"mitre":["T1566.001","T1566.002"]})

    if emb_ips:
        findings.append({"id":"EMBED-002","cat":"Embedded Indicator","sev":"MEDIUM",
            "title":f"Hardcoded IP Address(es) — {len(emb_ips)} found",
            "detail":f"Document embeds IPs ({', '.join(emb_ips[:3])}). Possible C2 addresses or exfiltration targets.",
            "score":12,"mitre":["T1071","T1566.001"]})

    if emb_flags and len(emb_flags) >= 3:
        findings.append({"id":"EMBED-003","cat