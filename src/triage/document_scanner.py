# src/triage/document_scanner.py
# Static document triage: macros, embedded URLs/IPs, dangerous PDF objects
# Never executes anything — pure static inspection, same philosophy as the detection engine.

import re
import os
import hashlib
from src.enrichment.hash_lookup import check_hash_reputation

FLAG_PATTERN = re.compile(r"\b[A-Za-z][A-Za-z0-9_]{1,15}\{[^{}]{3,100}\}")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SUSPICIOUS_VBA_KEYWORDS = [
    "Shell", "WScript.Shell", "CreateObject", "URLDownloadToFile", "PowerShell",
    "cmd.exe", "AutoOpen", "AutoExec", "Document_Open", ".Run(", "Environ(",
]

PDF_DANGEROUS_TAGS = ["/JavaScript", "/JS", "/OpenAction", "/Launch", "/EmbeddedFile", "/AA", "/RichMedia"]


def _scan_text(text):
    text = text or ""
    return {
        "flags": sorted(set(FLAG_PATTERN.findall(text))),
        "urls": sorted(set(URL_PATTERN.findall(text))),
        "ips": sorted(set(IP_PATTERN.findall(text))),
    }


def scan_office_document(filepath):
    result = {
        "filename": os.path.basename(filepath), "file_type": "office",
        "macros_found": False, "macro_streams": [], "suspicious_keywords": [],
        "text_indicators": {"flags": [], "urls": [], "ips": []},
        "body_text_excerpt": "", "errors": [],
    }
    try:
        from oletools.olevba import VBA_Parser
        vba = VBA_Parser(filepath)
        if vba.detect_vba_macros():
            result["macros_found"] = True
            combined = ""
            for (_, stream_path, vba_filename, vba_code) in vba.extract_macros():
                if vba_code:
                    result["macro_streams"].append(vba_filename or stream_path)
                    combined += vba_code + "\n"
            result["suspicious_keywords"] = [kw for kw in SUSPICIOUS_VBA_KEYWORDS if kw.lower() in combined.lower()]
            result["text_indicators"] = _scan_text(combined)
        vba.close()
    except Exception as e:
        result["errors"].append(f"Macro scan failed: {e}")

    try:
        if filepath.lower().endswith((".docx", ".docm")):
            from docx import Document
            doc = Document(filepath)
            body = "\n".join(p.text for p in doc.paragraphs)
            result["body_text_excerpt"] = body[:600]
            body_ind = _scan_text(body)
            for k in result["text_indicators"]:
                result["text_indicators"][k] = sorted(set(result["text_indicators"][k] + body_ind[k]))
    except Exception as e:
        result["errors"].append(f"Text extraction failed: {e}")

    return result


def scan_pdf_document(filepath):
    result = {
        "filename": os.path.basename(filepath), "file_type": "pdf",
        "dangerous_tags": [], "text_indicators": {"flags": [], "urls": [], "ips": []},
        "body_text_excerpt": "", "errors": [],
    }
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
        for tag in PDF_DANGEROUS_TAGS:
            count = raw.count(tag.encode("latin-1", errors="ignore"))
            if count:
                result["dangerous_tags"].append({"tag": tag, "count": count})
    except Exception as e:
        result["errors"].append(f"Raw scan failed: {e}")

    try:
        from pypdf import PdfReader
        reader = PdfReader(filepath)
        text = ""
        for page in reader.pages[:20]:
            text += (page.extract_text() or "") + "\n"
        result["body_text_excerpt"] = text[:600]
        result["text_indicators"] = _scan_text(text)
    except Exception as e:
        result["errors"].append(f"Text extraction failed: {e}")

    return result
def _sha256_of_file(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def scan_document(filepath):
    lower = filepath.lower()
    if lower.endswith(".pdf"):
        result = scan_pdf_document(filepath)
    elif lower.endswith((".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm")):
        result = scan_office_document(filepath)
    else:
        return {"filename": os.path.basename(filepath), "file_type": "unsupported",
                "errors": ["Unsupported file type for document triage."]}

    try:
        file_hash = _sha256_of_file(filepath)
        result["sha256"] = file_hash
        result["vt_intel"] = check_hash_reputation(file_hash)
    except Exception as e:
        result.setdefault("errors", []).append(f"Hash lookup failed: {e}")

    return result

if __name__ == "__main__":
    import sys, json
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if not path:
        print("Usage: python -m src.triage.document_scanner <path-to-file>")
    else:
        print(json.dumps(scan_document(path), indent=2))