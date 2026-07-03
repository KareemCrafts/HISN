content = '''# src/reports/pdf_report.py
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                  TableStyle, HRFlowable, PageBreak, KeepTogether)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from io import BytesIO
from datetime import datetime

C_BG     = colors.HexColor("#0A0E12")
C_PANEL  = colors.HexColor("#0D1318")
C_ACCENT = colors.HexColor("#7CFFB2")
C_AMBER  = colors.HexColor("#FFB347")
C_CRIT   = colors.HexColor("#E0483E")
C_HIGH   = colors.HexColor("#E2602E")
C_MED    = colors.HexColor("#D9B44A")
C_LOW    = colors.HexColor("#4C8BA8")
C_INK    = colors.HexColor("#D6E8DC")
C_META   = colors.HexColor("#5B7A75")
C_WHITE  = colors.white
C_DARK   = colors.HexColor("#03060A")

SEV_COLORS = {
    "critical": C_CRIT, "high": C_HIGH,
    "medium": C_MED, "low": C_LOW, "informational": C_META,
}

def _sev_color(sev):
    return SEV_COLORS.get((sev or "").lower(), C_META)

def _styles():
    base = getSampleStyleSheet()
    def S(name, **kw):
        return ParagraphStyle(name, parent=base["Normal"], **kw)
    return {
        "cover_title": S("ct", fontSize=36, textColor=C_ACCENT, spaceAfter=6,
                          fontName="Helvetica-Bold", alignment=TA_LEFT, leading=40),
        "cover_sub":   S("cs", fontSize=13, textColor=C_INK, spaceAfter=4,
                          fontName="Helvetica", alignment=TA_LEFT),
        "cover_meta":  S("cm", fontSize=9, textColor=C_META, spaceAfter=2,
                          fontName="Helvetica", alignment=TA_LEFT),
        "section":     S("sec", fontSize=10, textColor=C_ACCENT, spaceAfter=6,
                          fontName="Helvetica-Bold", spaceBefore=14,
                          borderPad=4, leading=14),
        "body":        S("body", fontSize=9, textColor=C_INK, spaceAfter=4,
                          fontName="Helvetica", leading=13),
        "small":       S("small", fontSize=8, textColor=C_META, spaceAfter=2,
                          fontName="Helvetica", leading=11),
        "case_title":  S("caset", fontSize=11, textColor=C_WHITE, spaceAfter=3,
                          fontName="Helvetica-Bold", leading=14),
        "ai_note":     S("ainote", fontSize=8.5, textColor=C_INK, spaceAfter=4,
                          fontName="Helvetica", leading=12,
                          leftIndent=6, borderPad=4),
        "mono":        S("mono", fontSize=7.5, textColor=C_ACCENT, spaceAfter=2,
                          fontName="Courier", leading=10),
        "label":       S("lbl", fontSize=7, textColor=C_META, spaceAfter=1,
                          fontName="Helvetica-Bold", leading=9),
    }

def _header_footer(canvas, doc):
    canvas.saveState()
    W, H = A4
    canvas.setFillColor(C_DARK)
    canvas.rect(0, H-28*mm, W, 28*mm, fill=1, stroke=0)
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, H-28*mm, 3*mm, 28*mm, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.setFillColor(C_ACCENT)
    canvas.drawString(1.2*cm, H-14*mm, "HISN")
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(C_META)
    canvas.drawString(2.5*cm, H-14*mm, "UNIFIED THREAT INVESTIGATION & ANALYTICS TOOL")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C_META)
    canvas.drawRightString(W-1.2*cm, H-14*mm,
        f"CLASSIFICATION: INTERNAL  |  PAGE {doc.page}")
    canvas.setFillColor(C_DARK)
    canvas.rect(0, 0, W, 15*mm, fill=1, stroke=0)
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, 0, W, 1*mm, fill=1, stroke=0)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C_META)
    canvas.drawString(1.2*cm, 5*mm,
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  |  "
        "AI-assisted analysis — verify before acting  |  HISN // Incident Report")
    canvas.restoreState()

def _divider(color=None):
    return HRFlowable(width="100%", thickness=0.5, color=color or C_ACCENT,
                      spaceAfter=4, spaceBefore=4)

def _stat_table(stats, sty):
    SEV_RANK = {"critical":4,"high":3,"medium":2,"low":1,"informational":0}
    data = [
        [Paragraph("RAW SIGNALS", sty["label"]),
         Paragraph("CASE FILES", sty["label"]),
         Paragraph("NOISE REDUCED", sty["label"]),
         Paragraph("ATT&CK TECHNIQUES", sty["label"])],
        [Paragraph(f'<font size="18" color="#7CFFB2">{stats["total_alerts"]}</font>', sty["body"]),
         Paragraph(f'<font size="18" color="#7CFFB2">{stats["total_incidents"]}</font>', sty["body"]),
         Paragraph(f'<font size="18" color="#FFB347">{stats["reduction"]}%</font>', sty["body"]),
         Paragraph(f'<font size="18" color="#7BE6FF">{stats["techniques_seen"]}</font>', sty["body"])],
    ]
    t = Table(data, colWidths=["25%","25%","25%","25%"])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_PANEL),
        ("GRID",       (0,0), (-1,-1), 0.5, C_BG),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("PADDING",    (0,0), (-1,-1), 10),
        ("LINEBELOW",  (0,0), (-1,0), 0.5, C_ACCENT),
    ]))
    return t

def _sev_badge_table(inc, sty):
    sev = (inc.get("max_severity","?")).upper()
    sc  = _sev_color(inc.get("max_severity",""))
    data = [[
        Paragraph(sev, ParagraphStyle("sb", fontSize=9, textColor=sc,
                                       fontName="Helvetica-Bold", alignment=TA_CENTER)),
    ]]
    t = Table(data, colWidths=[2*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,0), colors.HexColor("#0A0E12")),
        ("BOX",        (0,0), (0,0), 1, sc),
        ("ALIGN",      (0,0), (0,0), "CENTER"),
        ("VALIGN",     (0,0), (0,0), "MIDDLE"),
        ("PADDING",    (0,0), (0,0), 4),
    ]))
    return t

def _case_header_table(inc, sty, case_num):
    sev   = (inc.get("max_severity","?")).upper()
    sc    = _sev_color(inc.get("max_severity",""))
    host  = inc.get("host","UNKNOWN")
    ip    = inc.get("source_ip") or "Internal"
    cnt   = inc.get("alert_count",0)
    cid   = f"CASE-{str(case_num).zfill(3)}"
    s_str = inc.get("start_time","")[:16] if inc.get("start_time") else ""
    e_str = inc.get("end_time","")[:16] if inc.get("end_time") else ""

    left_cell  = [
        Paragraph(f'<font size="8" color="#5B7A75">{cid}</font>', sty["small"]),
        Paragraph(f'<b>{host}</b>', ParagraphStyle("ch", fontSize=13, textColor=C_WHITE,
                                                    fontName="Helvetica-Bold")),
        Paragraph(f'{ip}  ·  {cnt} alerts  ·  {s_str} → {e_str}',
                  ParagraphStyle("ci", fontSize=8, textColor=C_META, fontName="Helvetica")),
    ]
    right_cell = [
        Paragraph(sev, ParagraphStyle("sv", fontSize=11, textColor=sc,
                                       fontName="Helvetica-Bold", alignment=TA_RIGHT)),
    ]
    data = [[left_cell, right_cell]]
    t = Table(data, colWidths=["75%","25%"])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,-1), C_PANEL),
        ("LINEBELOW",   (0,0), (-1,0), 2, sc),
        ("LEFTPADDING", (0,0), (0,0), 10),
        ("RIGHTPADDING",(1,0), (1,0), 10),
        ("TOPPADDING",  (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0),(-1,-1), 8),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
    ]))
    return t

def _mitre_table(techniques_str, sty):
    techs = [t.strip() for t in (techniques_str or "").split(",") if t.strip()]
    if not techs: return Paragraph("No techniques mapped.", sty["small"])
    cells = []
    for t in techs:
        sc = C_ACCENT
        cells.append(Paragraph(t, ParagraphStyle("mt", fontSize=8, textColor=sc,
                                                   fontName="Courier-Bold",
                                                   alignment=TA_CENTER)))
    row_size = 5
    rows = [cells[i:i+row_size] for i in range(0, len(cells), row_size)]
    for row in rows:
        while len(row) < row_size:
            row.append(Paragraph("", sty["small"]))
    t = Table(rows, colWidths=["20%"]*5)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#070B11")),
        ("BOX",        (0,0), (-1,-1), 0.5, C_ACCENT),
        ("INNERGRID",  (0,0), (-1,-1), 0.3, colors.HexColor("#0D1318")),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("PADDING",    (0,0), (-1,-1), 5),
    ]))
    return t

def _ioc_table(iocs_dict, sty):
    rows = []
    if iocs_dict.get("ips"):
        for ip in iocs_dict["ips"][:8]:
            rows.append([Paragraph("IP", sty["label"]),
                         Paragraph(ip, sty["mono"])])
    if iocs_dict.get("hashes"):
        for h in iocs_dict["hashes"][:4]:
            short = h[:32] + "..." if len(h) > 32 else h
            rows.append([Paragraph("SHA256", sty["label"]),
                         Paragraph(short, sty["mono"])])
    if iocs_dict.get("domains"):
        for d in iocs_dict["domains"][:5]:
            rows.append([Paragraph("Domain", sty["label"]),
                         Paragraph(d, sty["mono"])])
    if not rows:
        return Paragraph("No IOCs extracted for this incident.", sty["small"])
    t = Table(rows, colWidths=[2*cm, None])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), colors.HexColor("#070B11")),
        ("TEXTCOLOR",    (0,0), (0,-1), C_META),
        ("ALIGN",        (0,0), (0,-1), "LEFT"),
        ("INNERGRID",    (0,0), (-1,-1), 0.3, colors.HexColor("#0D1318")),
        ("BOX",          (0,0), (-1,-1), 0.5, C_META),
        ("PADDING",      (0,0), (-1,-1), 4),
        ("VALIGN",       (0,0), (-1,-1), "TOP"),
    ]))
    return t

def _remediation_table(remediation, sty):
    rows = []
    for r in remediation[:6]:
        cat_color = {"Harden": C_ACCENT, "Detect": C_LOW,
                     "Isolate": C_AMBER, "Restore": C_CRIT}.get(r.get("category",""), C_META)
        rows.append([
            Paragraph(r.get("id",""), ParagraphStyle("rt", fontSize=8, textColor=C_WHITE,
                                                      fontName="Courier-Bold")),
            Paragraph(r.get("category",""), ParagraphStyle("rc", fontSize=7, textColor=cat_color,
                                                             fontName="Helvetica-Bold")),
            Paragraph("<br/>".join(r.get("steps",[])), sty["small"]),
        ])
    if not rows:
        return Paragraph("No remediation steps mapped.", sty["small"])
    t = Table(rows, colWidths=[2.2*cm, 1.6*cm, None])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), colors.HexColor("#070B11")),
        ("BOX",          (0,0), (-1,-1), 0.5, C_META),
        ("INNERGRID",    (0,0), (-1,-1), 0.3, colors.HexColor("#0D1318")),
        ("ALIGN",        (0,0), (-1,-1), "LEFT"),
        ("VALIGN",       (0,0), (-1,-1), "TOP"),
        ("PADDING",      (0,0), (-1,-1), 5),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.HexColor("#07090C"), colors.HexColor("#060808")]),
    ]))
    return t

def generate_incident_report(incidents_data, stats):
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                             leftMargin=1.5*cm, rightMargin=1.5*cm,
                             topMargin=3.5*cm, bottomMargin=2.2*cm)
    sty = _styles()
    story = []

    # ── COVER PAGE ─────────────────────────────────────────────────────
    story.append(Spacer(1, 2*cm))
    story.append(Paragraph("INCIDENT INVESTIGATION", sty["cover_meta"]))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph("REPORT", sty["cover_title"]))
    story.append(_divider(C_ACCENT))
    story.append(Spacer(1, 8*mm))
    story.append(Paragraph("HISN — Unified Threat Investigation & Analytics Tool", sty["cover_sub"]))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", sty["cover_meta"]))
    story.append(Paragraph(f"Total Cases: {stats.get('total_incidents',0)}  |  Raw Signals: {stats.get('total_alerts',0)}  |  Noise Reduction: {stats.get('reduction',0)}%", sty["cover_meta"]))
    story.append(Spacer(1, 12*mm))

    # severity breakdown
    counts = {}
    for inc in incidents_data:
        s = (inc.get("max_severity") or "unknown").lower()
        counts[s] = counts.get(s,0) + 1
    sev_data = [[
        Paragraph(f'{counts.get("critical",0)}', ParagraphStyle("sc", fontSize=22, textColor=C_CRIT, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(f'{counts.get("high",0)}',     ParagraphStyle("sh", fontSize=22, textColor=C_HIGH, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(f'{counts.get("medium",0)}',   ParagraphStyle("sm2", fontSize=22, textColor=C_MED, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(f'{counts.get("low",0)}',      ParagraphStyle("sl", fontSize=22, textColor=C_LOW, fontName="Helvetica-Bold", alignment=TA_CENTER)),
    ],[
        Paragraph("CRITICAL", sty["label"]),
        Paragraph("HIGH",     sty["label"]),
        Paragraph("MEDIUM",   sty["label"]),
        Paragraph("LOW",      sty["label"]),
    ]]
    sev_t = Table(sev_data, colWidths=["25%"]*4)
    sev_t.setStyle(TableStyle([
        ("BACKGROUND",  (0,0),(-1,-1), C_PANEL),
        ("BOX",         (0,0),(-1,-1), 1, C_CRIT),
        ("ALIGN",       (0,0),(-1,-1), "CENTER"),
        ("VALIGN",      (0,0),(-1,-1), "MIDDLE"),
        ("PADDING",     (0,0),(-1,-1), 10),
        ("LINEBELOW",   (0,0),(-1,0), 0.5, C_META),
    ]))
    story.append(sev_t)
    story.append(Spacer(1, 12*mm))
    story.append(Paragraph("ANALYST NOTE: This report was generated with AI-assisted triage. "
                            "All findings should be independently verified before action. "
                            "Detection was performed by deterministic Sigma rules matched against "
                            "the provided event logs.", sty["small"]))
    story.append(PageBreak())

    # ── EXECUTIVE SUMMARY ──────────────────────────────────────────────
    story.append(Paragraph("01 · EXECUTIVE SUMMARY", sty["section"]))
    story.append(_divider())
    story.append(_stat_table(stats, sty))
    story.append(Spacer(1, 6*mm))
    total = stats.get("total_incidents", 0)
    crits = counts.get("critical", 0)
    highs = counts.get("high", 0)
    summary_text = (
        f"This investigation identified <b>{total} incident case file(s)</b> from "
        f"{stats.get('total_alerts',0)} raw detection signals — "
        f"a {stats.get('reduction',0)}% noise reduction through correlation. "
    )
    if crits:
        summary_text += (f"<b><font color='#E0483E'>{crits} CRITICAL case(s)</font></b> require "
                         "immediate containment action. ")
    if highs:
        summary_text += f"<b>{highs} HIGH-severity case(s)</b> require same-shift investigation. "
    summary_text += (f"A total of {stats.get('techniques_seen',0)} distinct MITRE ATT&CK techniques "
                     "were observed across the telemetry.")
    story.append(Paragraph(summary_text, sty["body"]))
    story.append(Spacer(1, 8*mm))

    # Case index table
    idx_data = [[
        Paragraph("CASE", sty["label"]),
        Paragraph("HOST", sty["label"]),
        Paragraph("SEVERITY", sty["label"]),
        Paragraph("ALERTS", sty["label"]),
        Paragraph("TECHNIQUES", sty["label"]),
        Paragraph("TIME WINDOW", sty["label"]),
    ]]
    for inc in incidents_data:
        sev = (inc.get("max_severity","?")).upper()
        sc  = _sev_color(inc.get("max_severity",""))
        cn  = f"CASE-{str(inc.get('case_number',0)).zfill(3)}"
        idx_data.append([
            Paragraph(cn, sty["mono"]),
            Paragraph(inc.get("host","?"), sty["small"]),
            Paragraph(sev, ParagraphStyle("si", fontSize=8, textColor=sc, fontName="Helvetica-Bold")),
            Paragraph(str(inc.get("alert_count",0)), sty["small"]),
            Paragraph((inc.get("mitre_techniques","") or "")[:30], sty["mono"]),
            Paragraph(f'{str(inc.get("start_time",""))[:16]} →', sty["small"]),
        ])
    idx_t = Table(idx_data, colWidths=[2.2*cm, 3.5*cm, 1.8*cm, 1.4*cm, 3.5*cm, None])
    idx_t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), C_DARK),
        ("BACKGROUND",    (0,1), (-1,-1), C_PANEL),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#0D1318"),colors.HexColor("#0A0E12")]),
        ("LINEBELOW",     (0,0), (-1,0), 0.5, C_ACCENT),
        ("BOX",           (0,0), (-1,-1), 0.5, C_META),
        ("INNERGRID",     (0,0), (-1,-1), 0.3, C_DARK),
        ("ALIGN",         (0,0), (-1,-1), "LEFT"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("PADDING",       (0,0), (-1,-1), 5),
    ]))
    story.append(idx_t)
    story.append(PageBreak())

    # ── PER-INCIDENT PAGES ─────────────────────────────────────────────
    for i, inc in enumerate(incidents_data):
        cn  = f"CASE-{str(inc.get('case_number',0)).zfill(3)}"
        sev = inc.get("max_severity","unknown")
        sc  = _sev_color(sev)

        story.append(Paragraph(f"02.{str(i+1).zfill(2)} · INCIDENT DETAIL — {cn}", sty["section"]))
        story.append(_divider(sc))
        story.append(_case_header_table(inc, sty, inc.get("case_number",i+1)))
        story.append(Spacer(1, 4*mm))

        # AI analyst note
        if inc.get("ai_summary"):
            ai_block = Table([[Paragraph(
                f'<font color="#FFB347" size="7">AI-DRAFTED · VERIFY BEFORE ACTING</font><br/>'
                f'{inc["ai_summary"]}', sty["ai_note"]
            )]])
            ai_block.setStyle(TableStyle([
                ("BACKGROUND", (0,0),(0,0), colors.HexColor("#100C00")),
                ("BOX",        (0,0),(0,0), 1, C_AMBER),
                ("PADDING",    (0,0),(0,0), 8),
            ]))
            story.append(ai_block)
            story.append(Spacer(1, 4*mm))

        # Two-column: MITRE + IOCs
        left_content = [
            Paragraph("MITRE ATT&amp;CK TECHNIQUES", sty["label"]),
            Spacer(1, 2*mm),
            _mitre_table(inc.get("mitre_techniques",""), sty),
            Spacer(1, 4*mm),
            Paragraph("DETECTION RULES FIRED", sty["label"]),
            Spacer(1, 2*mm),
        ]
        for rule in (inc.get("rule_names","") or "").split(","):
            rule = rule.strip()
            if rule:
                left_content.append(Paragraph(f"• {rule}", sty["small"]))

        right_content = [
            Paragraph("INDICATORS OF COMPROMISE", sty["label"]),
            Spacer(1, 2*mm),
        ]
        # Build a simple IOC structure from what we have
        iocs_simple = {"ips":[], "hashes":[], "domains":[]}
        if inc.get("source_ip"):
            iocs_simple["ips"].append(inc["source_ip"])
        right_content.append(_ioc_table(iocs_simple, sty))

        two_col = Table([[left_content, right_content]], colWidths=["55%","45%"])
        two_col.setStyle(TableStyle([
            ("VALIGN",  (0,0),(-1,-1), "TOP"),
            ("PADDING", (0,0),(-1,-1), 0),
            ("LINEAFTER",(0,0),(0,0), 0.5, C_META),
            ("RIGHTPADDING",(0,0),(0,0), 8),
            ("LEFTPADDING",(1,0),(1,0), 8),
        ]))
        story.append(two_col)
        story.append(Spacer(1, 4*mm))

        # Remediation
        story.append(_divider(C_META))
        story.append(Paragraph("REMEDIATION PLAYBOOK", sty["label"]))
        story.append(Spacer(1, 2*mm))
        story.append(_remediation_table(inc.get("remediation",[]), sty))

        if i < len(incidents_data) - 1:
            story.append(PageBreak())

    # ── TAIL ───────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Spacer(1, 2*cm))
    story.append(Paragraph("END OF REPORT", ParagraphStyle("end", fontSize=10, textColor=C_META,
                                                             fontName="Helvetica", alignment=TA_CENTER)))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph("HISN — Unified Threat Investigation & Analytics Tool",
                             ParagraphStyle("endh", fontSize=8, textColor=C_ACCENT,
                                             fontName="Helvetica-Bold", alignment=TA_CENTER)))
    story.append(Paragraph("AI-assisted analysis — all findings require independent verification.",
                             ParagraphStyle("endd", fontSize=7, textColor=C_META,
                                             fontName="Helvetica", alignment=TA_CENTER)))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf


def generate_document_report(result):
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                             leftMargin=1.5*cm, rightMargin=1.5*cm,
                             topMargin=3.5*cm, bottomMargin=2.2*cm)
    sty = _styles()
    story = []
    story.append(Paragraph("DOCUMENT TRIAGE REPORT", sty["section"]))
    story.append(_divider())
    story.append(Paragraph(f"File: {result.get(\'filename\',\'Unknown\')}", sty["body"]))
    story.append(Paragraph(f"Type: {result.get(\'file_type\',\'Unknown\')}", sty["body"]))
    story.append(Paragraph(f"SHA256: {result.get(\'sha256\',\'N/A\')}", sty["mono"]))
    story.append(Spacer(1, 4*mm))
    vt = result.get("vt_intel") or {}
    if vt.get("mode") == "live":
        mal = vt.get("malicious",0); tot = vt.get("total_engines",0)
        color_str = "#E0483E" if mal > 0 else "#4C8BA8"
        story.append(Paragraph(f\'<font color="{color_str}"><b>VirusTotal: {mal}/{tot} engines flagged malicious</b></font>\', sty["body"]))
    if result.get("macros_found"):
        story.append(Paragraph("<b>MACROS DETECTED</b>", ParagraphStyle("mw", fontSize=9, textColor=C_CRIT, fontName="Helvetica-Bold")))
        for kw in (result.get("suspicious_keywords") or []):
            story.append(Paragraph(f"• {kw}", sty["small"]))
    ind = result.get("text_indicators") or {}
    if ind.get("urls"):
        story.append(Paragraph("Extracted URLs:", sty["label"]))
        for u in ind["urls"][:10]:
            story.append(Paragraph(u, sty["mono"]))
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf
'''

with open('src/reports/pdf_report.py', 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print("pdf_report.py written.")