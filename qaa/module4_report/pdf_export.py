"""
Module 4b - PDF report generation via ReportLab.

Produces an executive-summary audit report: findings, risk distribution, the
prioritised migration roadmap, scoring methodology, and the NIST references the
recommendations rest on.
"""

from __future__ import annotations

import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from qaa.module3_reasoner.risk_engine import explain_score

LEVEL_COLOR = {
    "Critical": colors.HexColor("#B3261E"),
    "High": colors.HexColor("#E8710A"),
    "Medium": colors.HexColor("#B58900"),
    "Low": colors.HexColor("#3D7A3D"),
    "Informational": colors.HexColor("#5A6672"),
}

BRAND = colors.HexColor("#1B3A5C")


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("QTitle", parent=ss["Title"], fontSize=20,
                          textColor=BRAND, spaceAfter=4))
    ss.add(ParagraphStyle("QSub", parent=ss["Normal"], fontSize=10,
                          textColor=colors.HexColor("#5A6672"), spaceAfter=14))
    ss.add(ParagraphStyle("QH2", parent=ss["Heading2"], fontSize=13,
                          textColor=BRAND, spaceBefore=14, spaceAfter=6))
    ss.add(ParagraphStyle("QH3", parent=ss["Heading3"], fontSize=11,
                          textColor=colors.HexColor("#22303C"),
                          spaceBefore=8, spaceAfter=3))
    ss.add(ParagraphStyle("QBody", parent=ss["Normal"], fontSize=9,
                          leading=13, alignment=TA_LEFT))
    ss.add(ParagraphStyle("QSmall", parent=ss["Normal"], fontSize=7.5,
                          leading=10, textColor=colors.HexColor("#3A4550")))
    ss.add(ParagraphStyle("QCode", parent=ss["Normal"], fontName="Courier",
                          fontSize=6.8, leading=8.4,
                          textColor=colors.HexColor("#1A1A1A")))
    ss.add(ParagraphStyle("QCell", parent=ss["Normal"], fontSize=7.4,
                          leading=9.2))
    return ss


def _table(data, col_widths, header_bg=BRAND, font_size=7.4):
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), font_size),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C9D2DA")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#F4F7FA")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _esc(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def build_pdf(result, max_roadmap_rows: int = 40,
              max_snippets: int = 6) -> bytes:
    """Render an AuditResult to PDF bytes."""
    ss = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=15 * mm, bottomMargin=15 * mm,
        title="Quantum-Agility Audit Report",
        author="Quantum-Agility Auditor",
    )
    story = []
    s = result.summary()
    ctx = result.context

    # ---------------- Title ----------------
    story.append(Paragraph("Quantum-Agility Audit Report", ss["QTitle"]))
    story.append(Paragraph(
        f"System: <b>{_esc(ctx.system_name)}</b> &nbsp;|&nbsp; "
        f"Generated: {datetime.now().strftime('%d %B %Y, %H:%M')} &nbsp;|&nbsp; "
        f"Data classification: {_esc(ctx.data_sensitivity)} &nbsp;|&nbsp; "
        f"Expected lifespan: {ctx.system_lifespan_years} years",
        ss["QSub"]))

    # ---------------- Executive summary ----------------
    story.append(Paragraph("1. Executive Summary", ss["QH2"]))
    hndl = ("<b>This system is HNDL-exposed.</b> Its data must remain "
            "confidential beyond the expected arrival of a cryptographically "
            "relevant quantum computer, so any traffic captured today by an "
            "adversary is decryptable in the future. Key-exchange findings "
            "below are therefore already compromised, not merely at risk."
            if ctx.hndl_exposed else
            "This system falls inside the Harvest-Now-Decrypt-Later threshold, "
            "so no HNDL amplification was applied to the scores below.")
    story.append(Paragraph(
        f"The auditor examined <b>{s['total_findings']}</b> cryptographic "
        f"findings across code, configuration, dependency and network surfaces, "
        f"producing <b>{s['cbom_entries']}</b> Cryptographic Bill of Materials "
        f"entries. Of these, <b>{s['actionable']}</b> require migration: "
        f"<b>{s['critical']}</b> Critical, <b>{s['high']}</b> High, "
        f"<b>{s['medium']}</b> Medium and <b>{s['low']}</b> Low. "
        f"<b>{s['already_pqc']}</b> finding(s) already use a NIST post-quantum "
        f"standard and need no action.<br/><br/>{hndl}", ss["QBody"]))
    story.append(Spacer(1, 8))

    counts = result.level_counts()
    story.append(_table(
        [["Risk level", "Findings", "Meaning"]] +
        [[lvl, str(counts.get(lvl, 0)), desc] for lvl, desc in [
            ("Critical", "Score &gt; 8 - migrate immediately"),
            ("High", "Score 5-8 - migrate this planning cycle"),
            ("Medium", "Score 2-5 - schedule within the roadmap"),
            ("Low", "Score 0-2 - monitor"),
            ("Informational", "Already post-quantum - no action"),
        ]],
        [30 * mm, 22 * mm, 126 * mm]))

    # ---------------- Distribution ----------------
    story.append(Paragraph("2. Distribution by Algorithm and Surface",
                           ss["QH2"]))
    algs = result.algorithm_counts()
    surfs = result.surface_counts()
    rows = [["Algorithm", "Count", "Surface", "Count"]]
    keys_a, keys_s = list(algs.items()), list(surfs.items())
    for i in range(max(len(keys_a), len(keys_s))):
        a = keys_a[i] if i < len(keys_a) else ("", "")
        b = keys_s[i] if i < len(keys_s) else ("", "")
        rows.append([a[0], str(a[1]) if a[0] else "",
                     b[0], str(b[1]) if b[0] else ""])
    story.append(_table(rows, [50 * mm, 24 * mm, 50 * mm, 24 * mm]))

    # ---------------- Roadmap ----------------
    story.append(PageBreak())
    story.append(Paragraph("3. Prioritised Migration Roadmap", ss["QH2"]))
    story.append(Paragraph(
        "Ordered Critical first. Every replacement is keyed on the "
        "cryptographic <i>purpose</i> of the finding, not its algorithm name, "
        "so RSA used for key transport maps to ML-KEM while RSA used for "
        "signing maps to ML-DSA.", ss["QBody"]))
    story.append(Spacer(1, 6))

    head = [["#", "Lvl", "Score", "Algorithm", "Location", "Replacement",
             "NIST", "Effort"]]
    body = []
    for i, a in enumerate(result.actionable[:max_roadmap_rows], start=1):
        e = a.sbom_entry
        loc = f"{e.finding.file_path.split('/')[-1]}:{e.finding.line_number}"
        body.append([
            str(i), a.risk_level[:4], f"{a.risk_score:.1f}", e.algorithm,
            Paragraph(_esc(loc), ss["QCell"]),
            Paragraph(_esc(a.replacement), ss["QCell"]),
            Paragraph(_esc(a.nist_standard.replace("NIST ", "")), ss["QCell"]),
            a.effort,
        ])
    if not body:
        body = [["-", "-", "-", "No actionable findings", "", "", "", ""]]

    t = _table(head + body, [8 * mm, 12 * mm, 12 * mm, 20 * mm, 38 * mm,
                             30 * mm, 24 * mm, 14 * mm])
    for r, a in enumerate(result.actionable[:max_roadmap_rows], start=1):
        t.setStyle(TableStyle([
            ("TEXTCOLOR", (1, r), (2, r),
             LEVEL_COLOR.get(a.risk_level, colors.black)),
            ("FONTNAME", (1, r), (2, r), "Helvetica-Bold"),
        ]))
    story.append(t)
    if len(result.actionable) > max_roadmap_rows:
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            f"({len(result.actionable) - max_roadmap_rows} further findings "
            f"omitted from this table - see the exported CBOM for the complete "
            f"list.)", ss["QSmall"]))

    # ---------------- Top findings in detail ----------------
    story.append(PageBreak())
    story.append(Paragraph("4. Highest-Risk Findings in Detail", ss["QH2"]))
    for i, a in enumerate(result.actionable[:max_snippets], start=1):
        e = a.sbom_entry
        block = [
            Paragraph(f"4.{i} &nbsp; {_esc(e.algorithm)} &mdash; "
                      f"<font color='#{LEVEL_COLOR.get(a.risk_level).hexval()[2:]}'>"
                      f"{a.risk_level}</font> (score {a.risk_score:.2f})",
                      ss["QH3"]),
            Paragraph(
                f"<b>Location:</b> {_esc(e.finding.file_path)}:"
                f"{e.finding.line_number} &nbsp;|&nbsp; "
                f"<b>Surface:</b> {_esc(e.finding.surface)} &nbsp;|&nbsp; "
                f"<b>Detected by:</b> {_esc(e.detection_method)} "
                f"(confidence {e.confidence:.2f})<br/>"
                f"<b>Evidence:</b> <font face='Courier'>"
                f"{_esc(e.finding.snippet.strip()[:220])}</font><br/>"
                f"<b>Score derivation:</b> "
                f"<font face='Courier'>{_esc(explain_score(a.score_breakdown))}"
                f"</font><br/>"
                f"<b>Recommendation:</b> migrate to {_esc(a.replacement)} "
                f"({_esc(a.nist_standard)}, {_esc(a.nist_level)}). "
                f"Transitional option: {_esc(a.hybrid_option)}<br/>"
                f"<b>Performance:</b> {_esc(a.performance_note)}<br/>"
                f"<b>Effort:</b> {_esc(a.effort)} &mdash; "
                f"{_esc(a.effort_note)}", ss["QBody"]),
            Spacer(1, 4),
            Paragraph("Replacement code:", ss["QSmall"]),
        ]
        code = _esc(a.code_snippet).replace("\n", "<br/>").replace(" ", "&nbsp;")
        block.append(Paragraph(code, ss["QCode"]))
        block.append(Spacer(1, 10))
        story.append(KeepTogether(block))

    # ---------------- Methodology ----------------
    story.append(PageBreak())
    story.append(Paragraph("5. Scoring Methodology", ss["QH2"]))
    story.append(Paragraph(
        "Each finding is scored on five factors:<br/>"
        "<b>1. Algorithm severity</b> &mdash; intrinsic quantum vulnerability "
        "(Shor-breakable asymmetric primitives score highest).<br/>"
        "<b>2. Key size</b> &mdash; +2 where the observed key is below the "
        "NIST SP 800-131A floor.<br/>"
        "<b>3. Data sensitivity</b> &mdash; x1.5 for financial, medical or "
        "government data; x1.6 for defence.<br/>"
        "<b>4. HNDL exposure</b> &mdash; x1.3 where the system lifespan "
        "exceeds five years.<br/>"
        "<b>5. Exposure surface</b> &mdash; x1.10 for a primitive observed on "
        "the wire, x0.85 for one only declared in a dependency manifest.<br/><br/>"
        "A confidence adjustment then scales the result into [0.75, 1.0] of its "
        "value, so low-confidence findings are de-prioritised without being "
        "discarded. Thresholds: Critical &gt; 8, High &gt; 5, Medium &gt; 2.",
        ss["QBody"]))

    story.append(Paragraph("6. References", ss["QH2"]))
    for ref in [
        "NIST FIPS 203 &mdash; Module-Lattice-Based Key-Encapsulation "
        "Mechanism Standard (ML-KEM), August 2024.",
        "NIST FIPS 204 &mdash; Module-Lattice-Based Digital Signature Standard "
        "(ML-DSA), August 2024.",
        "NIST FIPS 205 &mdash; Stateless Hash-Based Digital Signature Standard "
        "(SLH-DSA), August 2024.",
        "NIST SP 800-131A Rev.2 &mdash; Transitioning the Use of Cryptographic "
        "Algorithms and Key Lengths.",
        "NIST SP 800-22 Rev.1a &mdash; A Statistical Test Suite for Random and "
        "Pseudorandom Number Generators.",
        "NSA CNSA 2.0 &mdash; Commercial National Security Algorithm Suite.",
        "CycloneDX 1.6 &mdash; Cryptography Bill of Materials specification.",
    ]:
        story.append(Paragraph(f"&bull; {ref}", ss["QSmall"]))
        story.append(Spacer(1, 2))

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Generated by the Quantum-Agility Auditor. Findings are produced by "
        "automated static and statistical analysis and should be confirmed by "
        "a security reviewer before remediation work is scheduled.",
        ss["QSmall"]))

    doc.build(story)
    return buf.getvalue()
