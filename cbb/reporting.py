"""Render the frozen case snapshot into readable PDF and editable DOCX reports."""
from io import BytesIO
from html import escape
from pathlib import Path
import re
from .crypto import loads

def reports(case,version,entries,notes,verification,custody,ai):
    sections=[("Case report",case["title"]),("Scope",case.get("description") or "No scope recorded."),("Snapshot",f"Case {case['id']} · Version {version} · Status {case['status']}"),("Analyst conclusion",case.get("conclusion") or "No analyst conclusion recorded."),("Integrity",f"{verification['status']} / {verification['assurance']}; {verification['checked']} evidence records checked. Local verification is not independent witnessing or proof of truthful capture.")]
    for item in entries:
        sections.append(("Evidence · "+item["id"],f"Sequence: {item['sequence']}\nSource: {item['source_type']}\nEvent: {item['event_type']}\nOccurred: {item['occurred_at'] or 'Unknown'}\nReceived: {item['received_at']}\nObservation: {item['summary']}\nRaw SHA-256: {item['raw_sha256']}\nRecord hash: {item['record_hash']}\nOriginal bytes: {item['raw_path']}"))
    for note in notes:sections.append(("Analyst note · "+note["id"],f"Author: {note['author_id']} · {note['created_at']}\nSupersedes: {note.get('previous_id') or 'None'}\n{note['body']}"))
    for item in custody:sections.append(("Custody · "+str(item["sequence"]),f"{item['created_at']} · {item['actor']}\n{item['action']} → {item['target']}\nEntry hash: {item['entry_hash']}"))
    for item in ai:
        document=loads(item["document"]);review=loads(item.get("review"),{})
        sections.append(("Derived AI assistance · "+item["id"],f"Engine: {item['engine']}\nReview: {review.get('decision','UNREVIEWED')}\n{document['advice']['summary']}\nThis is derived advice, not original evidence. Full output, citations and review are in ai-assistance.json."))
    sections.append(("Limitations","The report preserves a selected case snapshot. It does not establish complete capture, absence of attack, legal admissibility or attribution. Acquired files, raw records, signatures and proof are included in the companion ZIP. Verify the original ZIP using a separately trusted public key. This editable report becomes a new derivative if modified."))
    # XML controls cannot be represented in Word/Paragraph markup. Preserve them
    # in original bytes/JSON while rendering explicit replacement characters here.
    clean=lambda s:re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]","\ufffd",s)
    sections=[(clean(heading),clean(body)) for heading,body in sections]
    from docx import Document
    from docx.shared import Inches,Pt,RGBColor
    doc=Document();sec=doc.sections[0];sec.header.paragraphs[0].text="CYBER BLACK BOX / INVESTIGATION REPORT"
    sec.top_margin=Inches(.8);sec.bottom_margin=Inches(.8)
    normal=doc.styles["Normal"];normal.font.name="Calibri";normal.font.size=Pt(10)
    for heading,body in sections:
        doc.add_heading(heading,0 if heading=="Case report" else 1)
        for line in body.splitlines():doc.add_paragraph(line)
    sec.footer.paragraphs[0].text="Controlled case snapshot · Verify the accompanying signed package"
    word=BytesIO();doc.save(word)
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    font="Helvetica"
    for path in (Path("C:/Windows/Fonts/arial.ttf"),Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")):
        if path.exists():
            if "CBBReport" not in pdfmetrics.getRegisteredFontNames():pdfmetrics.registerFont(TTFont("CBBReport",str(path)))
            font="CBBReport";break
    styles=getSampleStyleSheet()
    for name in ("BodyText","Heading1","Title"):
        styles[name].fontName=font;styles[name].wordWrap="CJK"
    styles["BodyText"].fontSize=9;styles["BodyText"].leading=14;styles["Heading1"].textColor=colors.HexColor("#214569")
    flow=[]
    for heading,body in sections:
        flow.extend([Paragraph(escape(heading),styles["Title"] if heading=="Case report" else styles["Heading1"]),Paragraph(escape(body).replace("\n","<br/>"),styles["BodyText"]),Spacer(1,12)])
    pdf=BytesIO()
    def page_footer(canvas,document):
        canvas.setFont(font,8);canvas.setFillColor(colors.HexColor("#718096"));canvas.drawString(42,28,"Cyber Black Box · Case "+case["id"]);canvas.drawRightString(550,28,str(document.page))
    SimpleDocTemplate(pdf,leftMargin=42,rightMargin=42,topMargin=42,bottomMargin=48,title=case["title"]).build(flow,onFirstPage=page_footer,onLaterPages=page_footer)
    return word.getvalue(),pdf.getvalue()
