"""Generate an inert PDF from persisted computed evidence, not screenshot data."""
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

import reportlab
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


# ReportLab bundles Bitstream Vera with redistribution permissions. Embed it to
# preserve common Latin/Greek/Cyrillic text without relying on remote fonts.
FONT_DIRECTORY = Path(reportlab.__file__).parent / "fonts"
MAX_REPORT_FIELD_CHARS = 20000
for font_name, font_file in (("PhishLens", "Vera.ttf"), ("PhishLens-Bold", "VeraBd.ttf"), ("PhishLens-Italic", "VeraIt.ttf"), ("PhishLens-BoldItalic", "VeraBI.ttf")):
    if font_name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(font_name, str(FONT_DIRECTORY / font_file)))
pdfmetrics.registerFontFamily("PhishLens", normal="PhishLens", bold="PhishLens-Bold", italic="PhishLens-Italic", boldItalic="PhishLens-BoldItalic")


def generate_pdf(analysis: dict, report: dict, case: dict | None = None, include_raw=False) -> bytes:
    stream = BytesIO()
    modern = "assessment" in analysis or analysis.get("ml", {}).get("available", False)
    styles = getSampleStyleSheet()
    for name in styles.byName:
        style = styles[name]
        style.fontName = "PhishLens-Bold" if name in {"Title", "Heading1", "Heading2"} else "PhishLens-BoldItalic" if name == "Heading3" else "PhishLens"
    styles["Heading2"].keepWithNext = True
    styles["Heading3"].keepWithNext = True
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], textColor=colors.HexColor("#006f73"), spaceAfter=12))
    styles.add(ParagraphStyle(name="SmallText", parent=styles["BodyText"], fontSize=8, leading=11, spaceAfter=5))
    def paragraph(value, style="BodyText"):
        # User-controlled text is escaped, so ReportLab cannot interpret links/markup.
        value = "".join(c for c in str(value) if ord(c) >= 32 or c in "\n\t").replace("—", "-").replace("–", "-")
        if modern:
            value = value.replace('→','->')
        if len(value) > MAX_REPORT_FIELD_CHARS:
            value = value[:MAX_REPORT_FIELD_CHARS] + f"\n[Report field truncated at {MAX_REPORT_FIELD_CHARS:,} characters. The complete submitted field remains in the saved local analysis.]"
        return Paragraph(escape(value).replace("\n", "<br/>"), styles[style])
    review_description = "Offline evidence review - observed rule indicators and available model predictions, not confirmation of compromise." if modern else "Offline evidence review - heuristic risk estimate, not confirmation of compromise."
    story = [paragraph("PhishLens | Investigation Report", "ReportTitle"), paragraph(review_description, "SmallText"), Spacer(1, 5 * mm)]
    subject = analysis["subject"]
    subject_preview = subject if len(subject) <= 350 else subject[:350] + " [Preview truncated; submitted subject/input follows below.]"
    metadata = [("Report ID", report["id"]), ("Generated (UTC)", report["created_at"]), ("Analysis ID", analysis["id"]), ("Case ID", case["id"] if case else "Not promoted to an investigation"), ("Subject / input", subject_preview), ("Input type", analysis["kind"]), ("Heuristic risk" if modern else "Risk estimate", f"{analysis['risk']} | {analysis['score']}/100 rule points"), ("Case status", case["status"] if case else "Not applicable")]
    table = Table([[paragraph(k, "SmallText"), paragraph(v, "SmallText")] for k, v in metadata], colWidths=[42 * mm, 128 * mm])
    table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#edf5f5")), ("LINEBELOW", (0, 0), (-1, -1), .4, colors.HexColor("#c6d4d7")), ("LEFTPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story.extend([table, Spacer(1, 5 * mm)])
    if len(subject) > 350:
        # Table rows cannot span arbitrarily many pages. A normal paragraph can.
        story.append(paragraph("Submitted subject / input", "Heading2"))
        bounded_subject = subject[:MAX_REPORT_FIELD_CHARS]
        # Small paragraphs let the section begin in the first page's remaining
        # space instead of forcing one enormous keep-with-heading block.
        story.extend(paragraph(bounded_subject[start:start + 2000]) for start in range(0, len(bounded_subject), 2000))
        if len(subject) > MAX_REPORT_FIELD_CHARS:
            story.append(paragraph(f"[Report field truncated at {MAX_REPORT_FIELD_CHARS:,} characters. The complete submitted field remains in the saved local analysis.]", "SmallText"))
    story.extend([paragraph("Summary", "Heading2"), paragraph(analysis["summary"])])
    ml = analysis.get("ml", {"available": False, "reason": "No model metadata was stored with this historical analysis."})
    score_contract = ml.get("score_type") == "archive_calibrated_decision_score"
    assessment = analysis.get("assessment")
    if modern:
        story.append(paragraph("Machine learning and final assessment", "Heading2"))
        if ml.get("available"):
            if ml.get("prediction_warning"):
                story.append(paragraph(ml["prediction_warning"], "SmallText"))
            if score_contract:
                story.append(paragraph(f"ML classification: {ml.get('classification', 'Unknown')} | ML decision score: {100 * ml.get('decision_score', ml.get('phishing_probability', 0)):.2f}/100 (not confidence) | Model: {ml.get('model_version', 'Unknown')}", "SmallText"))
                story.append(paragraph("Archive sigmoid fitting is not verified representative deployment calibration. This score is not a probability that this message is malicious or safe.", "SmallText"))
            else:
                story.append(paragraph(f"ML classification: {ml.get('classification', 'Unknown')} | Calibrated phishing probability: {100 * ml.get('phishing_probability', 0):.2f}% | Model: {ml.get('model_version', 'Unknown')}", "SmallText"))
            distinction = "Model decision scores are distinct from heuristic points." if score_contract else "Model probabilities are distinct from heuristic scores."
            story.append(paragraph(f"Heuristic score remains {analysis['score']}/100 rule points ({analysis['risk']}). {distinction}", "SmallText"))
            if assessment:
                if score_contract:
                    story.append(paragraph(f"Final assessment: {assessment.get('label', 'Unknown')} | Method: {assessment.get('method', 'Unknown')} | Decision score: {100 * assessment.get('decision_score', assessment.get('phishing_probability', 0)):.2f}/100 | Decision threshold: {assessment.get('classification_threshold', 'Unknown')}", "SmallText"))
                else:
                    story.append(paragraph(f"Final assessment: {assessment.get('label', 'Unknown')} | Method: {assessment.get('method', 'Unknown')} | Probability: {100 * assessment.get('phishing_probability', 0):.2f}% | Decision threshold: {assessment.get('classification_threshold', 'Unknown')}", "SmallText"))
            for limitation in ml.get("limitations", []):
                story.append(paragraph("Model limitation: " + str(limitation), "SmallText"))
            story.append(paragraph(str(ml.get("validation_scope", "Dataset evaluation does not establish performance on future campaigns.")), "SmallText"))
        else:
            story.append(paragraph(ml.get("reason", "No trained model was available for this saved analysis."), "SmallText"))
            story.append(paragraph("Final assessment uses the existing heuristic observations. No ML prediction or probability was obtained.", "SmallText"))
    story.append(paragraph("Evidence and reasoning", "Heading2"))
    if not analysis["evidence"]:
        story.append(paragraph("No configured indicators detected. The input has not been verified safe."))
    for finding in analysis["evidence"]:
        story.extend([paragraph(f"{finding['severity']} | {finding['title']} (+{finding['weight']} rule points)", "Heading3"), paragraph(f"Source: {finding['source']}", "SmallText"), paragraph(finding["detail"]), Spacer(1, 2 * mm)])
    story.append(paragraph("Extracted links (never visited)", "Heading2"))
    for link in analysis["links"]:
        story.extend([paragraph(link["url"], "SmallText"), paragraph(link["reason"], "SmallText")])
    story.append(paragraph("Attachment inventory - static metadata only", "Heading2"))
    for attachment in analysis["attachments"]:
        story.extend([paragraph(f"{attachment['filename']} | {attachment['content_type']} | {attachment['size']} bytes", "SmallText"), paragraph("SHA-256: " + attachment["sha256"], "SmallText")])
    if not analysis["attachments"]:
        story.append(paragraph("No attachment metadata was found."))
    if analysis.get("email"):
        story.append(paragraph("Authentication observations", "Heading2"))
        for method, value in analysis["email"]["authentication"].items():
            story.append(paragraph(method + ": " + value, "SmallText"))
    if case:
        story.extend([paragraph("Analyst notes", "Heading2"), paragraph(case["notes"] or "No analyst notes.")])
        events = [paragraph(f"{event['at']} | {event['title']}: {event['detail']}", "SmallText") for event in case["timeline"]]
        story.append(KeepTogether([paragraph("Case timeline", "Heading2")] + events[:1]))
        story.extend(events[1:])
    limitations_text = "No URL fetching, DNS, domain age, reputation lookup, attachment execution, malware scan, or independent SPF/DKIM/DMARC validation was performed. Reported model probabilities, when present, are calibrated only for their documented evaluation distribution; they are not certainty about this message. Absence of evidence is not evidence of safety. Repeated copies of a rule family count once; rule scores are capped at 100." if modern else "No URL fetching, DNS, domain age, reputation lookup, attachment execution, malware scan, independent SPF/DKIM/DMARC validation, or calibrated confidence estimation was performed. Absence of evidence is not evidence of safety. Repeated copies of a rule family count once; rule scores are capped at 100."
    if score_contract:
        limitations_text = "No URL fetching, DNS/domain-age/reputation lookup, attachment execution, malware scanning or independent SPF/DKIM/DMARC verification occurred. Model scores are not validated inbox probabilities, confidence or safety. Each rule family counts once; scores are capped at100."
    story.extend([paragraph("Limitations and model status", "Heading2"), paragraph(ml.get("reason", "Historical analysis; model status was not recorded.")), paragraph(limitations_text)])
    if include_raw and analysis.get("email"):
        story.extend([paragraph("Submitted raw email (explicitly included)", "Heading2"), paragraph(analysis["email"]["raw"][:50000], "SmallText")])
        if len(analysis["email"]["raw"]) > 50000:
            story.append(paragraph("Raw content truncated at 50,000 characters for report size.", "SmallText"))
    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("PhishLens", 8)
        canvas.setFillColor(colors.HexColor("#52616b"))
        canvas.drawString(20 * mm, 12 * mm, "PhishLens | Local evidence review | " + report["created_at"])
        canvas.drawRightString(190 * mm, 12 * mm, f"Page {doc.page}")
        canvas.restoreState()
    doc = SimpleDocTemplate(stream, pagesize=A4, rightMargin=20 * mm, leftMargin=20 * mm, topMargin=18 * mm, bottomMargin=22 * mm, title="PhishLens Investigation Report", author="PhishLens", pageCompression=1, invariant=1)
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return stream.getvalue()
