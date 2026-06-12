"""
report_generator.py — VulnProbe PDF Report Generator

Generates a professional PDF report containing the security assessment findings,
executive summary, and detailed technical sections with GDPR and SOC 2 mappings.

Dependencies: reportlab
"""

import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Flowable
import html

# ---------------------------------------------------------------------------
# Constants & Data
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "Critical": "#E53E3E",
    "High": "#DD6B20",
    "Medium": "#D69E2E",
    "Low": "#38A169",
}

HARDCODED_VULN_DATA = {
    "SQLi": {
        "explanation": "SQL Injection allows an attacker to manipulate database queries by injecting malicious SQL code into input fields.",
        "impact": "Attacker could extract the entire donor database including names, emails, donation history, and payment records. Full database takeover is possible.",
        "fix": "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings. Apply input validation and least-privilege database accounts.",
        "gdpr": "GDPR Article 32 — failure to implement appropriate technical measures to ensure data security.",
        "soc2": "SOC 2 CC6.1 — logical and physical access controls; CC7.2 — system monitoring."
    },
    "XSS": {
        "explanation": "Cross-Site Scripting allows attackers to inject malicious scripts into pages viewed by other users.",
        "impact": "Attacker could steal donor session cookies, redirect users to phishing pages, or deface the donation portal — damaging donor trust.",
        "fix": "Encode all user-supplied output using context-aware escaping. Implement Content-Security-Policy headers. Validate and sanitize all inputs.",
        "gdpr": "GDPR Article 32 — inadequate protection of personal data processed through the web interface.",
        "soc2": "SOC 2 CC6.1 — access controls; CC9.2 — risk mitigation for third-party exposure."
    },
    "LFI": {
        "explanation": "Local File Inclusion allows an attacker to read arbitrary files from the server by manipulating file path parameters.",
        "impact": "Attacker could read server configuration files, application source code, and system files like /etc/passwd — exposing credentials and infrastructure details.",
        "fix": "Never use user input directly in file path operations. Use a whitelist of allowed files. Disable allow_url_include in PHP. Run application with minimal filesystem permissions.",
        "gdpr": "GDPR Article 32 — failure to ensure confidentiality of systems processing personal data.",
        "soc2": "SOC 2 CC6.6 — restriction of access to protected information assets."
    },
    "IDOR": {
        "explanation": "Insecure Direct Object Reference allows attackers to access other users' data by manipulating object identifiers in requests.",
        "impact": "Attacker could access any donor's personal profile, donation history, and contact details by simply changing an ID number in the URL.",
        "fix": "Implement server-side authorization checks on every object access. Use indirect references (GUIDs or hashed IDs). Never trust client-supplied IDs without verifying ownership.",
        "gdpr": "GDPR Article 5(1)(f) — failure to ensure appropriate integrity and confidentiality of personal data.",
        "soc2": "SOC 2 CC6.3 — role-based access control and authorization."
    },
    "File Upload": {
        "explanation": "Unrestricted file upload allows attackers to upload malicious files such as PHP web shells to the server.",
        "impact": "Attacker could achieve Remote Code Execution — full control of the server, ability to exfiltrate all donor data, or use the server as an attack platform.",
        "fix": "Validate file type by magic bytes, not extension. Whitelist allowed extensions. Store uploads outside webroot. Rename uploaded files. Disable script execution in upload directories.",
        "gdpr": "GDPR Article 32 — failure to ensure ongoing confidentiality, integrity, and availability of processing systems.",
        "soc2": "SOC 2 CC7.1 — vulnerability management; CC6.8 — controls to prevent unauthorized software."
    },
    "Directory Enumeration": {
        "explanation": "Exposed directories or sensitive files were discovered that should not be publicly accessible.",
        "impact": "Exposed admin panels, backup files, or configuration files could give attackers direct access to sensitive systems or donor data without authentication.",
        "fix": "Remove or restrict access to sensitive paths. Implement authentication on admin endpoints. Disable directory listing. Remove backup files from webroot. Return 404 for sensitive paths to avoid enumeration.",
        "gdpr": "GDPR Article 25 — failure to implement data protection by design and by default.",
        "soc2": "SOC 2 CC6.1 — logical access controls to restricted resources."
    },
    "CSRF": {
        "explanation": "Cross-Site Request Forgery tricks authenticated users into unknowingly submitting malicious requests.",
        "impact": "Attacker could force a logged-in donor or admin to transfer funds, change account details, or perform unauthorized actions without their knowledge.",
        "fix": "Implement CSRF tokens on all state-changing forms. Validate the Origin and Referer headers. Use SameSite=Strict cookie attribute.",
        "gdpr": "GDPR Article 32 — inadequate technical measures to protect against unauthorized processing.",
        "soc2": "SOC 2 CC6.6 — controls against unauthorized access from external sources."
    },
    "Default Credentials": {
        "explanation": "The application accepted well-known default username and password combinations.",
        "impact": "Attacker could log in as administrator with no effort, gaining full access to donor records, financial data, and system configuration.",
        "fix": "Force password change on first login. Implement account lockout after 5 failed attempts. Ban known default credentials. Require strong passwords (min 12 chars, complexity rules).",
        "gdpr": "GDPR Article 32 — failure to ensure ongoing confidentiality through appropriate authentication controls.",
        "soc2": "SOC 2 CC6.1 — user authentication and access control policies."
    },
    "Weak Session Token": {
        "explanation": "Session tokens are short or predictable, making them vulnerable to brute-force or guessing attacks.",
        "impact": "Attacker could guess or brute-force a valid session token and hijack a donor or admin session without knowing their password.",
        "fix": "Use cryptographically secure random session token generation with at least 128 bits of entropy. Regenerate tokens on login. Set Secure and HttpOnly cookie flags.",
        "gdpr": "GDPR Article 32 — inadequate pseudonymisation and encryption of authentication data.",
        "soc2": "SOC 2 CC6.1 — logical access controls; CC6.7 — transmission of data protection."
    },
    "ReflectedXSS": {
        "explanation": "Cross-Site Scripting allows attackers to inject malicious scripts into pages viewed by other users.",
        "impact": "Attacker could steal donor session cookies, redirect users to phishing pages, or deface the donation portal — damaging donor trust.",
        "fix": "Encode all user-supplied output using context-aware escaping. Implement Content-Security-Policy headers. Validate and sanitize all inputs.",
        "gdpr": "GDPR Article 32 — inadequate protection of personal data processed through the web interface.",
        "soc2": "SOC 2 CC6.1 — access controls; CC9.2 — risk mitigation for third-party exposure."
    },
    "Parameter Tampering": {
        "explanation": "Insecure Direct Object Reference allows attackers to access other users' data by manipulating object identifiers in requests.",
        "impact": "Attacker could access any donor's personal profile, donation history, and contact details by simply changing an ID number in the URL.",
        "fix": "Implement server-side authorization checks on every object access. Use indirect references (GUIDs or hashed IDs). Never trust client-supplied IDs without verifying ownership.",
        "gdpr": "GDPR Article 5(1)(f) — failure to ensure appropriate integrity and confidentiality of personal data.",
        "soc2": "SOC 2 CC6.3 — role-based access control and authorization."
    },
    "Missing Header": {
        "explanation": "Important HTTP security headers are missing from server responses.",
        "impact": "Missing headers expose donors to clickjacking, MIME sniffing, and cross-site scripting attacks, putting their personal and financial data at risk.",
        "fix": "Add X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Content-Security-Policy, and Strict-Transport-Security headers to all responses.",
        "gdpr": "GDPR Article 25 — Data Protection by Design",
        "soc2": "SOC 2 CC6.1 — Logical Access Controls"
    }
}

# ---------------------------------------------------------------------------
# Custom Flowables
# ---------------------------------------------------------------------------

class StatBoxesFlowable(Flowable):
    def __init__(self, counts):
        Flowable.__init__(self)
        self.counts = counts
        self.width = 532
        self.height = 80
        
    def wrap(self, availWidth, availHeight):
        return (self.width, self.height)
        
    def draw(self):
        c = self.canv
        c.saveState()
        
        boxes = [
            ("CRITICAL", self.counts.get("Critical", 0), SEVERITY_COLORS["Critical"]),
            ("HIGH", self.counts.get("High", 0), SEVERITY_COLORS["High"]),
            ("MEDIUM", self.counts.get("Medium", 0), SEVERITY_COLORS["Medium"]),
            ("LOW", self.counts.get("Low", 0), SEVERITY_COLORS["Low"])
        ]
        
        box_width = 120
        box_height = 80
        gap = (self.width - (4 * box_width)) / 3.0
        
        for i, (label, count, color) in enumerate(boxes):
            x = i * (box_width + gap)
            y = 0
            c.setFillColor(colors.HexColor(color))
            c.roundRect(x, y, box_width, box_height, 6, fill=1, stroke=0)
            
            c.setFillColor(colors.white)
            c.setFont("Helvetica-Bold", 28)
            c.drawCentredString(x + box_width/2, y + 35, str(count))
            
            c.setFont("Helvetica-Bold", 10)
            c.drawCentredString(x + box_width/2, y + 15, label)
            
        c.restoreState()


class CircleIcon(Flowable):
    def __init__(self, text, color):
        Flowable.__init__(self)
        self.text = text
        self.color = color
        self.size = 14
        
    def wrap(self, availWidth, availHeight):
        return (self.size, self.size)
        
    def draw(self):
        self.canv.saveState()
        self.canv.setFillColor(colors.HexColor(self.color))
        self.canv.circle(self.size/2.0, self.size/2.0, self.size/2.0, fill=1, stroke=0)
        self.canv.setFillColor(colors.white)
        self.canv.setFont("Helvetica-Bold", 10)
        # Shift text down slightly for visual centering
        self.canv.drawCentredString(self.size/2.0, self.size/2.0 - 3.5, self.text)
        self.canv.restoreState()


# ---------------------------------------------------------------------------
# PDF Layout Helpers
# ---------------------------------------------------------------------------

def _draw_header_footer(canvas, doc):
    canvas.saveState()
    
    # Header (Dark Navy)
    canvas.setFillColor(colors.HexColor("#0f172a"))
    canvas.rect(0, doc.pagesize[1] - 40, doc.pagesize[0], 40, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 12)
    canvas.drawString(40, doc.pagesize[1] - 25, "VulnProbe")
    
    canvas.setFillColor(colors.HexColor("#94a3b8"))
    canvas.setFont("Helvetica", 10)
    canvas.drawCentredString(doc.pagesize[0]/2.0, doc.pagesize[1] - 25, "Security Assessment Report")
    
    canvas.setFillColor(colors.white)
    canvas.drawRightString(doc.pagesize[0] - 40, doc.pagesize[1] - 25, str(doc.page))
    
    # Footer (Accent line + text)
    canvas.setStrokeColor(colors.HexColor("#6366f1"))
    canvas.setLineWidth(1)
    canvas.line(40, 40, doc.pagesize[0] - 40, 40)
    
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.setFont("Helvetica", 9)
    canvas.drawString(40, 25, "CONFIDENTIAL")
    canvas.drawRightString(doc.pagesize[0] - 40, 25, "VulnProbe v1.0")
    
    canvas.restoreState()


def make_accent_title(title_text):
    t = Table([["", title_text]], colWidths=[6, 500])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,0), colors.HexColor("#6366f1")),
        ('FONTNAME', (1,0), (1,0), "Helvetica-Bold"),
        ('FONTSIZE', (1,0), (1,0), 18),
        ('TEXTCOLOR', (1,0), (1,0), colors.HexColor("#0f172a")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (1,0), (1,0), 10),
        ('BOTTOMPADDING', (1,0), (1,0), 0),
        ('TOPPADDING', (1,0), (1,0), 0),
    ]))
    return t


def make_summary_box(text, styles):
    p = Paragraph(text, styles['Normal'])
    t = Table([["", p]], colWidths=[4, 520])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,0), colors.HexColor("#6366f1")),
        ('BACKGROUND', (1,0), (1,0), colors.HexColor("#f8fafc")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('LEFTPADDING', (1,0), (1,0), 15),
        ('RIGHTPADDING', (1,0), (1,0), 15),
        ('TOPPADDING', (1,0), (1,0), 15),
        ('BOTTOMPADDING', (1,0), (1,0), 15),
    ]))
    return t


def make_badge(text, color_hex):
    t = Table([[text]])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,0), colors.HexColor(color_hex)),
        ('TEXTCOLOR', (0,0), (0,0), colors.white),
        ('FONTNAME', (0,0), (0,0), "Helvetica-Bold"),
        ('FONTSIZE', (0,0), (0,0), 9),
        ('TOPPADDING', (0,0), (0,0), 2),
        ('BOTTOMPADDING', (0,0), (0,0), 2),
        ('LEFTPADDING', (0,0), (0,0), 6),
        ('RIGHTPADDING', (0,0), (0,0), 6),
        ('ALIGN', (0,0), (0,0), 'CENTER'),
        ('VALIGN', (0,0), (0,0), 'MIDDLE'),
    ]))
    return t

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report(target_url: str, findings: list[dict], output_path: str) -> str:
    """Generate a PDF report of scan findings using ReportLab."""
    
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=60,
        bottomMargin=60
    )
    
    styles = getSampleStyleSheet()
    normal_style = styles['Normal']
    normal_style.fontSize = 10
    normal_style.leading = 14
    normal_style.textColor = colors.HexColor("#334155")
    
    bold_style = ParagraphStyle("BoldNormal", parent=normal_style, fontName="Helvetica-Bold", textColor=colors.HexColor("#0f172a"))
    mono_style = ParagraphStyle("Mono", parent=normal_style, fontName="Courier", fontSize=9, textColor=colors.HexColor("#0f172a"))
    
    # --- Metrics ---
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Low")
        if sev in counts:
            counts[sev] += 1
        else:
            counts["Low"] += 1
            
    if counts["Critical"] > 0:
        overall_risk = "CRITICAL"
        risk_color = SEVERITY_COLORS["Critical"]
    elif counts["High"] > 0:
        overall_risk = "HIGH"
        risk_color = SEVERITY_COLORS["High"]
    elif counts["Medium"] > 0:
        overall_risk = "MEDIUM"
        risk_color = SEVERITY_COLORS["Medium"]
    else:
        overall_risk = "LOW"
        risk_color = SEVERITY_COLORS["Low"]
        
    date_str = datetime.date.today().strftime("%Y-%m-%d")

    # ══════════════════════════════════════════════════════════════════════════
    # 1. COVER PAGE (Custom Canvas)
    # ══════════════════════════════════════════════════════════════════════════
    def _draw_cover(canvas, doc):
        canvas.saveState()
        # Dark navy background
        canvas.setFillColor(colors.HexColor("#0f172a"))
        canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=1, stroke=0)
        
        # VP Monogram
        canvas.setFillColor(colors.HexColor("#6366f1"))
        canvas.rect(40, doc.pagesize[1] - 120, 60, 60, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 24)
        canvas.drawCentredString(70, doc.pagesize[1] - 92, "VP")
        
        # VULNPROBE
        canvas.setFont("Helvetica-Bold", 36)
        canvas.drawString(120, doc.pagesize[1] - 95, "VULNPROBE")
        
        # Subtitle
        canvas.setFillColor(colors.HexColor("#94a3b8"))
        canvas.setFont("Helvetica", 16)
        canvas.drawString(120, doc.pagesize[1] - 115, "Security Assessment Report")
        
        # Accent line
        canvas.setStrokeColor(colors.HexColor("#6366f1"))
        canvas.setLineWidth(2)
        canvas.line(40, doc.pagesize[1] - 150, doc.pagesize[0] - 40, doc.pagesize[1] - 150)
        
        # Details
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 14)
        canvas.drawString(40, doc.pagesize[1] - 250, "Target:")
        canvas.setFont("Helvetica", 14)
        canvas.drawString(120, doc.pagesize[1] - 250, target_url)
        
        canvas.setFont("Helvetica-Bold", 14)
        canvas.drawString(40, doc.pagesize[1] - 280, "Date:")
        canvas.setFont("Helvetica", 14)
        canvas.drawString(120, doc.pagesize[1] - 280, date_str)
        
        canvas.setFont("Helvetica-Bold", 14)
        canvas.drawString(40, doc.pagesize[1] - 310, "Assessor:")
        canvas.setFont("Helvetica", 14)
        canvas.drawString(120, doc.pagesize[1] - 310, "VulnProbe Automated System")
        
        # Overall Risk
        canvas.setFont("Helvetica-Bold", 14)
        canvas.drawString(40, doc.pagesize[1] - 400, "Overall Risk Level:")
        
        canvas.setFillColor(colors.HexColor(risk_color))
        # badge dimensions
        canvas.roundRect(40, doc.pagesize[1] - 470, 200, 50, 25, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 18)
        canvas.drawCentredString(140, doc.pagesize[1] - 452, overall_risk)
        
        # Footer
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.setFont("Helvetica", 10)
        canvas.drawString(40, 40, "CONFIDENTIAL — Authorized Use Only")
        
        canvas.restoreState()

    # Force the first page to just contain the canvas cover
    elements = []
    elements.append(Spacer(1, 1))
    elements.append(PageBreak())
    
    # ══════════════════════════════════════════════════════════════════════════
    # 2. EXECUTIVE SUMMARY
    # ══════════════════════════════════════════════════════════════════════════
    elements.append(make_accent_title("Executive Summary"))
    elements.append(Spacer(1, 25))
    
    # Stat Boxes (Canvas)
    elements.append(StatBoxesFlowable(counts))
    elements.append(Spacer(1, 25))
    
    # Breakdown Table
    table_data = [["Severity", "Findings Count"]]
    for sev in ["Critical", "High", "Medium", "Low"]:
        table_data.append([sev, str(counts[sev])])
        
    t = Table(table_data, colWidths=[200, 200], hAlign='LEFT')
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 25))
    
    # Summary Paragraph
    total_findings = len(findings)
    summary_text = (
        f"The VulnProbe automated scan identified <b>{total_findings}</b> vulnerabilities across the target application. "
        f"Among these, <b>{counts['Critical']}</b> critical issues and <b>{counts['High']}</b> high-severity issues "
        f"were discovered. Immediate remediation of critical and high-severity findings is recommended to prevent system compromise."
    )
    elements.append(make_summary_box(summary_text, styles))
    
    elements.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # 3. FINDINGS SECTION
    # ══════════════════════════════════════════════════════════════════════════
    elements.append(make_accent_title("Detailed Findings"))
    elements.append(Spacer(1, 20))
    
    if not findings:
        elements.append(Paragraph("No vulnerabilities were detected.", normal_style))
        
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    sorted_findings = sorted(findings, key=lambda x: sev_order.get(x.get("severity", "Low"), 9))
    
    for i, f in enumerate(sorted_findings, 1):
        vuln_type = f.get("vuln_type", "Unknown")
        severity = f.get("severity", "Low")
        color_hex = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["Low"])
        
        # Build the inner contents of the card
        
        # 1. Header Row
        header_p = Paragraph(f"<font color='white'><b>#{i} — {vuln_type}</b></font>", normal_style)
        header_t = Table([[header_p]], colWidths=[510])
        header_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#1e293b")),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
        ]))
        
        # 2. Metadata (2 columns)
        param = f.get("parameter") or f.get("field") or "N/A"
        payload = f.get("payload") or "N/A"
        
        meta_left = f"<b>Parameter:</b> {html.escape(str(param))}<br/><b>Payload:</b> {html.escape(str(payload))}"
        badge = make_badge(severity.upper(), color_hex)
        
        meta_t = Table([
            [Paragraph(meta_left, normal_style), badge]
        ], colWidths=[400, 100])
        meta_t.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ALIGN', (1,0), (1,0), 'RIGHT'),
            ('TOPPADDING', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ]))
        
        # 3. Evidence Box
        evidence_text = str(f.get("evidence", ""))[:300]
        if not evidence_text: evidence_text = "No evidence provided."
        
        ev_t = Table([[Paragraph(html.escape(evidence_text).replace('\\n', '<br/>'), mono_style)]], colWidths=[510])
        ev_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        
        # 4. Info Sections — exact match first, then case-insensitive substring fallback
        meta_data = HARDCODED_VULN_DATA.get(vuln_type)
        if meta_data is None:
            vt_lower = vuln_type.lower()
            for known_key in HARDCODED_VULN_DATA:
                if known_key.lower() in vt_lower:
                    meta_data = HARDCODED_VULN_DATA[known_key]
                    break
            if meta_data is None:
                meta_data = {}
        expl = meta_data.get("explanation", "No description available.")
        imp = meta_data.get("impact", "Unknown impact.")
        fix = meta_data.get("fix", "No remediation provided.")
        
        def make_info_row(icon_char, icon_color, title, text):
            icon = CircleIcon(icon_char, icon_color)
            content = Paragraph(f"<b>{title}</b><br/>{text}", normal_style)
            rt = Table([[icon, content]], colWidths=[25, 480])
            rt.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ]))
            return rt
            
        info_rows = []
        info_rows.append(make_info_row("i", "#3b82f6", "What it means", expl))
        info_rows.append(make_info_row("!", "#ef4444", "Business Impact", imp))
        info_rows.append(make_info_row("✓", "#10b981", "Remediation", fix))
        
        # Combine all into a single outer card table
        card_content = [
            [header_t],
            [meta_t],
            [ev_t],
            [Spacer(1, 5)],
            [info_rows[0]],
            [info_rows[1]],
            [info_rows[2]],
        ]
        
        card_table = Table(card_content, colWidths=[520])
        card_table.setStyle(TableStyle([
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
            ('LINELEFT', (0,0), (-1,-1), 4, colors.HexColor(color_hex)),
            ('LEFTPADDING', (0,0), (-1,-1), 15),
            ('RIGHTPADDING', (0,0), (-1,-1), 15),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
            # remove padding around the inner tables to let them stretch
            ('LEFTPADDING', (0,0), (0,0), 0),
            ('RIGHTPADDING', (0,0), (0,0), 0),
            ('TOPPADDING', (0,0), (0,0), 0),
        ]))
        
        elements.append(card_table)
        elements.append(Spacer(1, 20))

    # Build Document using custom page handlers
    def _on_first_page(canvas, document):
        _draw_cover(canvas, document)
        
    def _on_later_pages(canvas, document):
        _draw_header_footer(canvas, document)

    # Insert a dummy flowable at the beginning just to force the first page layout without consuming space
    # (Since the cover is drawn entirely in canvas in _on_first_page)
    doc.build(elements, onFirstPage=_on_first_page, onLaterPages=_on_later_pages)
    
    return output_path


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Test with dummy findings
    test_findings = [
        {"vuln_type": "SQLi", "parameter": "id", "payload": "' OR 1=1--", "evidence": "MySQL error detected", "severity": "Critical"},
        {"vuln_type": "XSS", "parameter": "search", "payload": "<script>alert(1)</script>", "evidence": "Payload reflected in response", "severity": "High"},
        {"vuln_type": "LFI", "parameter": "filename", "payload": "../../../etc/passwd", "evidence": "root:x:0:0:root:/root:/bin/bash", "severity": "Medium"},
        {"vuln_type": "File Upload", "parameter": "file", "payload": "shell.php", "evidence": "File successfully uploaded and executed", "severity": "Critical"},
    ]
    path = generate_report("http://testapp.local", test_findings, "test_report.pdf")
    print(f"Report saved to {path}")
