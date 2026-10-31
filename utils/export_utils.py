"""Report generation and export utilities (CSV & PDF) for ThreatGuard."""

import io
from datetime import datetime
from typing import Any, Dict, List, Optional
import pandas as pd

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def export_dataframe_to_csv(df: pd.DataFrame) -> bytes:
    """Serialize a Pandas DataFrame into UTF-8 CSV bytes."""
    return df.to_csv(index=False).encode("utf-8")


def generate_security_pdf_report(
    kpis: Dict[str, int],
    incidents: List[Dict[str, Any]],
    generated_by: str = "ThreatGuard SOC Analyst",
    report_title: str = "ThreatGuard Executive Cyber Incident Report",
) -> bytes:
    """Generate a high-level executive cybersecurity PDF report using ReportLab.
    
    Includes executive KPI overview, detected incident audit table, and recommendations.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0B0F19"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748B"),
        spaceAfter=12,
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=14,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )
    cell_style = ParagraphStyle(
        "CellBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1E293B"),
    )
    cell_bold = ParagraphStyle(
        "CellBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1E293B"),
    )

    story = []

    # Title & Metadata
    story.append(Paragraph(f"🛡️ {report_title}", title_style))
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(
        Paragraph(
            f"<b>Generated:</b> {now_str} | <b>Operator:</b> {generated_by} | "
            f"<b>Platform:</b> ThreatGuard SIEM Defense Simulation",
            subtitle_style,
        )
    )
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#00D2FF"), spaceAfter=14))

    # Executive Summary
    story.append(Paragraph("1. Executive Summary & Telemetry Overview", section_heading))
    summary_text = (
        "This defensive security report compiles telemetry and detection indicators analyzed by the "
        "ThreatGuard platform. It summarizes observed threat vectors, severity classifications, and "
        "remediation actions recorded in the active incident database."
    )
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 8))

    # KPI Summary Table
    kpi_data = [
        [
            Paragraph("<b>Total Security Logs</b>", cell_bold),
            Paragraph("<b>Threats Detected</b>", cell_bold),
            Paragraph("<b>Critical Incidents</b>", cell_bold),
            Paragraph("<b>High-Risk Incidents</b>", cell_bold),
            Paragraph("<b>Resolved</b>", cell_bold),
            Paragraph("<b>Pending Triage</b>", cell_bold),
        ],
        [
            Paragraph(str(kpis.get("total_security_events", 0)), cell_style),
            Paragraph(str(kpis.get("total_threats_detected", 0)), cell_style),
            Paragraph(str(kpis.get("critical_incidents", 0)), cell_style),
            Paragraph(str(kpis.get("high_risk_incidents", 0)), cell_style),
            Paragraph(str(kpis.get("resolved_incidents", 0)), cell_style),
            Paragraph(str(kpis.get("pending_incidents", 0)), cell_style),
        ],
    ]
    t_kpi = Table(kpi_data, colWidths=[90, 90, 90, 90, 90, 90])
    t_kpi.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(t_kpi)
    story.append(Spacer(1, 14))

    # Incident Details Table
    story.append(Paragraph("2. Detected Cybersecurity Incidents (Top Records)", section_heading))
    if not incidents:
        story.append(Paragraph("<i>No incidents currently on record.</i>", body_style))
    else:
        table_rows = [
            [
                Paragraph("<b>ID</b>", cell_bold),
                Paragraph("<b>Threat Category</b>", cell_bold),
                Paragraph("<b>Source IP</b>", cell_bold),
                Paragraph("<b>Severity</b>", cell_bold),
                Paragraph("<b>Risk</b>", cell_bold),
                Paragraph("<b>Status</b>", cell_bold),
                Paragraph("<b>Created At</b>", cell_bold),
            ]
        ]
        # Include up to 25 recent incidents in PDF
        for inc in incidents[:25]:
            sev = inc.get("severity", "LOW")
            table_rows.append(
                [
                    Paragraph(f"#{inc.get('id', '')}", cell_style),
                    Paragraph(str(inc.get("category", "")), cell_style),
                    Paragraph(str(inc.get("source_ip", "") or "N/A"), cell_style),
                    Paragraph(sev, cell_style),
                    Paragraph(str(inc.get("risk_score", "")), cell_style),
                    Paragraph(str(inc.get("status", "")), cell_style),
                    Paragraph(str(inc.get("created_at", ""))[:16], cell_style),
                ]
            )

        t_inc = Table(table_rows, colWidths=[35, 120, 95, 60, 45, 75, 110])
        t_inc.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B0F19")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(t_inc)

    story.append(Spacer(1, 14))

    # Key Security Recommendations
    story.append(Paragraph("3. Recommended Hardening & Response Actions", section_heading))
    recs = [
        "<b>Authentication Enforcement:</b> Enforce multi-factor authentication (MFA) and adaptive rate-limiting on all web endpoints.",
        "<b>Web Application Defense:</b> Audit queries for parameterization (prepared statements) and mandate Content Security Policy (CSP) headers.",
        "<b>Perimeter Visibility:</b> Reconfigure perimeter firewalls to drop reconnaissance sweeps and monitor non-standard egress port activity.",
        "<b>Analyst Verification:</b> Conduct forensic examination of flagged source IP addresses before applying permanent blocklists.",
    ]
    for r in recs:
        story.append(Paragraph(f"• {r}", body_style))
        story.append(Spacer(1, 3))

    # Academic Disclaimer
    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8))
    disclaimer = (
        "<b>Academic Project Notice:</b> ThreatGuard is an educational defensive cybersecurity monitoring and "
        "incident response platform built for Computer Science Engineering demonstration. Scores and detections "
        "reflect rule-based heuristics rather than enterprise SIEM guarantees."
    )
    story.append(Paragraph(disclaimer, subtitle_style))

    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
