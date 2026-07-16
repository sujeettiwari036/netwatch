from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import netwatch.database as db

app = FastAPI(
    title="Netwatch API",
    description="Backend API endpoints for Network Traffic Analyzer stats and alerts.",
    version="1.0.0"
)

# Enable CORS for localhost:3000 and any standard frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/stats/top-talkers")
def stats_top_talkers(limit: int = 10):
    """
    Returns top talker source IPs by aggregate traffic size.
    """
    return db.get_top_talkers(limit=limit, db_path=db.DB_NAME)

@app.get("/stats/protocol-breakdown")
def stats_protocol_breakdown():
    """
    Returns packet counts grouped by protocol.
    """
    return db.get_protocol_breakdown(db_path=db.DB_NAME)

@app.get("/packets/recent")
def packets_recent(limit: int = 100):
    """
    Returns the most recent N packets captured.
    """
    return db.get_recent_packets(limit=limit, db_path=db.DB_NAME)

@app.get("/alerts")
def alerts(limit: int = 100):
    """
    Returns recent security anomaly alerts.
    """
    return db.get_alerts(limit=limit, db_path=db.DB_NAME)

@app.get("/stats/bandwidth-timeline")
def stats_bandwidth_timeline():
    """
    Returns aggregate packet sizes in 10-second intervals for the last 5 minutes.
    """
    return db.get_bandwidth_timeline(db_path=db.DB_NAME)

@app.get("/report")
def generate_report():
    """
    Generates a PDF report of the packet capture session.
    """
    from fastapi.responses import StreamingResponse
    import io
    import datetime
    import math
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors

    summary = db.get_session_summary(db_path=db.DB_NAME)
    top_talkers = db.get_top_talkers(limit=5, db_path=db.DB_NAME)
    protocols = db.get_protocol_breakdown(db_path=db.DB_NAME)
    alerts = db.get_alerts(limit=1000, db_path=db.DB_NAME)

    def format_bytes_pdf(bytes):
        if not bytes or bytes == 0: return '0 B'
        k = 1024
        sizes = ['B', 'KB', 'MB', 'GB']
        i = int(math.floor(math.log(bytes) / math.log(k)))
        return f"{bytes / (k ** i):.2f} {sizes[i]}"

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    # Custom ParagraphStyles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=15
    )

    section_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#1e3b8b'),
        spaceBefore=12,
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#334155')
    )

    mono_style = ParagraphStyle(
        'MonoTextCustom',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#0f172a')
    )

    elements = []

    # Title & Metadata
    elements.append(Paragraph("Netwatch Traffic Analysis Report", title_style))
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    elements.append(Paragraph(f"Generated at: {now_str}", body_style))
    elements.append(Spacer(1, 15))

    # Summary section
    elements.append(Paragraph("1. Capture Session Summary", section_style))
    summary_data = [
        [
            Paragraph("<b>Total Packets:</b>", body_style),
            Paragraph(f"{summary['total_packets']:,}", mono_style),
            Paragraph("<b>Total Volume:</b>", body_style),
            Paragraph(format_bytes_pdf(summary['total_bytes']), mono_style)
        ]
    ]
    summary_table = Table(summary_data, colWidths=[120, 120, 120, 120])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 15))

    # Top Talkers section
    elements.append(Paragraph("2. Top 5 Traffic Talkers (Source IPs)", section_style))
    talkers_data = [["Rank", "Source IP", "Bytes Transmitted", "Packets Sent"]]
    for idx, t in enumerate(top_talkers[:5]):
        talkers_data.append([
            str(idx + 1),
            t["src_ip"],
            format_bytes_pdf(t["total_size"]),
            f"{t['packet_count']:,}"
        ])

    talkers_table = Table(talkers_data, colWidths=[50, 170, 150, 130])
    talkers_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e3a8a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')])
    ]))
    elements.append(talkers_table)
    elements.append(Spacer(1, 15))

    # Protocol Breakdown section
    elements.append(Paragraph("3. Protocol Breakdown", section_style))
    proto_data = [["Protocol", "Packet Count"]]
    for p in protocols:
        proto_data.append([
            p["protocol"],
            f"{p['count']:,}"
        ])

    proto_table = Table(proto_data, colWidths=[250, 250])
    proto_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e3a8a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')])
    ]))
    elements.append(proto_table)
    elements.append(Spacer(1, 15))

    # Alerts section
    elements.append(Paragraph("4. Logged Anomaly Alerts", section_style))
    if not alerts:
        elements.append(Paragraph("No anomalies detected during this session.", body_style))
    else:
        alerts_data = [["Timestamp", "Type", "Source IP", "Detail"]]
        for a in alerts:
            time_str = a["timestamp"].replace("T", " ")[:19]
            alerts_data.append([
                Paragraph(time_str, body_style),
                Paragraph(a["type"].upper(), body_style),
                Paragraph(a["ip"], body_style),
                Paragraph(a["detail"], body_style)
            ])

        alerts_table = Table(alerts_data, colWidths=[110, 90, 90, 210])
        alerts_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#ef4444')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#fca5a5')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#fee2e2')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#fef2f2')])
        ]))
        elements.append(alerts_table)

    doc.build(elements)
    buffer.seek(0)

    headers = {
        'Content-Disposition': 'attachment; filename="netwatch_report.pdf"'
    }
    return StreamingResponse(buffer, media_type="application/pdf", headers=headers)

# Mount the built frontend static files at root
from fastapi.staticfiles import StaticFiles
import os

dist_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"))
if os.path.exists(dist_dir):
    app.mount("/", StaticFiles(directory=dist_dir, html=True), name="static")


