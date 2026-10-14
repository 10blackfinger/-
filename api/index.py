import os
import io
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, HTMLResponse, Response
from pydantic import BaseModel


app = FastAPI(title="10blackfingers API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----- Lazy Supabase client -----
_supabase_client = None

def get_supabase():
    global _supabase_client
    if _supabase_client is None:
        from supabase import create_client
        url = os.getenv("SUPABASE_URL", "")
        key = os.getenv("SUPABASE_SERVICE_KEY", "")
        if not url or not key:
            raise RuntimeError("Supabase credentials missing")
        _supabase_client = create_client(url, key)
    return _supabase_client


# ----- Models -----
class ScanRequest(BaseModel):
    url: str
    consent: bool
    session_id: str


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


# ----- Routes -----
@app.get("/")
def root():
    return {
        "name": "10blackfingers API",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/api")
def api_root():
    return {
        "name": "10blackfingers API",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/api/scan", response_model=ScanResponse)
async def create_scan(request: ScanRequest):
    import uuid
    import httpx

    if not request.consent:
        raise HTTPException(status_code=400, detail="Consent is required")

    scan_id = str(uuid.uuid4())
    target_url = request.url

    try:
        sb = get_supabase()
        sb.table("scans").insert({
            "id": scan_id,
            "target_url": target_url,
            "status": "pending",
            "session_id": request.session_id,
        }).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB error: {str(e)}")

    github_token = os.getenv("GITHUB_TOKEN", "")
    github_repo = os.getenv("GITHUB_REPO", "10blackfinger/-")
    if github_token:
        try:
            url = f"https://api.github.com/repos/{github_repo}/actions/workflows/security-scan.yml/dispatches"
            headers = {
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            payload = {
                "ref": "main",
                "inputs": {"scan_id": scan_id, "target_url": target_url},
            }
            async with httpx.AsyncClient(timeout=30.0) as client:
                await client.post(url, headers=headers, json=payload)
        except Exception:
            pass

    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        message="Scan has been queued successfully"
    )


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    try:
        sb = get_supabase()
        scan_result = sb.table("scans").select("*").eq("id", scan_id).execute()
        if not scan_result.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        results = sb.table("results").select("*").eq("scan_id", scan_id).execute()
        return {"scan": scan_result.data[0], "results": results.data or []}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fetch error: {str(e)}")


@app.get("/api/scans")
async def list_scans(session_id: str, limit: int = 10):
    try:
        sb = get_supabase()
        scans = sb.table("scans") \
            .select("*") \
            .eq("session_id", session_id) \
            .order("created_at", desc=True) \
            .limit(limit) \
            .execute()
        return {"scans": scans.data or []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"List error: {str(e)}")


# ============================================================
# REPORT ENDPOINTS
# ============================================================

def fetch_report_data(scan_id: str):
    """Fetch scan, results, and logs for report generation."""
    sb = get_supabase()

    scan_res = sb.table("scans").select("*").eq("id", scan_id).execute()
    if not scan_res.data:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scan_res.data[0]

    results_res = sb.table("results").select("*").eq("scan_id", scan_id).execute()
    results = results_res.data or []

    logs_res = sb.table("logs").select("*").eq("scan_id", scan_id).order("created_at").execute()
    logs = logs_res.data or []

    return scan, results, logs


def build_txt_report(scan, results):
    lines = []
    lines.append("=" * 70)
    lines.append("  10blackfingers - Security Assessment Report")
    lines.append("=" * 70)
    lines.append(f"Target URL:  {scan.get('target_url', 'N/A')}")
    lines.append(f"Scan ID:     {scan.get('id', 'N/A')}")
    lines.append(f"Started:     {scan.get('started_at', 'N/A')}")
    lines.append(f"Completed:   {scan.get('completed_at', 'N/A')}")
    lines.append(f"Status:      {scan.get('status', 'N/A')}")
    lines.append("")
    lines.append("-" * 70)
    lines.append("  EXECUTIVE SUMMARY")
    lines.append("-" * 70)
    lines.append(f"Total Findings:  {scan.get('total_findings', 0)}")
    lines.append(f"  Critical:      {scan.get('critical_count', 0)}")
    lines.append(f"  High:          {scan.get('high_count', 0)}")
    lines.append(f"  Medium:        {scan.get('medium_count', 0)}")
    lines.append(f"  Low:           {scan.get('low_count', 0)}")
    lines.append("")

    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for r in results:
        sev = r.get("severity", "info")
        by_severity.setdefault(sev, []).append(r)

    for severity in ["critical", "high", "medium", "low", "info"]:
        items = by_severity.get(severity, [])
        if not items:
            continue
        lines.append("")
        lines.append("=" * 70)
        lines.append(f"  {severity.upper()} FINDINGS ({len(items)})")
        lines.append("=" * 70)

        for i, r in enumerate(items, 1):
            lines.append("")
            lines.append(f"[{i}] {r.get('title', 'Untitled')}")
            lines.append("-" * 60)
            lines.append(f"  Tool:       {r.get('tool_name', 'N/A')}")
            lines.append(f"  Phase:      {r.get('phase', 'N/A')}")
            lines.append(f"  Severity:   {r.get('severity', 'N/A')}")

            if r.get("cvss_score"):
                lines.append(f"  CVSS Score: {r['cvss_score']}")
            if r.get("cve_id"):
                lines.append(f"  CVE:        {r['cve_id']}")

            if r.get("description"):
                lines.append("")
                lines.append("  DESCRIPTION:")
                for line in str(r["description"]).split("\n"):
                    lines.append(f"    {line}")

            if r.get("evidence"):
                lines.append("")
                lines.append("  EVIDENCE (Real Data from Target):")
                ev = r["evidence"]
                if isinstance(ev, dict):
                    for k, v in ev.items():
                        val = str(v)[:500]
                        lines.append(f"    {k}: {val}")

            if r.get("remediation"):
                lines.append("")
                lines.append("  REMEDIATION:")
                for line in str(r["remediation"]).split("\n"):
                    lines.append(f"    {line}")

    lines.append("")
    lines.append("=" * 70)
    lines.append("  END OF REPORT")
    lines.append("=" * 70)
    lines.append(f"Generated at {datetime.utcnow().isoformat()} UTC")
    return "\n".join(lines)


def build_html_report(scan, results):
    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for r in results:
        sev = r.get("severity", "info")
        by_severity.setdefault(sev, []).append(r)

    findings_html = ""
    for severity in ["critical", "high", "medium", "low", "info"]:
        items = by_severity.get(severity, [])
        if not items:
            continue

        findings_html += f'<h2 class="severity-{severity}">{severity.upper()} ({len(items)})</h2>'
        for i, r in enumerate(items, 1):
            evidence_str = ""
            if r.get("evidence") and isinstance(r["evidence"], dict):
                for k, v in r["evidence"].items():
                    evidence_str += f"<li><strong>{k}:</strong> <code>{str(v)[:1000]}</code></li>"

            cvss_html = f'<span><strong>CVSS:</strong> {r["cvss_score"]}</span>' if r.get('cvss_score') else ''
            cve_html = f'<span><strong>CVE:</strong> {r["cve_id"]}</span>' if r.get('cve_id') else ''
            desc_html = f'<p class="desc">{r["description"]}</p>' if r.get('description') else ''
            ev_html = f'<div class="evidence"><h4>Evidence</h4><ul>{evidence_str}</ul></div>' if evidence_str else ''
            rem_html = f'<div class="remediation"><h4>Remediation</h4><pre>{r["remediation"]}</pre></div>' if r.get('remediation') else ''

            findings_html += f"""
            <div class="finding severity-{severity}">
                <h3>[{i}] {r.get('title', 'Untitled')}</h3>
                <div class="meta">
                    <span><strong>Tool:</strong> {r.get('tool_name', 'N/A')}</span>
                    <span><strong>Phase:</strong> {r.get('phase', 'N/A')}</span>
                    <span><strong>Severity:</strong> {r.get('severity', 'N/A')}</span>
                    {cvss_html}
                    {cve_html}
                </div>
                {desc_html}
                {ev_html}
                {rem_html}
            </div>
            """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Report - {scan.get('target_url', 'N/A')}</title>
<style>
    body {{ font-family: -apple-system, Segoe UI, sans-serif; max-width: 1000px; margin: 40px auto; padding: 20px; background: #f5f5f5; color: #222; }}
    h1 {{ color: #111; border-bottom: 3px solid #00ff41; padding-bottom: 10px; }}
    .summary {{ background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
    .stats {{ display: flex; gap: 20px; flex-wrap: wrap; margin-top: 15px; }}
    .stat {{ padding: 15px 25px; border-radius: 8px; color: white; font-weight: bold; }}
    .stat.critical {{ background: #dc2626; }}
    .stat.high {{ background: #ea580c; }}
    .stat.medium {{ background: #ca8a04; }}
    .stat.low {{ background: #16a34a; }}
    .stat.total {{ background: #1e293b; }}
    h2 {{ margin-top: 40px; padding: 10px; border-radius: 6px; }}
    h2.severity-critical {{ background: #fee2e2; color: #991b1b; }}
    h2.severity-high {{ background: #ffedd5; color: #9a3412; }}
    h2.severity-medium {{ background: #fef9c3; color: #854d0e; }}
    h2.severity-low {{ background: #dcfce7; color: #166534; }}
    h2.severity-info {{ background: #e0e7ff; color: #3730a3; }}
    .finding {{ background: white; padding: 20px; border-radius: 8px; margin: 15px 0; border-left: 5px solid #ccc; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }}
    .finding.severity-critical {{ border-left-color: #dc2626; }}
    .finding.severity-high {{ border-left-color: #ea580c; }}
    .finding.severity-medium {{ border-left-color: #ca8a04; }}
    .finding.severity-low {{ border-left-color: #16a34a; }}
    .finding h3 {{ margin-top: 0; color: #111; }}
    .meta {{ display: flex; gap: 15px; flex-wrap: wrap; font-size: 0.9em; color: #555; margin: 10px 0; }}
    .desc {{ background: #f9fafb; padding: 12px; border-radius: 6px; }}
    .evidence {{ background: #1e293b; color: #e2e8f0; padding: 15px; border-radius: 6px; margin: 15px 0; }}
    .evidence h4 {{ margin-top: 0; color: #00ff41; }}
    .evidence ul {{ list-style: none; padding-left: 0; }}
    .evidence li {{ padding: 6px 0; border-bottom: 1px solid #334155; word-break: break-all; }}
    .evidence code {{ color: #fbbf24; font-family: monospace; }}
    .remediation {{ background: #f0fdf4; padding: 15px; border-radius: 6px; margin: 15px 0; border-left: 4px solid #16a34a; }}
    .remediation h4 {{ margin-top: 0; color: #166534; }}
    .remediation pre {{ background: #1e293b; color: #e2e8f0; padding: 12px; border-radius: 6px; overflow-x: auto; }}
    .print-btn {{ position: fixed; top: 20px; right: 20px; background: #00ff41; color: #000; padding: 12px 20px; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; box-shadow: 0 2px 8px rgba(0,0,0,0.2); }}
    @media print {{
        body {{ background: white; }}
        .finding {{ break-inside: avoid; }}
        .print-btn {{ display: none; }}
    }}
</style>
</head>
<body>
    <button class="print-btn" onclick="window.print()">Print / Save as PDF</button>
    <h1>10blackfingers Security Report</h1>
    <div class="summary">
        <p><strong>Target:</strong> {scan.get('target_url', 'N/A')}</p>
        <p><strong>Scan ID:</strong> {scan.get('id', 'N/A')}</p>
        <p><strong>Started:</strong> {scan.get('started_at', 'N/A')}</p>
        <p><strong>Completed:</strong> {scan.get('completed_at', 'N/A')}</p>
        <div class="stats">
            <div class="stat total">Total: {scan.get('total_findings', 0)}</div>
            <div class="stat critical">Critical: {scan.get('critical_count', 0)}</div>
            <div class="stat high">High: {scan.get('high_count', 0)}</div>
            <div class="stat medium">Medium: {scan.get('medium_count', 0)}</div>
            <div class="stat low">Low: {scan.get('low_count', 0)}</div>
        </div>
    </div>
    {findings_html}
    <hr>
    <p style="text-align: center; color: #888; font-size: 0.9em;">
        Generated by 10blackfingers at {datetime.utcnow().isoformat()} UTC
    </p>
</body>
</html>"""
    return html


@app.get("/api/scan/{scan_id}/report/txt")
async def download_report_txt(scan_id: str):
    scan, results, _ = fetch_report_data(scan_id)
    content = build_txt_report(scan, results)
    return PlainTextResponse(
        content,
        headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.txt"'}
    )


@app.get("/api/scan/{scan_id}/report/html", response_class=HTMLResponse)
async def download_report_html(scan_id: str):
    scan, results, _ = fetch_report_data(scan_id)
    content = build_html_report(scan, results)
    return HTMLResponse(content)


@app.get("/api/scan/{scan_id}/report/pdf")
async def download_report_pdf(scan_id: str):
    scan, results, _ = fetch_report_data(scan_id)

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
    except ImportError:
        raise HTTPException(status_code=500, detail="PDF library not available")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=15*mm, rightMargin=15*mm,
                            topMargin=15*mm, bottomMargin=15*mm)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('Title', parent=styles['Title'], fontSize=20, textColor=colors.HexColor('#00ff41'))
    h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14, spaceAfter=10)
    h3_style = ParagraphStyle('H3', parent=styles['Heading3'], fontSize=11, spaceAfter=6)
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=9, leading=13)

    story = []
    story.append(Paragraph("10blackfingers Security Report", title_style))
    story.append(Spacer(1, 10))

    info = f"""
    <b>Target:</b> {scan.get('target_url', 'N/A')}<br/>
    <b>Scan ID:</b> {scan.get('id', 'N/A')}<br/>
    <b>Started:</b> {scan.get('started_at', 'N/A')}<br/>
    <b>Completed:</b> {scan.get('completed_at', 'N/A')}<br/>
    <b>Total Findings:</b> {scan.get('total_findings', 0)}<br/>
    <b>Critical:</b> {scan.get('critical_count', 0)} |
    <b>High:</b> {scan.get('high_count', 0)} |
    <b>Medium:</b> {scan.get('medium_count', 0)} |
    <b>Low:</b> {scan.get('low_count', 0)}
    """
    story.append(Paragraph(info, body_style))
    story.append(Spacer(1, 15))

    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for r in results:
        sev = r.get("severity", "info")
        by_severity.setdefault(sev, []).append(r)

    for severity in ["critical", "high", "medium", "low", "info"]:
        items = by_severity.get(severity, [])
        if not items:
            continue

        story.append(Paragraph(f"{severity.upper()} ({len(items)})", h2_style))
        for i, r in enumerate(items, 1):
            title = f"[{i}] {r.get('title', 'Untitled')}"
            story.append(Paragraph(title, h3_style))

            meta = f"<b>Tool:</b> {r.get('tool_name', 'N/A')} | <b>Phase:</b> {r.get('phase', 'N/A')} | <b>Severity:</b> {r.get('severity', 'N/A')}"
            if r.get('cvss_score'):
                meta += f" | <b>CVSS:</b> {r['cvss_score']}"
            if r.get('cve_id'):
                meta += f" | <b>CVE:</b> {r['cve_id']}"
            story.append(Paragraph(meta, body_style))

            if r.get('description'):
                desc = str(r['description']).replace('<', '&lt;').replace('>', '&gt;')[:1000]
                story.append(Paragraph(f"<b>Description:</b> {desc}", body_style))

            if r.get('evidence') and isinstance(r['evidence'], dict):
                ev_text = "Evidence: "
                for k, v in list(r['evidence'].items())[:5]:
                    ev_text += f"{k}={str(v)[:200]}; "
                ev_text = ev_text.replace('<', '&lt;').replace('>', '&gt;')
                story.append(Paragraph(ev_text, body_style))

            if r.get('remediation'):
                rem = str(r['remediation']).replace('<', '&lt;').replace('>', '&gt;')[:1000]
                story.append(Paragraph(f"<b>Remediation:</b> {rem}", body_style))

            story.append(Spacer(1, 8))

        story.append(PageBreak())

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.pdf"'}
    )