import os
import io
import re
import html
import socket
import ipaddress
from datetime import datetime
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, HTMLResponse, Response
from pydantic import BaseModel, field_validator


app = FastAPI(title="10blackfingers API", version="1.1.0")

# ============================================================
# إصلاح 2: CORS - allow_origins="*" مع allow_credentials=True
# كان تضارب غير آمن (والمتصفحات أصلًا بترفضه). إحنا مش محتاجين
# credentials (مفيش cookies/auth هنا)، فخليناه False، وحددنا
# الدومينات الحقيقية المسموح لها تنادي الـ API.
# ============================================================
ALLOWED_ORIGINS = [
    "https://10blackfingers.vercel.app",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")


def sb_headers():
    return {
        "apikey": SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }


async def sb_insert(table: str, data: dict):
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(url, headers=sb_headers(), json=data)
        if r.status_code >= 400:
            raise Exception(f"Supabase insert error: {r.status_code} - {r.text}")
        return r.json()


async def sb_select(table: str, params: dict = None):
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(url, headers=sb_headers(), params=params or {})
        if r.status_code >= 400:
            raise Exception(f"Supabase select error: {r.status_code} - {r.text}")
        return r.json()


async def sb_update(table: str, match: dict, data: dict):
    params = {k: f"eq.{v}" for k, v in match.items()}
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.patch(url, headers=sb_headers(), params=params, json=data)
        if r.status_code >= 400:
            raise Exception(f"Supabase update error: {r.status_code} - {r.text}")
        return r.json()


# ============================================================
# إصلاح 3: حماية من SSRF - التأكد إن الرابط المطلوب فحصه
# رابط عام حقيقي، مش عنوان داخلي أو Cloud metadata أو localhost.
# من غير كده، أي حد يقدر يخلي منصتك تفحص بنيتها التحتية هي نفسها.
# ============================================================

BLOCKED_HOSTNAMES = {"localhost", "metadata.google.internal"}


def is_private_or_reserved_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # لو مش قادرين نفهمه، منرفضوش الفايدة
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_target_url(raw_url: str) -> str:
    raw_url = (raw_url or "").strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="الرابط مطلوب")

    parsed = urlparse(raw_url)

    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="الرابط لازم يبدأ بـ http:// أو https://")

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="رابط غير صالح")

    hostname_lower = hostname.lower()
    if hostname_lower in BLOCKED_HOSTNAMES or hostname_lower.endswith(".local"):
        raise HTTPException(status_code=400, detail="غير مسموح بفحص عناوين داخلية")

    # لو الهوست نفسه IP، نتأكد إنه مش private/loopback/metadata
    try:
        ipaddress.ip_address(hostname)
        if is_private_or_reserved_ip(hostname):
            raise HTTPException(status_code=400, detail="غير مسموح بفحص عناوين IP داخلية أو محجوزة")
    except ValueError:
        pass  # مش IP، يبقى دومين عادي - هنتأكد من الـ DNS resolution تحت

    # نتأكد إن الدومين مش بيعمل resolve لـ IP داخلي (DNS rebinding / SSRF)
    try:
        resolved_ips = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in resolved_ips:
            ip_candidate = sockaddr[0]
            if is_private_or_reserved_ip(ip_candidate):
                raise HTTPException(
                    status_code=400,
                    detail="الدومين بيشاور على عنوان IP داخلي - غير مسموح بالفحص",
                )
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="تعذر إيجاد الدومين (DNS resolution فشل)")

    return raw_url


class ScanRequest(BaseModel):
    url: str
    consent: bool
    session_id: str

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, v):
        v = (v or "").strip()
        if not v or len(v) > 100 or not re.match(r"^[A-Za-z0-9_\-]+$", v):
            raise ValueError("session_id غير صالح")
        return v


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


@app.get("/")
def root():
    return {"name": "10blackfingers API", "version": "1.1.0", "status": "running"}


@app.get("/api")
def api_root():
    return {"name": "10blackfingers API", "version": "1.1.0", "status": "running"}


@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.post("/api/scan", response_model=ScanResponse)
async def create_scan(request: ScanRequest):
    import uuid

    if not request.consent:
        raise HTTPException(status_code=400, detail="الموافقة على التصريح مطلوبة قبل الفحص")

    target_url = validate_target_url(request.url)

    scan_id = str(uuid.uuid4())

    try:
        await sb_insert("scans", {
            "id": scan_id,
            "target_url": target_url,
            "status": "pending",
            "session_id": request.session_id,
        })
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
            payload = {"ref": "main", "inputs": {"scan_id": scan_id, "target_url": target_url}}
            async with httpx.AsyncClient(timeout=30.0) as client:
                dispatch_res = await client.post(url, headers=headers, json=payload)
                if dispatch_res.status_code >= 300:
                    log_detail = f"GitHub dispatch failed: {dispatch_res.status_code} - {dispatch_res.text[:300]}"
                    try:
                        await sb_update("scans", {"id": scan_id}, {
                            "status": "failed",
                            "error_message": log_detail,
                        })
                    except Exception:
                        pass
        except Exception as e:
            try:
                await sb_update("scans", {"id": scan_id}, {
                    "status": "failed",
                    "error_message": f"تعذر بدء الفحص: {str(e)}",
                })
            except Exception:
                pass
    else:
        try:
            await sb_update("scans", {"id": scan_id}, {
                "status": "failed",
                "error_message": "GITHUB_TOKEN غير مُعرّف في إعدادات السيرفر",
            })
        except Exception:
            pass

    return ScanResponse(scan_id=scan_id, status="pending", message="تم إضافة الفحص للطابور بنجاح")


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    try:
        scans = await sb_select("scans", {"id": f"eq.{scan_id}", "select": "*"})
        if not scans:
            raise HTTPException(status_code=404, detail="الفحص غير موجود")
        scan = scans[0]
        results = await sb_select("results", {"scan_id": f"eq.{scan_id}", "select": "*"})
        return {"scan": scan, "results": results or []}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fetch error: {str(e)}")


@app.get("/api/scans")
async def list_scans(session_id: str, limit: int = 10):
    # إصلاح 4: حد أقصى حقيقي على limit عشان محدش يطلب آلاف السجلات
    limit = max(1, min(limit, 50))
    try:
        scans = await sb_select("scans", {
            "session_id": f"eq.{session_id}",
            "select": "*",
            "order": "created_at.desc",
            "limit": str(limit),
        })
        return {"scans": scans or []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"List error: {str(e)}")


# ============================================================
# REPORT ENDPOINTS
# ============================================================

async def fetch_report_data(scan_id: str):
    scans = await sb_select("scans", {"id": f"eq.{scan_id}", "select": "*"})
    if not scans:
        raise HTTPException(status_code=404, detail="الفحص غير موجود")
    scan = scans[0]
    results = await sb_select("results", {"scan_id": f"eq.{scan_id}", "select": "*"})
    return scan, results or []


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
                        lines.append(f"    {k}: {str(v)[:500]}")
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


def _esc(value) -> str:
    """إصلاح 1: HTML escaping - أي نص جاي من أداة فحص (ممكن يكون
    جزء من استجابة الموقع المستهدف نفسه) لازم يتعامل معاه كـ نص عادي
    مش HTML، عشان منسمحش بـ XSS جوه التقرير نفسه."""
    return html.escape(str(value), quote=True)


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
        findings_html += f'<h2 class="severity-{severity}">{_esc(severity.upper())} ({len(items)})</h2>'
        for i, r in enumerate(items, 1):
            evidence_str = ""
            if r.get("evidence") and isinstance(r["evidence"], dict):
                for k, v in r["evidence"].items():
                    evidence_str += f"<li><strong>{_esc(k)}:</strong> <code>{_esc(str(v)[:1000])}</code></li>"
            cvss_html = f'<span><strong>CVSS:</strong> {_esc(r["cvss_score"])}</span>' if r.get('cvss_score') else ''
            cve_html = f'<span><strong>CVE:</strong> {_esc(r["cve_id"])}</span>' if r.get('cve_id') else ''
            desc_html = f'<p class="desc">{_esc(r["description"])}</p>' if r.get('description') else ''
            ev_html = f'<div class="evidence"><h4>Evidence</h4><ul>{evidence_str}</ul></div>' if evidence_str else ''
            rem_html = f'<div class="remediation"><h4>Remediation</h4><pre>{_esc(r["remediation"])}</pre></div>' if r.get('remediation') else ''
            findings_html += f"""
            <div class="finding severity-{severity}">
                <h3>[{i}] {_esc(r.get('title', 'Untitled'))}</h3>
                <div class="meta">
                    <span><strong>Tool:</strong> {_esc(r.get('tool_name', 'N/A'))}</span>
                    <span><strong>Phase:</strong> {_esc(r.get('phase', 'N/A'))}</span>
                    <span><strong>Severity:</strong> {_esc(r.get('severity', 'N/A'))}</span>
                    {cvss_html}{cve_html}
                </div>
                {desc_html}{ev_html}{rem_html}
            </div>
            """

    target_safe = _esc(scan.get('target_url', 'N/A'))
    html_out = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Security Report - {target_safe}</title>
<style>
body {{ font-family: -apple-system, Segoe UI, sans-serif; max-width: 1000px; margin: 40px auto; padding: 20px; background: #f5f5f5; color: #222; }}
h1 {{ color: #111; border-bottom: 3px solid #00ff41; padding-bottom: 10px; }}
.summary {{ background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
.stats {{ display: flex; gap: 20px; flex-wrap: wrap; margin-top: 15px; }}
.stat {{ padding: 15px 25px; border-radius: 8px; color: white; font-weight: bold; }}
.stat.critical {{ background: #dc2626; }} .stat.high {{ background: #ea580c; }}
.stat.medium {{ background: #ca8a04; }} .stat.low {{ background: #16a34a; }}
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
.finding h3 {{ margin-top: 0; }}
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
.print-btn {{ position: fixed; top: 20px; right: 20px; background: #00ff41; color: #000; padding: 12px 20px; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; }}
@media print {{ .print-btn {{ display: none; }} .finding {{ break-inside: avoid; }} }}
</style></head><body>
<button class="print-btn" onclick="window.print()">Print / Save as PDF</button>
<h1>10blackfingers Security Report</h1>
<div class="summary">
<p><strong>Target:</strong> {target_safe}</p>
<p><strong>Scan ID:</strong> {_esc(scan.get('id', 'N/A'))}</p>
<p><strong>Started:</strong> {_esc(scan.get('started_at', 'N/A'))}</p>
<p><strong>Completed:</strong> {_esc(scan.get('completed_at', 'N/A'))}</p>
<div class="stats">
<div class="stat total">Total: {scan.get('total_findings', 0)}</div>
<div class="stat critical">Critical: {scan.get('critical_count', 0)}</div>
<div class="stat high">High: {scan.get('high_count', 0)}</div>
<div class="stat medium">Medium: {scan.get('medium_count', 0)}</div>
<div class="stat low">Low: {scan.get('low_count', 0)}</div>
</div></div>
{findings_html}
<hr><p style="text-align: center; color: #888; font-size: 0.9em;">
Generated by 10blackfingers at {datetime.utcnow().isoformat()} UTC</p>
</body></html>"""
    return html_out


@app.get("/api/scan/{scan_id}/report/txt")
async def download_report_txt(scan_id: str):
    scan, results = await fetch_report_data(scan_id)
    content = build_txt_report(scan, results)
    return PlainTextResponse(content, headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.txt"'})


@app.get("/api/scan/{scan_id}/report/html", response_class=HTMLResponse)
async def download_report_html(scan_id: str):
    scan, results = await fetch_report_data(scan_id)
    return HTMLResponse(build_html_report(scan, results))


@app.get("/api/scan/{scan_id}/report/pdf")
async def download_report_pdf(scan_id: str):
    scan, results = await fetch_report_data(scan_id)
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
    except ImportError:
        raise HTTPException(status_code=500, detail="PDF library not available")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=15*mm, rightMargin=15*mm, topMargin=15*mm, bottomMargin=15*mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('T', parent=styles['Title'], fontSize=20, textColor=colors.HexColor('#00ff41'))
    h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14, spaceAfter=10)
    h3_style = ParagraphStyle('H3', parent=styles['Heading3'], fontSize=11, spaceAfter=6)
    body_style = ParagraphStyle('B', parent=styles['Normal'], fontSize=9, leading=13)

    story = [Paragraph("10blackfingers Security Report", title_style), Spacer(1, 10)]
    info = (
        f"<b>Target:</b> {_esc(scan.get('target_url', 'N/A'))}<br/>"
        f"<b>Scan ID:</b> {_esc(scan.get('id', 'N/A'))}<br/>"
        f"<b>Total:</b> {scan.get('total_findings', 0)} | <b>Critical:</b> {scan.get('critical_count', 0)} | "
        f"<b>High:</b> {scan.get('high_count', 0)} | <b>Medium:</b> {scan.get('medium_count', 0)} | "
        f"<b>Low:</b> {scan.get('low_count', 0)}"
    )
    story.append(Paragraph(info, body_style))
    story.append(Spacer(1, 15))

    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for r in results:
        by_severity.setdefault(r.get("severity", "info"), []).append(r)

    for severity in ["critical", "high", "medium", "low", "info"]:
        items = by_severity.get(severity, [])
        if not items:
            continue
        story.append(Paragraph(f"{severity.upper()} ({len(items)})", h2_style))
        for i, r in enumerate(items, 1):
            story.append(Paragraph(f"[{i}] {_esc(r.get('title', 'Untitled'))}", h3_style))
            meta = f"<b>Tool:</b> {_esc(r.get('tool_name', 'N/A'))} | <b>Phase:</b> {_esc(r.get('phase', 'N/A'))}"
            if r.get('cvss_score'):
                meta += f" | <b>CVSS:</b> {_esc(r['cvss_score'])}"
            if r.get('cve_id'):
                meta += f" | <b>CVE:</b> {_esc(r['cve_id'])}"
            story.append(Paragraph(meta, body_style))
            if r.get('description'):
                desc = _esc(str(r['description'])[:1000])
                story.append(Paragraph(f"<b>Description:</b> {desc}", body_style))
            if r.get('evidence') and isinstance(r['evidence'], dict):
                ev = "Evidence: "
                for k, v in list(r['evidence'].items())[:5]:
                    ev += f"{_esc(k)}={_esc(str(v)[:200])}; "
                story.append(Paragraph(ev, body_style))
            if r.get('remediation'):
                rem = _esc(str(r['remediation'])[:1000])
                story.append(Paragraph(f"<b>Remediation:</b> {rem}", body_style))
            story.append(Spacer(1, 8))
        story.append(PageBreak())

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return Response(content=pdf_bytes, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.pdf"'})