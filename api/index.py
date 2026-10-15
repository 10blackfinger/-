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


BLOCKED_HOSTNAMES = {"localhost", "metadata.google.internal"}


def is_private_or_reserved_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
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

    try:
        ipaddress.ip_address(hostname)
        if is_private_or_reserved_ip(hostname):
            raise HTTPException(status_code=400, detail="غير مسموح بفحص عناوين IP داخلية أو محجوزة")
    except ValueError:
        pass

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


async def fetch_report_data(scan_id: str):
    scans = await sb_select("scans", {"id": f"eq.{scan_id}", "select": "*"})
    if not scans:
        raise HTTPException(status_code=404, detail="الفحص غير موجود")
    scan = scans[0]
    results = await sb_select("results", {"scan_id": f"eq.{scan_id}", "select": "*"})
    return scan, results or []


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


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


def build_html_report(scan, results):
    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for r in results:
        sev = r.get("severity", "info")
        by_severity.setdefault(sev, []).append(r)

    severity_ar = {
        "critical": "ثغرات حرجة",
        "high": "ثغرات عالية",
        "medium": "ثغرات متوسطة",
        "low": "ثغرات منخفضة",
        "info": "معلومات",
    }

    findings_html = ""
    for severity in ["critical", "high", "medium", "low", "info"]:
        items = by_severity.get(severity, [])
        if not items:
            continue
        findings_html += f'<h2 class="severity-{severity}">{severity_ar[severity]} ({len(items)})</h2>'
        for i, r in enumerate(items, 1):
            evidence_str = ""
            if r.get("evidence") and isinstance(r["evidence"], dict):
                for k, v in list(r["evidence"].items())[:6]:
                    evidence_str += f"<li><strong>{_esc(k)}:</strong> <code>{_esc(str(v)[:600])}</code></li>"
            cvss_html = f'<span><strong>CVSS:</strong> {_esc(r["cvss_score"])}</span>' if r.get('cvss_score') else ''
            cve_html = f'<span><strong>CVE:</strong> {_esc(r["cve_id"])}</span>' if r.get('cve_id') else ''
            desc_html = f'<p class="desc">{_esc(r["description"])}</p>' if r.get('description') else ''
            ev_html = f'<div class="evidence"><h4>الأدلة التقنية:</h4><ul>{evidence_str}</ul></div>' if evidence_str else ''
            rem_html = f'<div class="remediation"><h4>كيفية الإصلاح:</h4><pre>{_esc(r["remediation"])}</pre></div>' if r.get('remediation') else ''
            findings_html += f"""
            <div class="finding severity-{severity}">
                <h3>[{i}] {_esc(r.get('title', 'Untitled'))}</h3>
                <div class="meta">
                    <span><strong>الأداة:</strong> {_esc(r.get('tool_name', 'N/A'))}</span>
                    <span><strong>المرحلة:</strong> {_esc(r.get('phase', 'N/A'))}</span>
                    {cvss_html}{cve_html}
                </div>
                {desc_html}{ev_html}{rem_html}
            </div>
            """

    total = scan.get('total_findings', 0)
    critical = scan.get('critical_count', 0)
    high = scan.get('high_count', 0)
    medium = scan.get('medium_count', 0)
    low = scan.get('low_count', 0)

    if critical > 0:
        overall_msg = "خطر - يوجد ثغرات حرجة تحتاج إصلاح فوري"
        overall_class = "danger"
    elif high > 0:
        overall_msg = "يحتاج انتباه - يوجد ثغرات عالية"
        overall_class = "warning"
    elif medium > 0:
        overall_msg = "متوسط - يوجد ثغرات متوسطة الخطورة"
        overall_class = "medium"
    else:
        overall_msg = "آمن - لا يوجد ثغرات خطيرة"
        overall_class = "safe"

    target_safe = _esc(scan.get('target_url', 'N/A'))
    html_out = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>تقرير أمني - {target_safe}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&family=IBM+Plex+Sans+Arabic:wght@400;600&display=swap" rel="stylesheet">
<style>
    * {{ box-sizing: border-box; }}
    body {{
        font-family: 'Cairo', 'IBM Plex Sans Arabic', -apple-system, sans-serif;
        max-width: 1100px;
        margin: 40px auto;
        padding: 20px;
        background: #f8f9fa;
        color: #1f2937;
        direction: rtl;
        line-height: 1.7;
    }}
    h1 {{
        color: #00a832;
        border-bottom: 3px solid #00a832;
        padding-bottom: 12px;
        margin-bottom: 24px;
        font-size: 28px;
    }}
    h2 {{
        margin-top: 40px;
        padding: 14px 20px;
        border-radius: 8px;
        font-size: 20px;
        font-weight: 700;
    }}
    h2.severity-critical {{ background: #fee2e2; color: #991b1b; border-right: 5px solid #dc2626; }}
    h2.severity-high {{ background: #ffedd5; color: #9a3412; border-right: 5px solid #ea580c; }}
    h2.severity-medium {{ background: #fef9c3; color: #854d0e; border-right: 5px solid #ca8a04; }}
    h2.severity-low {{ background: #dcfce7; color: #166534; border-right: 5px solid #16a34a; }}
    h2.severity-info {{ background: #e0e7ff; color: #3730a3; border-right: 5px solid #6366f1; }}

    .overall {{
        padding: 20px 24px;
        border-radius: 10px;
        font-size: 18px;
        font-weight: 700;
        margin: 20px 0;
        text-align: center;
    }}
    .overall.danger {{ background: #fef2f2; color: #991b1b; border: 2px solid #dc2626; }}
    .overall.warning {{ background: #fff7ed; color: #9a3412; border: 2px solid #ea580c; }}
    .overall.medium {{ background: #fefce8; color: #854d0e; border: 2px solid #ca8a04; }}
    .overall.safe {{ background: #f0fdf4; color: #166534; border: 2px solid #16a34a; }}

    .summary {{
        background: #ffffff;
        padding: 24px;
        border-radius: 10px;
        margin: 20px 0;
        box-shadow: 0 2px 10px rgba(0,0,0,0.06);
        border: 1px solid #e5e7eb;
    }}
    .summary p {{ margin: 8px 0; }}
    .summary strong {{ color: #374151; }}

    .stats {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
        gap: 14px;
        margin-top: 20px;
    }}
    .stat {{
        padding: 16px;
        border-radius: 8px;
        color: white;
        text-align: center;
    }}
    .stat .num {{ font-size: 26px; font-weight: 700; }}
    .stat .lbl {{ font-size: 13px; opacity: 0.95; }}
    .stat.total {{ background: #1e293b; }}
    .stat.critical {{ background: #dc2626; }}
    .stat.high {{ background: #ea580c; }}
    .stat.medium {{ background: #ca8a04; }}
    .stat.low {{ background: #16a34a; }}

    .finding {{
        background: #ffffff;
        padding: 20px 24px;
        border-radius: 10px;
        margin: 16px 0;
        border-right: 5px solid #cbd5e1;
        box-shadow: 0 1px 4px rgba(0,0,0,0.05);
    }}
    .finding.severity-critical {{ border-right-color: #dc2626; }}
    .finding.severity-high {{ border-right-color: #ea580c; }}
    .finding.severity-medium {{ border-right-color: #ca8a04; }}
    .finding.severity-low {{ border-right-color: #16a34a; }}
    .finding.severity-info {{ border-right-color: #6366f1; }}

    .finding h3 {{
        margin: 0 0 12px 0;
        color: #111827;
        font-size: 17px;
        font-weight: 600;
    }}
    .meta {{
        display: flex;
        gap: 16px;
        flex-wrap: wrap;
        font-size: 13px;
        color: #6b7280;
        margin: 8px 0;
        padding: 8px 0;
        border-bottom: 1px dashed #e5e7eb;
    }}
    .desc {{
        background: #f9fafb;
        padding: 14px;
        border-radius: 6px;
        margin: 12px 0;
        color: #374151;
        font-size: 14px;
    }}
    .evidence {{
        background: #1e293b;
        color: #e2e8f0;
        padding: 16px;
        border-radius: 8px;
        margin: 14px 0;
    }}
    .evidence h4 {{ margin: 0 0 10px 0; color: #4ade80; font-size: 14px; }}
    .evidence ul {{ list-style: none; padding: 0; margin: 0; }}
    .evidence li {{
        padding: 8px 0;
        border-bottom: 1px solid #334155;
        word-break: break-word;
        font-size: 12px;
    }}
    .evidence li:last-child {{ border-bottom: none; }}
    .evidence code {{
        color: #fbbf24;
        font-family: 'Courier New', monospace;
        font-size: 11px;
        direction: ltr;
        display: inline-block;
    }}
    .remediation {{
        background: #f0fdf4;
        padding: 16px;
        border-radius: 8px;
        margin: 14px 0;
        border-right: 4px solid #16a34a;
    }}
    .remediation h4 {{ margin: 0 0 10px 0; color: #166534; font-size: 14px; }}
    .remediation pre {{
        background: #1e293b;
        color: #e2e8f0;
        padding: 14px;
        border-radius: 6px;
        overflow-x: auto;
        white-space: pre-wrap;
        word-break: break-word;
        margin: 0;
        font-size: 12px;
        direction: ltr;
        text-align: left;
    }}
    .print-btn {{
        position: fixed;
        top: 20px;
        left: 20px;
        background: #00a832;
        color: white;
        padding: 12px 24px;
        border: none;
        border-radius: 8px;
        font-weight: 700;
        cursor: pointer;
        font-family: 'Cairo', sans-serif;
        font-size: 15px;
        box-shadow: 0 4px 12px rgba(0,168,50,0.3);
    }}
    .print-btn:hover {{ background: #008a28; }}
    @media print {{
        body {{ background: white; margin: 0; }}
        .print-btn {{ display: none; }}
        .finding {{ break-inside: avoid; page-break-inside: avoid; }}
    }}
</style>
</head>
<body>
<button class="print-btn" onclick="window.print()">🖨️ طباعة / حفظ PDF</button>
<h1>🛡️ تقرير فحص أمني - 10blackfingers</h1>

<div class="overall {overall_class}">{overall_msg}</div>

<div class="summary">
    <p><strong>الهدف:</strong> {target_safe}</p>
    <p><strong>رقم الفحص:</strong> {_esc(scan.get('id', 'N/A'))}</p>
    <p><strong>تاريخ البدء:</strong> {_esc(scan.get('started_at', 'N/A'))}</p>
    <p><strong>تاريخ الانتهاء:</strong> {_esc(scan.get('completed_at', 'N/A'))}</p>
    <div class="stats">
        <div class="stat total"><div class="num">{total}</div><div class="lbl">إجمالي</div></div>
        <div class="stat critical"><div class="num">{critical}</div><div class="lbl">حرجة</div></div>
        <div class="stat high"><div class="num">{high}</div><div class="lbl">عالية</div></div>
        <div class="stat medium"><div class="num">{medium}</div><div class="lbl">متوسطة</div></div>
        <div class="stat low"><div class="num">{low}</div><div class="lbl">منخفضة</div></div>
    </div>
</div>

{findings_html}

<hr style="margin-top: 50px; border: none; border-top: 1px solid #e5e7eb;">
<p style="text-align: center; color: #9ca3af; font-size: 13px;">
    تم توليد هذا التقرير بواسطة منصة 10blackfingers في {datetime.utcnow().isoformat()} UTC
</p>
</body>
</html>"""
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
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        import arabic_reshaper
        from bidi.algorithm import get_display
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"PDF library not available: {str(e)}")

    arabic_font_name = "Helvetica"
    try:
        font_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts", "Cairo-Regular.ttf")
        if os.path.exists(font_path):
            pdfmetrics.registerFont(TTFont("Cairo", font_path))
            arabic_font_name = "Cairo"
    except Exception:
        pass

    def ar(text):
        if not text:
            return ""
        try:
            reshaped = arabic_reshaper.reshape(str(text))
            bidi_text = get_display(reshaped)
            return bidi_text.replace("<", "&lt;").replace(">", "&gt;")
        except Exception:
            return str(text).replace("<", "&lt;").replace(">", "&gt;")

    def en(text):
        return str(text or "").replace("<", "&lt;").replace(">", "&gt;")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=15 * mm, rightMargin=15 * mm,
        topMargin=15 * mm, bottomMargin=15 * mm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'T', parent=styles['Title'], fontSize=22,
        textColor=colors.HexColor('#00a832'), fontName=arabic_font_name,
        alignment=1,
    )
    h2_style = ParagraphStyle(
        'H2', parent=styles['Heading2'], fontSize=14,
        spaceAfter=10, fontName=arabic_font_name,
        textColor=colors.HexColor('#111111'),
    )
    h3_style = ParagraphStyle(
        'H3', parent=styles['Heading3'], fontSize=11,
        spaceAfter=6, fontName=arabic_font_name,
    )
    body_style = ParagraphStyle(
        'B', parent=styles['Normal'], fontSize=9, leading=13,
        fontName=arabic_font_name,
    )
    body_rtl = ParagraphStyle(
        'BR', parent=body_style, alignment=2,
    )

    story = []
    story.append(Paragraph(ar("تقرير فحص أمني - 10blackfingers"), title_style))
    story.append(Spacer(1, 8))

    total = scan.get('total_findings', 0)
    critical = scan.get('critical_count', 0)
    high = scan.get('high_count', 0)
    medium = scan.get('medium_count', 0)
    low = scan.get('low_count', 0)

    if critical > 0:
        overall = "خطر - يوجد ثغرات حرجة تحتاج إصلاح فوري"
    elif high > 0:
        overall = "يحتاج انتباه - يوجد ثغرات عالية"
    elif medium > 0:
        overall = "متوسط - يوجد ثغرات متوسطة الخطورة"
    else:
        overall = "آمن - لا يوجد ثغرات خطيرة"

    info_text = (
        f"<b>الهدف:</b> {en(scan.get('target_url', 'N/A'))}<br/>"
        f"<b>رقم الفحص:</b> {en(scan.get('id', 'N/A'))}<br/>"
        f"<b>التقييم العام:</b> {ar(overall)}<br/>"
        f"<b>إجمالي النتائج:</b> {total}<br/>"
        f"<b>حرجة:</b> {critical} | <b>عالية:</b> {high} | <b>متوسطة:</b> {medium} | <b>منخفضة:</b> {low}"
    )
    story.append(Paragraph(info_text, body_rtl))
    story.append(Spacer(1, 20))

    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for r in results:
        by_severity.setdefault(r.get("severity", "info"), []).append(r)

    severity_ar = {
        "critical": "ثغرات حرجة",
        "high": "ثغرات عالية",
        "medium": "ثغرات متوسطة",
        "low": "ثغرات منخفضة",
        "info": "معلومات",
    }

    for severity in ["critical", "high", "medium", "low", "info"]:
        items = by_severity.get(severity, [])
        if not items:
            continue

        story.append(Paragraph(
            ar(f"{severity_ar.get(severity, severity)} ({len(items)})"),
            h2_style
        ))
        story.append(Spacer(1, 6))

        for i, r in enumerate(items, 1):
            title = r.get('title', 'Untitled')
            story.append(Paragraph(f"[{i}] {en(title)}", h3_style))

            meta = f"<b>Tool:</b> {en(r.get('tool_name', 'N/A'))} | <b>Phase:</b> {en(r.get('phase', 'N/A'))}"
            if r.get('cvss_score'):
                meta += f" | <b>CVSS:</b> {en(r['cvss_score'])}"
            if r.get('cve_id'):
                meta += f" | <b>CVE:</b> {en(r['cve_id'])}"
            story.append(Paragraph(meta, body_style))

            if r.get('description'):
                desc = en(str(r['description'])[:800])
                story.append(Paragraph(f"<b>Description:</b> {desc}", body_style))

            if r.get('evidence') and isinstance(r['evidence'], dict):
                ev = "<b>Evidence:</b><br/>"
                for k, v in list(r['evidence'].items())[:4]:
                    ev += f"&nbsp;&nbsp;- {en(k)}: {en(str(v)[:300])}<br/>"
                story.append(Paragraph(ev, body_style))

            if r.get('remediation'):
                rem = en(str(r['remediation'])[:600])
                story.append(Paragraph(f"<b>Remediation:</b> {rem}", body_style))

            story.append(Spacer(1, 10))

        story.append(PageBreak())

    try:
        doc.build(story)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF build error: {str(e)}")

    pdf_bytes = buffer.getvalue()
    buffer.close()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.pdf"'},
    )