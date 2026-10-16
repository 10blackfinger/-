import os
import io
import re
import html
import socket
import ipaddress
import uuid
from datetime import datetime
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, HTMLResponse, Response
from pydantic import BaseModel, Field, field_validator


app = FastAPI(
    title="10blackfingers Security API",
    description="Enterprise-grade Security Scanning & Penetration Testing Orchestration API for ISEF",
    version="1.2.0"
)

ALLOWED_ORIGINS = [
    "https://10blackfingers.vercel.app",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
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
            raise Exception(f"Supabase insert error [{r.status_code}]: {r.text}")
        return r.json()


async def sb_select(table: str, params: dict = None):
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(url, headers=sb_headers(), params=params or {})
        if r.status_code >= 400:
            raise Exception(f"Supabase select error [{r.status_code}]: {r.text}")
        return r.json()


async def sb_update(table: str, match: dict, data: dict):
    params = {k: f"eq.{v}" for k, v in match.items()}
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.patch(url, headers=sb_headers(), params=params, json=data)
        if r.status_code >= 400:
            raise Exception(f"Supabase update error [{r.status_code}]: {r.text}")
        return r.json()


BLOCKED_HOSTNAMES = {"localhost", "metadata.google.internal", "169.254.169.254", "internal.net"}


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
        raise HTTPException(status_code=400, detail="الرابط مطلوب ولا يمكن أن يكون فارغاً")

    parsed = urlparse(raw_url)

    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="يجب أن يبدأ الرابط بـ http:// أو https:// حصرياً")

    hostname = parsed.hostname
    if not hostname:
        raise hostname_error("رابط غير صالح أو نطاق غير معرّف")

    hostname_lower = hostname.lower()
    if hostname_lower in BLOCKED_HOSTNAMES or hostname_lower.endswith(".local") or hostname_lower.endswith(".internal"):
        raise HTTPException(status_code=400, detail="غير مسموح نهائياً بفحص النطاقات أو العناوين الداخلية (SSRF Protection)")

    try:
        ipaddress.ip_address(hostname)
        if is_private_or_reserved_ip(hostname):
            raise HTTPException(status_code=400, detail="غير مسموح بفحص عناوين IP المحلية أو الخاصة أو المحجوزة")
    except ValueError:
        pass

    try:
        resolved_ips = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in resolved_ips:
            ip_candidate = sockaddr[0]
            if is_private_or_reserved_ip(ip_candidate):
                raise HTTPException(
                    status_code=400,
                    detail="النطاق المستهدف يشير إلى عنوان IP داخلي أو محجوز - تم رفض الطلب أماناً",
                )
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="تعذر حل عنوان النطاق (DNS resolution failed)")

    return raw_url


def hostname_error(msg):
    return HTTPException(status_code=400, detail=msg)


class ScanRequest(BaseModel):
    url: str = Field(..., description="Target URL to scan")
    consent: bool = Field(..., description="Legal authorization consent confirmation")
    session_id: str = Field(..., description="User session identifier")

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, v):
        v = (v or "").strip()
        if not v or len(v) > 120 or not re.match(r"^[A-Za-z0-9_\-]+$", v):
            raise ValueError("معرّف الجلسة (session_id) غير صالح")
        return v


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


@app.get("/")
def root():
    return {"name": "10blackfingers Security API", "version": "1.2.0", "status": "active"}


@app.get("/api")
def api_root():
    return {"name": "10blackfingers Security API", "version": "1.2.0", "status": "active"}


@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.post("/api/scan", response_model=ScanResponse)
async def create_scan(request: ScanRequest):
    if not request.consent:
        raise HTTPException(status_code=400, detail="يجب الموافقة على شروط التصريح القانوني قبل بدء الفحص")

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
        raise HTTPException(status_code=500, detail=f"خطأ في قاعدة البيانات: {str(e)}")

    github_token = os.getenv("GITHUB_TOKEN", "")
    github_repo = os.getenv("GITHUB_REPO", "")

    if github_token and github_repo:
        try:
            url = f"https://api.github.com/repos/{github_repo}/actions/workflows/security-scan.yml/dispatches"
            headers = {
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            payload = {
                "ref": "main",
                "inputs": {
                    "scan_id": scan_id,
                    "target_url": target_url
                }
            }
            async with httpx.AsyncClient(timeout=30.0) as client:
                dispatch_res = await client.post(url, headers=headers, json=payload)
                if dispatch_res.status_code >= 300:
                    err_detail = f"فشل تشغيل مهام GitHub Actions [{dispatch_res.status_code}]: {dispatch_res.text[:300]}"
                    await sb_update("scans", {"id": scan_id}, {
                        "status": "failed",
                        "error_message": err_detail,
                    })
                    raise HTTPException(status_code=502, detail=err_detail)
        except HTTPException:
            raise
        except Exception as e:
            err_msg = f"تعذر الاتصال بخدمة GitHub Dispatch: {str(e)}"
            try:
                await sb_update("scans", {"id": scan_id}, {
                    "status": "failed",
                    "error_message": err_msg,
                })
            except Exception:
                pass
            raise HTTPException(status_code=500, detail=err_msg)
    else:
        await sb_update("scans", {"id": scan_id}, {
            "status": "failed",
            "error_message": "إعدادات المصادقة مع غيت هاب (GITHUB_TOKEN أو GITHUB_REPO) غير متوفرة في بيئة العمل",
        })
        raise HTTPException(status_code=500, detail="متغيرات البيئة الخاصة بـ GitHub مفقودة في الخادم")

    return ScanResponse(scan_id=scan_id, status="pending", message="تم إدراج الفحص في الطابور بنجاح وبدء التنفيذ عبر المحرك السحابي")


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    try:
        scans = await sb_select("scans", {"id": f"eq.{scan_id}", "select": "*"})
        if not scans:
            raise HTTPException(status_code=404, detail="معرّف الفحص غير موجود أو لم يتم العثور عليه")
        scan = scans[0]
        results = await sb_select("results", {"scan_id": f"eq.{scan_id}", "select": "*"})
        return {"scan": scan, "results": results or []}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"خطأ أثناء جلب بيانات الفحص: {str(e)}")


@app.get("/api/scans")
async def list_scans(session_id: str = Query(..., description="User session identifier"), limit: int = 15):
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
        raise HTTPException(status_code=500, detail=f"خطأ في استعلام قائمة الفحوصات: {str(e)}")


async def fetch_report_data(scan_id: str):
    scans = await sb_select("scans", {"id": f"eq.{scan_id}", "select": "*"})
    if not scans:
        raise HTTPException(status_code=404, detail="الفحص المطلوب غير موجود")
    scan = scans[0]
    results = await sb_select("results", {"scan_id": f"eq.{scan_id}", "select": "*"})
    return scan, results or []


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def build_txt_report(scan, results):
    lines = []
    lines.append("=" * 75)
    lines.append("  10blackfingers - Advanced Security Assessment Report")
    lines.append("  ISEF International Competition Standard")
    lines.append("=" * 75)
    lines.append(f"Target URL:  {scan.get('target_url', 'N/A')}")
    lines.append(f"Scan ID:     {scan.get('id', 'N/A')}")
    lines.append(f"Started At:  {scan.get('started_at', 'N/A')}")
    lines.append(f"Completed:   {scan.get('completed_at', 'N/A')}")
    lines.append(f"Status:      {scan.get('status', 'N/A')}")
    lines.append("")
    lines.append("-" * 75)
    lines.append("  EXECUTIVE SUMMARY & STATISTICS")
    lines.append("-" * 75)
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
        lines.append("=" * 75)
        lines.append(f"  {severity.upper()} SEVERITY FINDINGS ({len(items)})")
        lines.append("=" * 75)

        for i, r in enumerate(items, 1):
            lines.append("")
            lines.append(f"[{i}] {r.get('title', 'Untitled Finding')}")
            lines.append("-" * 65)
            lines.append(f"  Tool Name:  {r.get('tool_name', 'N/A')}")
            lines.append(f"  Phase:      {r.get('phase', 'N/A')}")
            lines.append(f"  Severity:   {r.get('severity', 'N/A')}")
            if r.get("cvss_score"):
                lines.append(f"  CVSS Score: {r['cvss_score']}")
            if r.get("cve_id"):
                lines.append(f"  CVE ID:     {r['cve_id']}")
            if r.get("description"):
                lines.append("")
                lines.append("  DESCRIPTION:")
                for line in str(r["description"]).split("\n"):
                    lines.append(f"    {line}")
            if r.get("evidence"):
                lines.append("")
                lines.append("  TECHNICAL EVIDENCE:")
                ev = r["evidence"]
                if isinstance(ev, dict):
                    for k, v in ev.items():
                        lines.append(f"    - {k}: {str(v)[:600]}")
            if r.get("remediation"):
                lines.append("")
                lines.append("  REMEDIATION / FIX:")
                for line in str(r["remediation"]).split("\n"):
                    lines.append(f"    {line}")

    lines.append("")
    lines.append("=" * 75)
    lines.append("  END OF REPORT - GENERATED SECURELY BY 10BLACKFINGERS")
    lines.append("=" * 75)
    return "\n".join(lines)


def build_html_report(scan, results):
    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for r in results:
        sev = r.get("severity", "info")
        by_severity.setdefault(sev, []).append(r)

    severity_ar = {
        "critical": "ثغرات حرجة (Critical)",
        "high": "ثغرات عالية الخطورة (High)",
        "medium": "ثغرات متوسطة الخطورة (Medium)",
        "low": "ثغرات منخفضة الخطورة (Low)",
        "info": "معلومات استخباراتية (Info)",
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
                for k, v in list(r["evidence"].items())[:8]:
                    evidence_str += f"<li><strong>{_esc(k)}:</strong> <code>{_esc(str(v)[:800])}</code></li>"
            cvss_html = f'<span><strong>CVSS:</strong> {_esc(r["cvss_score"])}</span>' if r.get('cvss_score') else ''
            cve_html = f'<span><strong>CVE:</strong> {_esc(r["cve_id"])}</span>' if r.get('cve_id') else ''
            desc_html = f'<p class="desc">{_esc(r["description"])}</p>' if r.get('description') else ''
            ev_html = f'<div class="evidence"><h4>الأدلة التقنية والمستندات:</h4><ul>{evidence_str}</ul></div>' if evidence_str else ''
            rem_html = f'<div class="remediation"><h4>خطوات الإصلاح والتحصين:</h4><pre>{_esc(r["remediation"])}</pre></div>' if r.get('remediation') else ''
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
        overall_msg = "⚠️ خطر داهم - تم رصد ثغرات حرجة تتطلب تدخلاً فورياً وإصلاحاً عاجلاً"
        overall_class = "danger"
    elif high > 0:
        overall_msg = "🚨 تنبيه أمني - يوجد ثغرات عالية الخطورة تهدد أمان النظام"
        overall_class = "warning"
    elif medium > 0:
        overall_msg = "⚡ متوسط الحماية - يوجد ثغرات متوسطة ينصح بمعالجتها"
        overall_class = "medium"
    else:
        overall_msg = "🛡️ آمن - لم يتم رصد أي ثغرات خطيرة تهدد النظام"
        overall_class = "safe"

    target_safe = _esc(scan.get('target_url', 'N/A'))
    html_out = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>تقرير فحص أمني - {target_safe}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;900&display=swap" rel="stylesheet">
<style>
    * {{ box-sizing: border-box; }}
    body {{
        font-family: 'Cairo', sans-serif;
        max-width: 1200px;
        margin: 40px auto;
        padding: 24px;
        background: #0f172a;
        color: #f8fafc;
        direction: rtl;
        line-height: 1.8;
    }}
    h1 {{
        color: #38ef7d;
        border-bottom: 3px solid #38ef7d;
        padding-bottom: 15px;
        margin-bottom: 25px;
        font-size: 30px;
        display: flex;
        align-items: center;
        gap: 12px;
    }}
    h2 {{
        margin-top: 45px;
        padding: 16px 22px;
        border-radius: 8px;
        font-size: 21px;
        font-weight: 700;
    }}
    h2.severity-critical {{ background: rgba(220, 38, 38, 0.15); color: #fca5a5; border-right: 6px solid #dc2626; }}
    h2.severity-high {{ background: rgba(234, 88, 12, 0.15); color: #fdba74; border-right: 6px solid #ea580c; }}
    h2.severity-medium {{ background: rgba(202, 138, 4, 0.15); color: #fde047; border-right: 6px solid #ca8a04; }}
    h2.severity-low {{ background: rgba(22, 163, 74, 0.15); color: #86efac; border-right: 6px solid #16a34a; }}
    h2.severity-info {{ background: rgba(99, 102, 241, 0.15); color: #a5b4fc; border-right: 6px solid #6366f1; }}

    .overall {{
        padding: 22px 28px;
        border-radius: 12px;
        font-size: 19px;
        font-weight: 700;
        margin: 24px 0;
        text-align: center;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    }}
    .overall.danger {{ background: #7f1d1d; color: #fee2e2; border: 2px solid #dc2626; }}
    .overall.warning {{ background: #7c2d12; color: #ffedd5; border: 2px solid #ea580c; }}
    .overall.medium {{ background: #713f12; color: #fef9c3; border: 2px solid #ca8a04; }}
    .overall.safe {{ background: #064e3b; color: #dcfce7; border: 2px solid #10b981; }}

    .summary {{
        background: #1e293b;
        padding: 28px;
        border-radius: 12px;
        margin: 24px 0;
        box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        border: 1px solid #334155;
    }}
    .summary p {{ margin: 10px 0; font-size: 16px; }}
    .summary strong {{ color: #38ef7d; }}

    .stats {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
        gap: 16px;
        margin-top: 24px;
    }}
    .stat {{
        padding: 18px;
        border-radius: 10px;
        color: white;
        text-align: center;
        box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    }}
    .stat .num {{ font-size: 28px; font-weight: 900; }}
    .stat .lbl {{ font-size: 14px; opacity: 0.9; margin-top: 4px; }}
    .stat.total {{ background: #334155; }}
    .stat.critical {{ background: #dc2626; }}
    .stat.high {{ background: #ea580c; }}
    .stat.medium {{ background: #ca8a04; }}
    .stat.low {{ background: #16a34a; }}

    .finding {{
        background: #1e293b;
        padding: 22px 28px;
        border-radius: 12px;
        margin: 20px 0;
        border-right: 6px solid #64748b;
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    }}
    .finding.severity-critical {{ border-right-color: #dc2626; }}
    .finding.severity-high {{ border-right-color: #ea580c; }}
    .finding.severity-medium {{ border-right-color: #ca8a04; }}
    .finding.severity-low {{ border-right-color: #16a34a; }}
    .finding.severity-info {{ border-right-color: #6366f1; }}

    .finding h3 {{
        margin: 0 0 14px 0;
        color: #f1f5f9;
        font-size: 19px;
        font-weight: 700;
    }}
    .meta {{
        display: flex;
        gap: 20px;
        flex-wrap: wrap;
        font-size: 14px;
        color: #94a3b8;
        margin: 10px 0;
        padding-bottom: 10px;
        border-bottom: 1px dashed #334155;
    }}
    .desc {{
        background: #0f172a;
        padding: 16px;
        border-radius: 8px;
        margin: 14px 0;
        color: #cbd5e1;
        font-size: 15px;
    }}
    .evidence {{
        background: #090d16;
        color: #e2e8f0;
        padding: 18px;
        border-radius: 10px;
        margin: 16px 0;
        border: 1px solid #1e293b;
    }}
    .evidence h4 {{ margin: 0 0 12px 0; color: #38ef7d; font-size: 15px; }}
    .evidence ul {{ list-style: none; padding: 0; margin: 0; }}
    .evidence li {{
        padding: 8px 0;
        border-bottom: 1px solid #1e293b;
        word-break: break-word;
        font-size: 13px;
    }}
    .evidence li:last-child {{ border-bottom: none; }}
    .evidence code {{
        color: #facc15;
        font-family: 'Courier New', monospace;
        font-size: 12px;
        direction: ltr;
        display: inline-block;
    }}
    .remediation {{
        background: rgba(16, 185, 129, 0.1);
        padding: 18px;
        border-radius: 10px;
        margin: 16px 0;
        border-right: 5px solid #10b981;
    }}
    .remediation h4 {{ margin: 0 0 10px 0; color: #34d399; font-size: 15px; }}
    .remediation pre {{
        background: #090d16;
        color: #34d399;
        padding: 16px;
        border-radius: 8px;
        overflow-x: auto;
        white-space: pre-wrap;
        word-break: break-word;
        margin: 0;
        font-size: 13px;
        direction: ltr;
        text-align: left;
    }}
    .print-btn {{
        position: fixed;
        top: 25px;
        left: 25px;
        background: #38ef7d;
        color: #0f172a;
        padding: 14px 26px;
        border: none;
        border-radius: 10px;
        font-weight: 900;
        cursor: pointer;
        font-family: 'Cairo', sans-serif;
        font-size: 16px;
        box-shadow: 0 4px 20px rgba(56,239,125,0.4);
        z-index: 1000;
        transition: all 0.3s ease;
    }}
    .print-btn:hover {{ background: #2ecc71; transform: translateY(-2px); }}
    @media print {{
        body {{ background: white; color: black; margin: 0; }}
        .summary, .finding {{ background: #f8fafc; border: 1px solid #cbd5e1; color: black; }}
        .print-btn {{ display: none; }}
        .finding {{ break-inside: avoid; page-break-inside: avoid; }}
    }}
</style>
</head>
<body>
<button class="print-btn" onclick="window.print()">🖨️ طباعة / حفظ التقرير PDF</button>
<h1>🛡️ منصة 10blackfingers - تقرير الفحص الأمني الشامل</h1>

<div class="overall {overall_class}">{overall_msg}</div>

<div class="summary">
    <p><strong>الهدف المستهدف:</strong> {target_safe}</p>
    <p><strong>معرّف الفحص (Scan ID):</strong> {_esc(scan.get('id', 'N/A'))}</p>
    <p><strong>تاريخ وبدء الفحص:</strong> {_esc(scan.get('started_at', 'N/A'))}</p>
    <p><strong>تاريخ الانتهاء:</strong> {_esc(scan.get('completed_at', 'N/A'))}</p>
    <div class="stats">
        <div class="stat total"><div class="num">{total}</div><div class="lbl">إجمالي النتائج</div></div>
        <div class="stat critical"><div class="num">{critical}</div><div class="lbl">ثغرات حرجة</div></div>
        <div class="stat high"><div class="num">{high}</div><div class="lbl">ثغرات عالية</div></div>
        <div class="stat medium"><div class="num">{medium}</div><div class="lbl">ثغرات متوسطة</div></div>
        <div class="stat low"><div class="num">{low}</div><div class="lbl">ثغرات منخفضة</div></div>
    </div>
</div>

{findings_html}

<hr style="margin-top: 60px; border: none; border-top: 1px solid #334155;">
<p style="text-align: center; color: #64748b; font-size: 14px; margin-top: 20px;">
    تم توليد هذا التقرير رسمياً وعملياً بواسطة منصة 10blackfingers لمسابقة ISEF الدولية في {datetime.utcnow().isoformat()} UTC
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
        raise HTTPException(status_code=500, detail=f"مكتبات تصدير PDF غير متوفرة في بيئة الخادم: {str(e)}")

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
        'T', parent=styles['Title'], fontSize=20,
        textColor=colors.HexColor('#38ef7d'), fontName=arabic_font_name,
        alignment=1,
    )
    h2_style = ParagraphStyle(
        'H2', parent=styles['Heading2'], fontSize=13,
        spaceAfter=8, fontName=arabic_font_name,
        textColor=colors.HexColor('#0f172a'),
    )
    h3_style = ParagraphStyle(
        'H3', parent=styles['Heading3'], fontSize=10,
        spaceAfter=5, fontName=arabic_font_name,
    )
    body_style = ParagraphStyle(
        'B', parent=styles['Normal'], fontSize=8.5, leading=12,
        fontName=arabic_font_name,
    )
    body_rtl = ParagraphStyle(
        'BR', parent=body_style, alignment=2,
    )

    story = []
    story.append(Paragraph(ar("منصة 10blackfingers - تقرير فحص أمني معتمد"), title_style))
    story.append(Spacer(1, 10))

    total = scan.get('total_findings', 0)
    critical = scan.get('critical_count', 0)
    high = scan.get('high_count', 0)
    medium = scan.get('medium_count', 0)
    low = scan.get('low_count', 0)

    if critical > 0:
        overall = "خطر داهم - ثغرات حرجة تتطلب إصلاحاً فوريأ"
    elif high > 0:
        overall = "تنبيه أمني - ثغرات عالية الخطورة"
    elif medium > 0:
        overall = "متوسط الحماية - ثغرات متوسطة"
    else:
        overall = "آمن - لا توجد ثغرات خطيرة"

    info_text = (
        f"<b>الهدف المستهدف:</b> {en(scan.get('target_url', 'N/A'))}<br/>"
        f"<b>معرّف الفحص:</b> {en(scan.get('id', 'N/A'))}<br/>"
        f"<b>التقييم العام:</b> {ar(overall)}<br/>"
        f"<b>إجمالي الاكتشافات:</b> {total} | <b>حرجة:</b> {critical} | <b>عالية:</b> {high} | <b>متوسطة:</b> {medium} | <b>منخفضة:</b> {low}"
    )
    story.append(Paragraph(info_text, body_rtl))
    story.append(Spacer(1, 15))

    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for r in results:
        by_severity.setdefault(r.get("severity", "info"), []).append(r)

    severity_ar = {
        "critical": "ثغرات حرجة",
        "high": "ثغرات عالية الخطورة",
        "medium": "ثغرات متوسطة الخطورة",
        "low": "ثغرات منخفضة الخطورة",
        "info": "معلومات استخباراتية",
    }

    for severity in ["critical", "high", "medium", "low", "info"]:
        items = by_severity.get(severity, [])
        if not items:
            continue

        story.append(Paragraph(
            ar(f"{severity_ar.get(severity, severity)} ({len(items)})"),
            h2_style
        ))
        story.append(Spacer(1, 4))

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
                desc = en(str(r['description'])[:600])
                story.append(Paragraph(f"<b>Description:</b> {desc}", body_style))

            if r.get('evidence') and isinstance(r['evidence'], dict):
                ev = "<b>Evidence:</b><br/>"
                for k, v in list(r['evidence'].items())[:3]:
                    ev += f"&nbsp;&nbsp;- {en(k)}: {en(str(v)[:250])}<br/>"
                story.append(Paragraph(ev, body_style))

            if r.get('remediation'):
                rem = en(str(r['remediation'])[:500])
                story.append(Paragraph(f"<b>Remediation:</b> {rem}", body_style))

            story.append(Spacer(1, 8))

        story.append(PageBreak())

    try:
        doc.build(story)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"خطأ أثناء بناء ملف PDF: {str(e)}")

    pdf_bytes = buffer.getvalue()
    buffer.close()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.pdf"'},
    )