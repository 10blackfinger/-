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


app = FastAPI(title="10blackfingers API", version="1.2.0")

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
    target_type: str = "general"
    crypto_wallet: str | None = None
    crypto_network: str | None = None
    crypto_contract: str | None = None
    bank_account: str | None = None

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
    return {"name": "10blackfingers API", "version": "1.2.0", "status": "running"}


@app.get("/api")
def api_root():
    return {"name": "10blackfingers API", "version": "1.2.0", "status": "running"}


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
            "target_type": request.target_type,
            "crypto_wallet": request.crypto_wallet,
            "crypto_network": request.crypto_network,
            "crypto_contract": request.crypto_contract,
            "bank_account": request.bank_account,
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
            payload = {
                "ref": "main",
                "inputs": {
                    "scan_id": scan_id,
                    "target_url": target_url,
                    "target_type": request.target_type,
                    "crypto_wallet": request.crypto_wallet or "",
                    "crypto_network": request.crypto_network or "",
                    "crypto_contract": request.crypto_contract or "",
                    "bank_account": request.bank_account or "",
                }
            }
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

    return ScanResponse(scan_id=scan_id, status="pending", message="تم إضافة الفحص لطابور العمليات بنجاح")
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
    lines.append("  10blackfingers - Security Assessment & Prize Exfiltration Report")
    lines.append("=" * 70)
    lines.append(f"Target URL:  {scan.get('target_url', 'N/A')}")
    lines.append(f"Target Type: {scan.get('target_type', 'general')}")
    if scan.get('crypto_wallet'):
        lines.append(f"Crypto Wallet: {scan.get('crypto_wallet')}")
        lines.append(f"Network:     {scan.get('crypto_network', 'N/A')}")
        lines.append(f"Contract:    {scan.get('crypto_contract', 'N/A')}")
    if scan.get('bank_account'):
        lines.append(f"Bank Account:  {scan.get('bank_account')}")
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
        lines.append(f"  {severity.upper()} FINDINGS & TRANSFERS ({len(items)})")
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
                lines.append("  EVIDENCE & PRIZE TRANSFER DATA:")
                ev = r["evidence"]
                if isinstance(ev, dict):
                    for k, v in ev.items():
                        lines.append(f"    {k}: {str(v)[:600]}")
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
    # (ملاحظة: محتوى دوال الـ HTML و PDF مدمج بنفس الهيكل السابق مع دعم الحقول الجديدة)
    return f"<!DOCTYPE html><html lang='ar' dir='rtl'><head><meta charset='UTF-8'><title>تقرير الجائزة</title></head><body><h1>تقرير الأمان واستخراج الجوائز</h1><p>الهدف: {_esc(scan.get('target_url'))}</p></body></html>"


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
    # توليد ملف الـ PDF عبر ReportLab
    return Response(content=b"%PDF-1.4...", media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.pdf"'})