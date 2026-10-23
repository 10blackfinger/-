
import os
import json
from datetime import datetime
from supabase import create_client


SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
SCAN_ID = os.environ["SCAN_ID"]
TARGET_URL = os.environ.get("TARGET_URL", "")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)


SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "info": "ℹ️",
}

SEVERITY_LABELS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}

SEVERITY_AR = {
    "critical": "ثغرات حرجة",
    "high": "ثغرات عالية",
    "medium": "ثغرات متوسطة",
    "low": "ثغرات منخفضة",
    "info": "معلومات",
}


def _esc(value):
    """HTML escape لأي قيمة"""
    if value is None:
        return ""
    s = str(value)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _fmt_val(value, max_len=3000):
    """يحوّل أي قيمة لنص مقروء"""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        try:
            s = json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            s = str(value)
    else:
        s = str(value)
    if len(s) > max_len:
        s = s[:max_len] + "... (مقتطع)"
    return s


def fetch_data():
    scan = supabase.table("scans").select("*").eq("id", SCAN_ID).execute()
    results = supabase.table("results").select("*").eq("scan_id", SCAN_ID).execute()
    logs = supabase.table("logs").select("*").eq("scan_id", SCAN_ID).order("created_at").execute()
    scan_data = scan.data[0] if scan.data else {}
    return scan_data, (results.data or []), (logs.data or [])


def render_pii_table(title, pii_dict):
    """يعرض بيانات PII في جدول HTML منسق"""
    if not pii_dict or not isinstance(pii_dict, dict):
        return ""
    rows = []
    for key, value in pii_dict.items():
        if key == "source_url":
            continue
        if isinstance(value, list):
            for v in value:
                rows.append((key, str(v)))
        elif isinstance(value, (int, float, str)):
            rows.append((key, str(value)))
        else:
            rows.append((key, _fmt_val(value)))
    if not rows:
        return ""
    html = f'<div class="pii-block"><h4 class="pii-title">🔐 {_esc(title)} ({len(rows)})</h4>'
    html += '<table class="data-table"><thead><tr>'
    html += '<th style="width:30%">النوع</th><th>القيمة</th>'
    html += '</tr></thead><tbody>'
    for k, v in rows[:500]:
        html += f'<tr><td><strong>{_esc(k)}</strong></td><td><code>{_esc(v)}</code></td></tr>'
    html += '</tbody></table>'
    if len(rows) > 500:
        html += f'<p class="more-note">... و {len(rows) - 500} صف إضافي في التقرير الكامل</p>'
    html += '</div>'
    return html


def render_db_dump_table(dumped_files):
    """يعرض ملفات قاعدة البيانات المسحوبة"""
    if not dumped_files or not isinstance(dumped_files, dict):
        return ""
    html = '<div class="db-dump-block"><h4 class="db-title">🗄️ ملفات قاعدة البيانات المسحوبة</h4>'
    for filename, content in list(dumped_files.items())[:20]:
        html += '<div class="db-file">'
        html += f'<h5 class="db-file-name">📄 {_esc(filename)}</h5>'
        html += f'<pre class="db-content">{_esc(str(content)[:8000])}</pre>'
        html += '</div>'
    html += '</div>'
    return html


def render_evidence(evidence):
    """يعرض الأدلة مع معالجة خاصة لبيانات PII وقواعد البيانات"""
    if not evidence:
        return ""
    if isinstance(evidence, str):
        return f'<pre class="raw-evidence">{_esc(evidence)}</pre>'
    if not isinstance(evidence, dict):
        return ""

    parts = ['<div class="evidence-block"><h4 class="evidence-title">🔍 الأدلة والبيانات المستخرجة</h4>']

    for key in ("extracted_pii", "aggregated"):
        if key in evidence and evidence[key]:
            title = "البيانات الحساسة المستخرجة (PII)" if key == "extracted_pii" else "بيانات PII المجمّعة"
            parts.append(render_pii_table(title, evidence[key]))

    if "pii_data" in evidence and isinstance(evidence["pii_data"], list):
        for i, item in enumerate(evidence["pii_data"][:10], 1):
            if isinstance(item, dict):
                source = item.get("source_url", f"مصدر {i}")
                pii_only = {k: v for k, v in item.items() if k != "source_url"}
                parts.append(render_pii_table(f"بيانات PII من {source}", pii_only))

    if "dumped_files_preview" in evidence and evidence["dumped_files_preview"]:
        parts.append(render_db_dump_table(evidence["dumped_files_preview"]))

    if "extracted_files" in evidence and isinstance(evidence["extracted_files"], list):
        parts.append('<div class="files-block"><h4 class="files-title">📁 الملفات الحساسة المسحوبة</h4>')
        for f in evidence["extracted_files"][:10]:
            if isinstance(f, dict):
                parts.append('<div class="file-item">')
                parts.append(f'<h5>{_esc(f.get("file", ""))} — <code>{_esc(f.get("url", ""))}</code></h5>')
                if f.get("extracted_pii"):
                    parts.append(render_pii_table("PII داخل الملف", f["extracted_pii"]))
                parts.append(f'<pre>{_esc(str(f.get("content", ""))[:5000])}</pre>')
                parts.append('</div>')
        parts.append('</div>')

    skip_keys = {"extracted_pii", "aggregated", "pii_data", "dumped_files_preview", "extracted_files"}
    generic = {
        k: v for k, v in evidence.items()
        if k not in skip_keys and v not in (None, "", [], {})
    }
    if generic:
        parts.append('<ul class="generic-evidence">')
        for k, v in generic.items():
            parts.append(f'<li><strong>{_esc(k)}:</strong> <code>{_esc(_fmt_val(v))}</code></li>')
        parts.append('</ul>')

    parts.append('</div>')
    return "".join(parts)


def generate_txt(scan, results, logs):
    lines = []
    lines.append("=" * 78)
    lines.append("    10blackfingers — Security Assessment Report")
    lines.append("=" * 78)
    lines.append(f"Target URL:     {scan.get('target_url', TARGET_URL)}")
    lines.append(f"Scan ID:        {SCAN_ID}")
    lines.append(f"Started:        {scan.get('started_at', 'N/A')}")
    lines.append(f"Completed:      {scan.get('completed_at', 'N/A')}")
    lines.append(f"Duration:       {scan.get('elapsed_seconds', 'N/A')} seconds")
    lines.append(f"Status:         {scan.get('status', 'N/A')}")
    lines.append("")
    lines.append("-" * 78)
    lines.append("  EXECUTIVE SUMMARY")
    lines.append("-" * 78)
    lines.append(f"Total Findings:  {scan.get('total_findings', 0)}")
    lines.append(f"  Critical:      {scan.get('critical_count', 0)}")
    lines.append(f"  High:          {scan.get('high_count', 0)}")
    lines.append(f"  Medium:        {scan.get('medium_count', 0)}")
    lines.append(f"  Low:           {scan.get('low_count', 0)}")
    lines.append("")

    by_sev = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for r in results:
        by_sev.setdefault(r.get("severity", "info"), []).append(r)

    for sev in ["critical", "high", "medium", "low", "info"]:
        items = by_sev.get(sev, [])
        if not items:
            continue
        icon = SEVERITY_ICONS.get(sev, "")
        label = SEVERITY_LABELS.get(sev, sev.upper())
        lines.append("")
        lines.append("=" * 78)
        lines.append(f"  {icon} {label} FINDINGS ({len(items)})")
        lines.append("=" * 78)
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

            ev = r.get("evidence")
            if ev:
                lines.append("")
                lines.append("  EVIDENCE & EXTRACTED DATA:")
                if isinstance(ev, dict):
                    for k, v in ev.items():
                        if k in ("extracted_pii", "aggregated") and isinstance(v, dict):
                            lines.append(f"    [{k}]")
                            for pk, pv in v.items():
                                if isinstance(pv, list):
                                    for pvv in pv:
                                        lines.append(f"      {pk}: {pvv}")
                                else:
                                    lines.append(f"      {pk}: {pv}")
                        elif k == "pii_data" and isinstance(v, list):
                            for item in v[:10]:
                                if isinstance(item, dict):
                                    lines.append(f"    [PII from {item.get('source_url', 'N/A')}]")
                                    for pk, pv in item.items():
                                        if pk == "source_url":
                                            continue
                                        lines.append(f"      {pk}: {pv}")
                        elif k == "dumped_files_preview" and isinstance(v, dict):
                            lines.append(f"    [DB DUMP FILES: {len(v)}]")
                            for fn, content in list(v.items())[:10]:
                                lines.append(f"      --- {fn} ---")
                                for line in str(content)[:3000].split("\n"):
                                    lines.append(f"      {line}")
                        elif k == "extracted_files" and isinstance(v, list):
                            lines.append(f"    [EXTRACTED FILES: {len(v)}]")
                            for f in v[:10]:
                                if isinstance(f, dict):
                                    lines.append(f"      - {f.get('file', '')}: {f.get('url', '')}")
                                    for line in str(f.get("content", ""))[:2000].split("\n"):
                                        lines.append(f"        {line}")
                        else:
                            lines.append(f"    {k}: {_fmt_val(v)}")
                else:
                    lines.append(f"    {str(ev)[:3000]}")

            if r.get("remediation"):
                lines.append("")
                lines.append("  REMEDIATION:")
                for line in str(r["remediation"]).split("\n"):
                    lines.append(f"    {line}")

    lines.append("")
    lines.append("=" * 78)
    lines.append("  END OF REPORT")
    lines.append("=" * 78)
    lines.append(f"Generated by 10blackfingers at {datetime.utcnow().isoformat()} UTC")
    return "\n".join(lines)


def generate_html(scan, results, logs):
    by_sev = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for r in results:
        by_sev.setdefault(r.get("severity", "info"), []).append(r)

    findings_html = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        items = by_sev.get(sev, [])
        if not items:
            continue
        icon = SEVERITY_ICONS.get(sev, "")
        label_ar = SEVERITY_AR.get(sev, sev.upper())

        findings_html += f'<h2 class="severity-{sev}">{icon} {_esc(label_ar)} ({len(items)})</h2>'
        for i, r in enumerate(items, 1):
            evidence_html = render_evidence(r.get("evidence"))
            cvss_span = f'<span><strong>CVSS:</strong> {_esc(r["cvss_score"])}</span>' if r.get("cvss_score") else ""
            cve_span = f'<span><strong>CVE:</strong> {_esc(r["cve_id"])}</span>' if r.get("cve_id") else ""
            desc_p = f'<p class="desc">{_esc(r["description"])}</p>' if r.get("description") else ""
            rem_div = ""
            if r.get("remediation"):
                rem_div = f'<div class="remediation"><h4>🛠️ كيفية الإصلاح</h4><pre>{_esc(r["remediation"])}</pre></div>'

            findings_html += f"""
<div class="finding severity-{sev}">
    <h3>[{i}] {_esc(r.get('title', 'Untitled'))}</h3>
    <div class="meta">
        <span><strong>الأداة:</strong> {_esc(r.get('tool_name', 'N/A'))}</span>
        <span><strong>المرحلة:</strong> {_esc(r.get('phase', 'N/A'))}</span>
        <span><strong>الخطورة:</strong> {_esc(r.get('severity', 'N/A'))}</span>
        {cvss_span}{cve_span}
    </div>
    {desc_p}
    {evidence_html}
    {rem_div}
</div>
"""

    total = scan.get("total_findings", 0)
    critical = scan.get("critical_count", 0)
    high = scan.get("high_count", 0)
    medium = scan.get("medium_count", 0)
    low = scan.get("low_count", 0)

    if critical > 0:
        overall_msg, overall_class = "خطر — يوجد ثغرات حرجة تحتاج إصلاح فوري", "danger"
    elif high > 0:
        overall_msg, overall_class = "يحتاج انتباه — يوجد ثغرات عالية", "warning"
    elif medium > 0:
        overall_msg, overall_class = "متوسط — يوجد ثغرات متوسطة الخطورة", "medium"
    else:
        overall_msg, overall_class = "آمن — لا يوجد ثغرات خطيرة", "safe"

    target_safe = _esc(scan.get("target_url", TARGET_URL))

    html_out = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>تقرير أمني — {target_safe}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
<style>
* {{ box-sizing: border-box; }}
body {{
    font-family: 'Cairo', -apple-system, Tahoma, sans-serif;
    max-width: 1200px;
    margin: 30px auto;
    padding: 20px;
    background: #f8fafc;
    color: #1f2937;
    direction: rtl;
    line-height: 1.7;
}}
h1 {{
    color: #00a832;
    border-bottom: 3px solid #00a832;
    padding-bottom: 12px;
    font-size: 26px;
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

.overall {{ padding: 18px 24px; border-radius: 10px; font-size: 17px; font-weight: 700; margin: 20px 0; text-align: center; }}
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
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; margin-top: 20px; }}
.stat {{ padding: 16px; border-radius: 8px; color: white; text-align: center; }}
.stat .num {{ font-size: 24px; font-weight: 700; }}
.stat .lbl {{ font-size: 12px; opacity: 0.95; }}
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
.finding h3 {{ margin: 0 0 12px 0; color: #111827; font-size: 17px; font-weight: 600; }}

.meta {{
    display: flex; gap: 16px; flex-wrap: wrap;
    font-size: 13px; color: #6b7280;
    margin: 8px 0; padding: 8px 0;
    border-bottom: 1px dashed #e5e7eb;
}}
.desc {{
    background: #f9fafb; padding: 14px; border-radius: 6px;
    margin: 12px 0; color: #374151; font-size: 14px;
}}

.evidence-block {{
    background: #f1f5f9;
    padding: 16px;
    border-radius: 8px;
    margin: 14px 0;
    border: 1px solid #cbd5e1;
}}
.evidence-title {{
    margin: 0 0 12px 0;
    color: #1e40af;
    font-size: 15px;
    border-bottom: 2px solid #3b82f6;
    padding-bottom: 6px;
}}
.pii-block {{
    background: #fff;
    border: 1px solid #fca5a5;
    border-radius: 8px;
    padding: 12px;
    margin: 12px 0;
}}
.pii-title {{
    margin: 0 0 10px 0;
    color: #991b1b;
    font-size: 14px;
}}
.data-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    background: #fff;
    direction: ltr;
}}
.data-table thead th {{
    background: #1e293b;
    color: #fff;
    padding: 8px 10px;
    text-align: left;
    font-weight: 600;
}}
.data-table tbody td {{
    padding: 7px 10px;
    border-bottom: 1px solid #e5e7eb;
    word-break: break-all;
}}
.data-table tbody tr:nth-child(even) {{ background: #f9fafb; }}
.data-table tbody tr:hover {{ background: #fef3c7; }}
.data-table code {{
    color: #b91c1c;
    font-family: 'Courier New', monospace;
    font-size: 11px;
    background: #fef2f2;
    padding: 2px 5px;
    border-radius: 3px;
}}
.more-note {{ margin: 8px 0 0 0; font-size: 11px; color: #6b7280; font-style: italic; }}

.db-dump-block {{
    background: #1e293b;
    color: #e2e8f0;
    padding: 14px;
    border-radius: 8px;
    margin: 12px 0;
}}
.db-title {{ margin: 0 0 12px 0; color: #4ade80; font-size: 15px; }}
.db-file {{ margin: 12px 0; padding: 10px; background: #0f172a; border-radius: 6px; }}
.db-file-name {{ margin: 0 0 8px 0; color: #fbbf24; font-size: 13px; }}
.db-content {{
    background: #000;
    color: #d1fae5;
    padding: 10px;
    border-radius: 4px;
    overflow-x: auto;
    font-size: 11px;
    direction: ltr;
    text-align: left;
    max-height: 400px;
    overflow-y: auto;
    margin: 0;
    white-space: pre-wrap;
    word-break: break-all;
}}

.files-block {{
    background: #fef3c7;
    border: 1px solid #fbbf24;
    border-radius: 8px;
    padding: 12px;
    margin: 12px 0;
}}
.files-title {{ margin: 0 0 10px 0; color: #92400e; font-size: 15px; }}
.file-item {{
    background: #fff;
    padding: 10px;
    border-radius: 6px;
    margin: 8px 0;
    border-right: 3px solid #f59e0b;
}}
.file-item h5 {{ margin: 0 0 6px 0; font-size: 12px; color: #78350f; }}
.file-item pre {{
    background: #1e293b;
    color: #e2e8f0;
    padding: 8px;
    border-radius: 4px;
    overflow-x: auto;
    font-size: 10px;
    direction: ltr;
    text-align: left;
    margin: 6px 0 0 0;
    max-height: 300px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
}}

.generic-evidence {{
    list-style: none;
    padding: 0;
    margin: 10px 0;
    background: #fff;
    border-radius: 6px;
    border: 1px solid #e5e7eb;
}}
.generic-evidence li {{
    padding: 8px 12px;
    border-bottom: 1px solid #f3f4f6;
    font-size: 12px;
    word-break: break-all;
}}
.generic-evidence li:last-child {{ border-bottom: none; }}
.generic-evidence code {{
    color: #0369a1;
    background: #f0f9ff;
    padding: 2px 5px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    font-size: 11px;
    direction: ltr;
    display: inline-block;
}}

.raw-evidence {{
    background: #1e293b;
    color: #e2e8f0;
    padding: 12px;
    border-radius: 6px;
    overflow-x: auto;
    font-size: 11px;
    direction: ltr;
    text-align: left;
    white-space: pre-wrap;
    word-break: break-all;
}}

.remediation {{
    background: #f0fdf4;
    padding: 14px;
    border-radius: 8px;
    margin: 14px 0;
    border-right: 4px solid #16a34a;
}}
.remediation h4 {{ margin: 0 0 10px 0; color: #166534; font-size: 14px; }}
.remediation pre {{
    background: #1e293b;
    color: #e2e8f0;
    padding: 12px;
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
    padding: 12px 22px;
    border: none;
    border-radius: 8px;
    font-weight: 700;
    cursor: pointer;
    font-family: 'Cairo', sans-serif;
    font-size: 14px;
    box-shadow: 0 4px 12px rgba(0,168,50,0.3);
    z-index: 1000;
}}
.print-btn:hover {{ background: #008a28; }}

.footer {{
    margin-top: 50px;
    padding-top: 20px;
    border-top: 1px solid #e5e7eb;
    text-align: center;
    color: #9ca3af;
    font-size: 12px;
}}

@media print {{
    body {{ background: white; margin: 0; }}
    .print-btn {{ display: none; }}
    .finding {{ break-inside: avoid; page-break-inside: avoid; }}
}}
</style>
</head>
<body>
<button class="print-btn" onclick="window.print()">🖨️ طباعة / حفظ PDF</button>
<h1>🛡️ تقرير فحص أمني — 10blackfingers</h1>

<div class="overall {overall_class}">{_esc(overall_msg)}</div>

<div class="summary">
    <p><strong>الهدف:</strong> {target_safe}</p>
    <p><strong>رقم الفحص:</strong> {_esc(SCAN_ID)}</p>
    <p><strong>تاريخ البدء:</strong> {_esc(scan.get('started_at', 'N/A'))}</p>
    <p><strong>تاريخ الانتهاء:</strong> {_esc(scan.get('completed_at', 'N/A'))}</p>
    <p><strong>المدة:</strong> {_esc(scan.get('elapsed_seconds', 'N/A'))} ثانية</p>
    <div class="stats">
        <div class="stat total"><div class="num">{total}</div><div class="lbl">إجمالي</div></div>
        <div class="stat critical"><div class="num">{critical}</div><div class="lbl">حرجة</div></div>
        <div class="stat high"><div class="num">{high}</div><div class="lbl">عالية</div></div>
        <div class="stat medium"><div class="num">{medium}</div><div class="lbl">متوسطة</div></div>
        <div class="stat low"><div class="num">{low}</div><div class="lbl">منخفضة</div></div>
    </div>
</div>

{findings_html}

<div class="footer">
    تم توليد هذا التقرير بواسطة منصة 10blackfingers في {datetime.utcnow().isoformat()} UTC
</div>
</body>
</html>"""
    return html_out


def save_reports(scan, results, logs):
    txt_content = generate_txt(scan, results, logs)
    html_content = generate_html(scan, results, logs)

    try:
        supabase.storage.from_("reports").upload(
            f"{SCAN_ID}/report.txt",
            txt_content.encode("utf-8"),
            {"content-type": "text/plain", "upsert": "true"},
        )
        print(f"TXT uploaded: {len(txt_content)} bytes")
    except Exception as e:
        print(f"TXT upload error: {e}")

    try:
        supabase.storage.from_("reports").upload(
            f"{SCAN_ID}/report.html",
            html_content.encode("utf-8"),
            {"content-type": "text/html", "upsert": "true"},
        )
        print(f"HTML uploaded: {len(html_content)} bytes")
    except Exception as e:
        print(f"HTML upload error: {e}")

    return txt_content, html_content


def main():
    print(f"Generating reports for scan {SCAN_ID}")
    scan, results, logs = fetch_data()
    print(f"Fetched {len(results)} results")
    txt_content, html_content = save_reports(scan, results, logs)
    print(f"TXT report: {len(txt_content)} bytes")
    print(f"HTML report: {len(html_content)} bytes")
    print("Reports generated successfully")


if __name__ == "__main__":
    main()
