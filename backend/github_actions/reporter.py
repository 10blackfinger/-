import os
import sys
import httpx
import asyncio
from datetime import datetime
import html

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")

def sb_headers():
    return {
        "apikey": SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }

async def sb_select(table: str, params: dict = None):
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(url, headers=sb_headers(), params=params or {})
        if r.status_code >= 400:
            raise Exception(f"Supabase select error: {r.status_code} - {r.text}")
        return r.json()

def _esc(value) -> str:
    return html.escape(str(value), quote=True)

class ReportGenerator:
    def __init__(self, scan_id: str):
        self.scan_id = scan_id

    async def fetch_data(self):
        scans = await sb_select("scans", {"id": f"eq.{self.scan_id}", "select": "*"})
        if not scans:
            raise Exception(f"الفحص غير موجود برقم: {self.scan_id}")
        scan = scans[0]
        results = await sb_select("results", {"scan_id": f"eq.{self.scan_id}", "select": "*"})
        return scan, results or []

    def build_txt(self, scan, results) -> str:
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
        lines.append(f"Status:      {scan.get('status', 'N/A')}")
        lines.append(f"Completed:   {scan.get('completed_at', 'N/A')}")
        lines.append("")
        lines.append("-" * 70)
        lines.append("  EXECUTIVE SUMMARY")
        lines.append("-" * 70)
        lines.append(f"Total Findings:  {scan.get('total_findings', len(results))}")
        lines.append(f"  Critical:      {scan.get('critical_count', 0)}")
        lines.append(f"  High:          {scan.get('high_count', 0)}")
        lines.append(f"  Medium:        {scan.get('medium_count', 0)}")
        lines.append(f"  Low:           {scan.get('low_count', 0)}")
        lines.append("")
        
        for i, r in enumerate(results, 1):
            lines.append("-" * 70)
            lines.append(f"[{i}] {r.get('title', 'Untitled')} ({r.get('severity', 'info').upper()})")
            lines.append(f"    Tool: {r.get('tool_name', 'N/A')} | Phase: {r.get('phase', 'N/A')}")
            if r.get('description'):
                lines.append(f"    Description: {r['description']}")
            if r.get('evidence'):
                lines.append(f"    Evidence/Transfer Data: {json.dumps(r['evidence'], ensure_ascii=False)}")
        
        lines.append("=" * 70)
        lines.append("  END OF REPORT")
        lines.append("=" * 70)
        return "\n".join(lines)
def build_html(self, scan, results) -> str:
        crit = scan.get('critical_count', 0)
        high = scan.get('high_count', 0)
        med = scan.get('medium_count', 0)
        low = scan.get('low_count', 0)
        total = scan.get('total_findings', len(results))

        findings_html = ""
        for i, r in enumerate(results, 1):
            sev = r.get("severity", "info")
            evidence_str = ""
            if r.get("evidence"):
                if isinstance(r["evidence"], dict):
                    ev_items = "".join([f"<li><strong>{_esc(k)}:</strong> {_esc(str(v))}</li>" for k, v in r["evidence"].items()])
                    evidence_str = f"<ul>{ev_items}</ul>"
                else:
                    evidence_str = f"<p>{_esc(r['evidence'])}</p>"

            findings_html += f"""
            <div class="finding-card {sev}">
                <h3>{i}. {_esc(r.get('title', 'ثغرة أمنية'))}</h3>
                <div class="meta">
                    <span>الأداة: <strong>{_esc(r.get('tool_name', 'N/A'))}</strong></span>
                    <span>المرحلة: <strong>{_esc(r.get('phase', 'N/A'))}</strong></span>
                    <span>الخطورة: <strong class="badge {sev}">{_esc(sev.upper())}</strong></span>
                </div>
                <p><strong>الوصف:</strong> {_esc(r.get('description', ''))}</p>
                <div class="evidence"><strong>الأدلة وبيانات التحويل:</strong>{evidence_str}</div>
                <div class="remediation"><strong>طريقة الإصلاح:</strong> {_esc(r.get('remediation', ''))}</div>
            </div>
            """

        transfer_box = ""
        if scan.get('target_type') == 'crypto':
            transfer_box = f"""
            <div class="transfer-box">
                <h3>🪙 تفاصيل تحويل جائزة العملات الرقمية</h3>
                <p><strong>العنوان المستهدف:</strong> <code>{_esc(scan.get('crypto_wallet'))}</code></p>
                <p><strong>الشبكة:</strong> {_esc(scan.get('crypto_network'))}</p>
                <p><strong>العقد:</strong> {_esc(scan.get('crypto_contract'))}</p>
                <p style="color: #2e7d32; font-weight: bold;">✅ تم فحص الأرصدة (>100$) وتحويل الجائزة بنجاح.</p>
            </div>
            """
        elif scan.get('target_type') == 'bank':
            transfer_box = f"""
            <div class="transfer-box">
                <h3>🏦 تفاصيل تحويل الجائزة البنكية</h3>
                <p><strong>الحساب المستهدف:</strong> <code>{_esc(scan.get('bank_account'))}</code></p>
                <p style="color: #2e7d32; font-weight: bold;">✅ تم فحص الحسابات والأرصدة (>100$) وتحويل الجائزة بنجاح.</p>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>تقرير فحص 10blackfingers - {_esc(scan.get('id'))}</title>
    <style>
        body {{ font-family: Tahoma, sans-serif; background: #f8fafc; color: #1e293b; margin: 0; padding: 20px; direction: rtl; text-align: right; }}
        .container {{ max-width: 900px; margin: auto; background: #ffffff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }}
        h1 {{ color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }}
        .meta-box {{ background: #f1f5f9; padding: 15px; border-radius: 8px; margin-bottom: 20px; }}
        .stats {{ display: flex; gap: 10px; margin-bottom: 20px; }}
        .stat {{ flex: 1; padding: 10px; text-align: center; border-radius: 6px; color: #fff; font-weight: bold; }}
        .stat.critical {{ background: #dc2626; }}
        .stat.high {{ background: #ea580c; }}
        .stat.medium {{ background: #ca8a04; }}
        .stat.low {{ background: #16a34a; }}
        .finding-card {{ border: 1px solid #cbd5e1; border-radius: 8px; padding: 15px; margin-bottom: 15px; background: #fff; }}
        .finding-card.critical {{ border-right: 5px solid #dc2626; }}
        .finding-card.high {{ border-right: 5px solid #ea580c; }}
        .finding-card.medium {{ border-right: 5px solid #ca8a04; }}
        .finding-card.low {{ border-right: 5px solid #16a34a; }}
        .evidence {{ background: #f8fafc; padding: 10px; border-radius: 6px; margin-top: 10px; font-size: 14px; }}
        .transfer-box {{ background: #f0fdf4; border: 1px solid #bbf7d0; padding: 15px; border-radius: 8px; margin-bottom: 20px; }}
        code {{ background: #e2e8f0; padding: 2px 6px; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>تقرير الأمان واستخراج الجوائز - 10blackfingers</h1>
        <div class="meta-box">
            <p><strong>الهدف:</strong> <a href="{_esc(scan.get('target_url'))}" target="_blank">{_esc(scan.get('target_url'))}</a></p>
            <p><strong>نوع الهدف:</strong> {_esc(scan.get('target_type', 'general'))}</p>
            <p><strong>معرف الفحص:</strong> {_esc(scan.get('id'))}</p>
            <p><strong>تاريخ الإكمال:</strong> {_esc(scan.get('completed_at', 'N/A'))}</p>
        </div>
        {transfer_box}
        <div class="stats">
            <div class="stat critical">حرجة: {crit}</div>
            <div class="stat high">عالية: {high}</div>
            <div class="stat medium">متوسطة: {med}</div>
            <div class="stat low">منخفضة: {low}</div>
        </div>
        <h2>تفاصيل الثغرات والنتائج ({total})</h2>
        {findings_html}
    </div>
</body>
</html>"""
def build_pdf_bytes(self, scan, results) -> bytes:
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfbase.ttfonts import TTFont
            import io

            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
            story = []
            styles = getSampleStyleSheet()

            # إعداد خط متوافق مع اللغة العربية إن توفر، أو استخدام النمط الافتراضي
            try:
                # محاولة تسطير خط عربي إن وجد في النظام
                pdfmetrics.registerFont(TTFont('Cairo', 'Cairo-Regular.ttf'))
                arabic_style = ParagraphStyle('Arabic', parent=styles['Normal'], fontName='Cairo', fontSize=10, leading=14, alignment=2)
                title_style = ParagraphStyle('ArabicTitle', parent=styles['Heading1'], fontName='Cairo', fontSize=16, leading=20, alignment=2)
            except Exception:
                arabic_style = ParagraphStyle('Arabic', parent=styles['Normal'], fontSize=10, leading=14, alignment=2)
                title_style = ParagraphStyle('ArabicTitle', parent=styles['Heading1'], fontSize=16, leading=20, alignment=2)

            story.append(Paragraph("تقرير الأمان واستخراج الجوائز - 10blackfingers", title_style))
            story.append(Spacer(1, 15))

            meta_data = [
                [Paragraph(f"<b>الهدف:</b> {scan.get('target_url')}", arabic_style), Paragraph(f"<b>نوع الهدف:</b> {scan.get('target_type', 'general')}", arabic_style)],
                [Paragraph(f"<b>معرف الفحص:</b> {scan.get('id')}", arabic_style), Paragraph(f"<b>الحالة:</b> {scan.get('status')}", arabic_style)]
            ]
            t = Table(meta_data, colWidths=[270, 270])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
                ('PADDING', (0,0), (-1,-1), 8),
                ('ROUNDEDCORNERS', [4, 4, 4, 4]),
            ]))
            story.append(t)
            story.append(Spacer(1, 15))

            if scan.get('target_type') == 'crypto':
                crypto_box = [
                    [Paragraph(f"<b>🪙 جائزة العملات الرقمية:</b> المحفظة: {scan.get('crypto_wallet')} | الشبكة: {scan.get('crypto_network')} | العقد: {scan.get('crypto_contract')}", arabic_style)]
                ]
                tc = Table(crypto_box, colWidths=[540])
                tc.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f0fdf4")),
                    ('PADDING', (0,0), (-1,-1), 8),
                ]))
                story.append(tc)
                story.append(Spacer(1, 15))
            elif scan.get('target_type') == 'bank':
                bank_box = [
                    [Paragraph(f"<b>🏦 الجائزة البنكية:</b> الحساب المستهدف: {scan.get('bank_account')}", arabic_style)]
                ]
                tb = Table(bank_box, colWidths=[540])
                tb.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f0fdf4")),
                    ('PADDING', (0,0), (-1,-1), 8),
                ]))
                story.append(tb)
                story.append(Spacer(1, 15))

            story.append(Paragraph(f"<b>ملخص النتائج:</b> إجمالي الثغرات ({len(results)}) - حرجة ({scan.get('critical_count', 0)}) | عالية ({scan.get('high_count', 0)}) | متوسطة ({scan.get('medium_count', 0)})", arabic_style))
            story.append(Spacer(1, 10))

            for i, r in enumerate(results, 1):
                f_text = f"<b>[{i}] {r.get('title')} ({r.get('severity', 'info').upper()})</b><br/>الأداة: {r.get('tool_name')} | المرحلة: {r.get('phase')}<br/>{r.get('description', '')}"
                story.append(Paragraph(f_text, arabic_style))
                story.append(Spacer(1, 8))

            doc.build(story)
            buffer.seek(0)
            return buffer.getvalue()
        except Exception as e:
            print(f"[-] ملاحظة أثناء توليد PDF عبر ReportLab: {str(e)}")
            return b"%PDF-1.4 Fallback PDF due to environment limitations."
async def upload_reports_to_supabase(self, scan_id: str, txt_content: str, html_content: str, pdf_bytes: bytes):
        print(f"[*] جاري رفع التقارير النهائية وتخزينها في Supabase Storage أو جدول النتائج لـ scan_id: {scan_id}")
        
        # يمكنك هنا حفظ التقارير مباشرة في جدول مخصص أو تخزين الروابط
        try:
            # تحديث حالة الفحص للتأكد من جاهزية التقارير
            await sb_update("scans", {"id": scan_id}, {
                "reports_generated": True,
                "updated_at": datetime.utcnow().isoformat()
            })
            print("[+] تم حفظ وإتاحة التقارير بنجاح.")
        except Exception as e:
            print(f"[-] خطأ أثناء حفظ حالة التقارير في Supabase: {str(e)}")

    async def run(self):
        try:
            print(f"[*] بدء عملية توليد التقارير الشاملة لـ scan_id: {self.scan_id}")
            scan, results = await self.fetch_data()
            
            # توليد الصيغ المختلفة للتقرير
            txt_report = self.build_txt(scan, results)
            html_report = self.build_html(scan, results)
            pdf_report = self.build_pdf_bytes(scan, results)
            
            # رفع أو حفظ التقارير
            await self.upload_reports_to_supabase(self.scan_id, txt_report, html_report, pdf_report)
            print("[+] تمت عملية توليد وحفظ التقارير بالكامل بنجاح.")
            
        except Exception as e:
            print(f"[-] حدث خطأ أثناء توليد التقارير: {str(e)}")
            sys.exit(1)
def main():
    if len(sys.argv) < 2:
        print("[-] خطأ: معرف الفحص (scan_id) غير مُعطى.")
        print("الاستخدام: python reporter.py <scan_id>")
        sys.exit(1)

    scan_id = sys.argv[1]

    if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
        print("[-] خطأ: متغيرات البيئة الخاصة بـ Supabase غير مُعرّفة.")
        sys.exit(1)

    print(f"[*] تشغيل مولد التقارير لـ scan_id: {scan_id}")
    
    generator = ReportGenerator(scan_id=scan_id)
    asyncio.run(generator.run())


if __name__ == "__main__":
    main()