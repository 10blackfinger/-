
import os
import sys
import json
import time
import argparse
from datetime import datetime, timezone

class SecurityReportGenerator:
    def __init__(self, target, scan_id, results, output_dir="reports"):
        self.target = target
        self.scan_id = scan_id
        self.results = results if isinstance(results, dict) else {}
        self.output_dir = output_dir
        self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

    def calculate_summary_metrics(self):
        critical = 0
        high = 0
        medium = 0
        low = 0
        info = 0

        vulnerabilities = self.results.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            severity = str(vuln.get("severity", "info")).lower()
            if severity == "critical":
                critical += 1
            elif severity == "high":
                high += 1
            elif severity == "medium":
                medium += 1
            elif severity == "low":
                low += 1
            else:
                info += 1

        total = critical + high + medium + low + info
        return {
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info
        }

    def generate_html_report(self):
        metrics = self.calculate_summary_metrics()
        html_file = os.path.join(self.output_dir, f"report_{self.scan_id}.html")
        
        vulnerabilities = self.results.get("vulnerabilities", [])
        tool_outputs = self.results.get("tool_outputs", {})

        vuln_rows_html = ""
        if vulnerabilities:
            for v in vulnerabilities:
                sev = str(v.get("severity", "INFO")).upper()
                badge_class = "bg-info"
                if sev == "CRITICAL": badge_class = "bg-critical"
                elif sev == "HIGH": badge_class = "bg-high"
                elif sev == "MEDIUM": badge_class = "bg-medium"
                elif sev == "LOW": badge_class = "bg-low"

                vuln_rows_html += f"""
                <tr>
                    <td><span class="badge {badge_class}">{sev}</span></td>
                    <td><strong>{v.get('title', 'Vulnerability Finding')}</strong></td>
                    <td><code>{v.get('tool', 'Scanner')}</code></td>
                    <td>{v.get('description', 'No details provided.')}</td>
                </tr>
                """
        else:
            vuln_rows_html = "<tr><td colspan='4' style='text-align:center;'>No critical security vulnerabilities were discovered during this scan.</td></tr>"

        raw_logs_html = ""
        for tool, out in tool_outputs.items():
            raw_logs_html += f"""
            <div class="log-section">
                <h3>🔍 Output: {tool}</h3>
                <pre><code>{out}</code></pre>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>10blackfingers - Security Scan Report ({self.scan_id})</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-color: #c9d1d9;
            --heading-color: #58a6ff;
            --critical: #f85149;
            --high: #da3633;
            --medium: #d29922;
            --low: #3fb950;
            --info: #58a6ff;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: var(--heading-color);
            margin: 0 0 10px 0;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .meta-card {{
            background: var(--card-bg);
            padding: 15px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: var(--card-bg);
            padding: 20px;
            border-radius: 6px;
            text-align: center;
            border: 1px solid var(--border-color);
        }}
        .metric-card .number {{
            font-size: 2.5rem;
            font-weight: bold;
        }}
        .table-container {{
            overflow-x: auto;
            margin-bottom: 30px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border-radius: 6px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: #21262d;
            color: #f0f6fc;
        }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.8rem;
            color: #ffffff;
        }}
        .bg-critical {{ background-color: var(--critical); }}
        .bg-high {{ background-color: var(--high); }}
        .bg-medium {{ background-color: var(--medium); color: #000; }}
        .bg-low {{ background-color: var(--low); color: #000; }}
        .bg-info {{ background-color: var(--info); color: #000; }}
        .log-section {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 20px;
        }}
        pre {{
            background: #010409;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            color: #7ee787;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ 10blackfingers Security Assessment Report</h1>
            <p>Automated Penetration Testing & Vulnerability Assessment Dashboard Findings</p>
        </div>

        <div class="meta-grid">
            <div class="meta-card">
                <strong>Target Domain / IP:</strong><br>{self.target}
            </div>
            <div class="meta-card">
                <strong>Scan Identifier:</strong><br><code>{self.scan_id}</code>
            </div>
            <div class="meta-card">
                <strong>Timestamp:</strong><br>{self.timestamp}
            </div>
            <div class="meta-card">
                <strong>Status:</strong><br><span style="color:#3fb950; font-weight:bold;">COMPLETED</span>
            </div>
        </div>

        <h2>📊 Executive Summary</h2>
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="number">{metrics['total']}</div>
                <div>Total Findings</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid var(--critical);">
                <div class="number" style="color: var(--critical);">{metrics['critical']}</div>
                <div>Critical</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid var(--high);">
                <div class="number" style="color: var(--high);">{metrics['high']}</div>
                <div>High</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid var(--medium);">
                <div class="number" style="color: var(--medium);">{metrics['medium']}</div>
                <div>Medium</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid var(--low);">
                <div class="number" style="color: var(--low);">{metrics['low']}</div>
                <div>Low</div>
            </div>
        </div>

        <h2>🚨 Vulnerability Breakdown</h2>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Vulnerability</th>
                        <th>Source Tool</th>
                        <th>Description & Evidence</th>
                    </tr>
                </thead>
                <tbody>
                    {vuln_rows_html}
                </tbody>
            </table>
        </div>

        <h2>📋 Execution Console Logs</h2>
        {raw_logs_html if raw_logs_html else "<p>No raw execution logs were generated.</p>"}

        <div style="text-align: center; margin-top: 50px; color: #8b949e; font-size: 0.85rem;">
            Generated by 10blackfingers Automated Security Engine • ISEF Competition Edition
        </div>
    </div>
</body>
</html>
"""
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f"[+] HTML Report generated successfully: {html_file}")
        return html_file

    def generate_json_report(self):
        json_file = os.path.join(self.output_dir, f"report_{self.scan_id}.json")
        report_data = {
            "scan_id": self.scan_id,
            "target": self.target,
            "timestamp": self.timestamp,
            "summary": self.calculate_summary_metrics(),
            "results": self.results
        }
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)

        print(f"[+] JSON Report generated successfully: {json_file}")
        return json_file

    def generate_all(self):
        html_path = self.generate_html_report()
        json_path = self.generate_json_report()
        return {"html": html_path, "json": json_path}

def main():
    parser = argparse.ArgumentParser(description="10blackfingers Security Report Generator")
    parser.add_argument("--target", required=True, help="Target URL or IP Address")
    parser.add_argument("--scan-id", required=True, help="Unique Scan UUID")
    parser.add_argument("--results-json", required=True, help="Path to JSON results file")
    parser.add_argument("--output-dir", default="reports", help="Output directory for generated reports")

    args = parser.parse_args()

    try:
        with open(args.results_json, "r", encoding="utf-8") as f:
            results_data = json.load(f)
    except Exception as e:
        print(f"[-] Error loading results JSON: {e}")
        results_data = {}

    generator = SecurityReportGenerator(
        target=args.target,
        scan_id=args.scan_id,
        results=results_data,
        output_dir=args.output_dir
    )
    generator.generate_all()

if __name__ == "__main__":
    main()