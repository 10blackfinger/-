import os
import re
import json
import subprocess
import tempfile
from datetime import datetime
from urllib.parse import urlparse

from supabase import create_client


SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
SCAN_ID = os.environ["SCAN_ID"]
TARGET_URL = os.environ["TARGET_URL"]


supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)


def log(message, level="info"):
    try:
        supabase.table("logs").insert({
            "scan_id": SCAN_ID,
            "level": level,
            "message": message,
        }).execute()
    except Exception:
        pass
    print(f"[{level.upper()}] {message}")


def save_result(phase, tool_name, severity, title, description="", evidence=None, remediation="", cve_id=None, cvss=None):
    try:
        supabase.table("results").insert({
            "scan_id": SCAN_ID,
            "phase": phase,
            "tool_name": tool_name,
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": evidence or {},
            "remediation": remediation,
            "cve_id": cve_id,
            "cvss_score": cvss,
        }).execute()
    except Exception as e:
        print(f"Error saving result: {e}")


def run_command(cmd, timeout=300):
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


# ============== PHASE 1: RECONNAISSANCE ==============

def phase_recon():
    log("Starting reconnaissance phase")
    domain = urlparse(TARGET_URL).netloc

    # 1. Nmap
    log("Running nmap...")
    stdout, _, _ = run_command(
        f"nmap -T4 --top-ports 100 -sV {domain} -oX - 2>/dev/null",
        timeout=180,
    )
    if stdout:
        ports = re.findall(r'portid="(\d+)".*?name="([^"]*)"', stdout)
        for port, service in ports:
            save_result("recon", "nmap", "info",
                f"Open port: {port}/{service}",
                f"Port {port} is open and running {service}",
                evidence={"port": port, "service": service})

    # 2. WhatWeb
    log("Running WhatWeb...")
    stdout, _, _ = run_command(f"whatweb {TARGET_URL} --log-json=- 2>/dev/null", timeout=60)
    if stdout:
        try:
            data = json.loads(stdout)
            for entry in data:
                plugins = entry.get("plugins", {})
                for plugin_name, plugin_data in plugins.items():
                    save_result("recon", "whatweb", "info",
                        f"Technology detected: {plugin_name}",
                        f"Detected {plugin_name} with version info",
                        evidence={"plugin": plugin_name, "data": plugin_data})
        except Exception as e:
            log(f"WhatWeb parse error: {e}", "warning")

    # 3. WAFW00F
    log("Running WAFW00F...")
    stdout, _, _ = run_command(f"wafw00f {TARGET_URL} -a 2>/dev/null", timeout=60)
    if stdout and "is behind" in stdout:
        waf_match = re.search(r"is behind (.+)", stdout)
        if waf_match:
            save_result("recon", "wafw00f", "info",
                f"WAF detected: {waf_match.group(1).strip()}",
                "Web Application Firewall detected",
                evidence={"waf": waf_match.group(1).strip()})

    # 4. Subfinder
    log("Running subfinder...")
    stdout, _, _ = run_command(f"subfinder -d {domain} -silent 2>/dev/null", timeout=120)
    if stdout:
        subdomains = [s.strip() for s in stdout.strip().split("\n") if s.strip()]
        if subdomains:
            save_result("recon", "subfinder", "info",
                f"Found {len(subdomains)} subdomains",
                "Subdomains discovered",
                evidence={"subdomains": subdomains[:100]})

    # 5. Amass
    log("Running amass...")
    stdout, _, _ = run_command(f"amass enum -passive -d {domain} -timeout 2 2>/dev/null", timeout=120)
    if stdout:
        entries = [s.strip() for s in stdout.strip().split("\n") if s.strip()]
        if entries:
            save_result("recon", "amass", "info",
                f"Amass found {len(entries)} entries",
                "Passive enumeration results",
                evidence={"entries": entries[:100]})

    # 6. HTTPX
    log("Running httpx...")
    stdout, _, _ = run_command(
        f"httpx -u {TARGET_URL} -json -silent -tech-detect -status-code -title 2>/dev/null",
        timeout=120,
    )
    if stdout:
        try:
            for line in stdout.strip().split("\n"):
                if not line.strip():
                    continue
                data = json.loads(line)
                save_result("recon", "httpx", "info",
                    f"HTTP probe: {data.get('status_code', '?')} - {data.get('title', '')}",
                    f"Tech: {', '.join(data.get('tech', []))}",
                    evidence=data)
        except json.JSONDecodeError:
            pass

    # 7. Katana
    log("Running katana...")
    stdout, _, _ = run_command(
        f"katana -u {TARGET_URL} -silent -d 2 -jc -timeout 5 2>/dev/null | head -200",
        timeout=300,
    )
    if stdout:
        urls = [u.strip() for u in stdout.strip().split("\n") if u.strip()]
        save_result("recon", "katana", "info",
            f"Crawled {len(urls)} URLs",
            "URLs discovered via crawling",
            evidence={"urls": urls[:100]})

    # 8. Gau
    log("Running gau...")
    stdout, _, _ = run_command(
        f"echo {domain} | gau --threads 5 2>/dev/null | head -200",
        timeout=180,
    )
    if stdout:
        urls = [u.strip() for u in stdout.strip().split("\n") if u.strip()]
        if urls:
            save_result("recon", "gau", "info",
                f"GAU found {len(urls)} URLs",
                "Historical URLs from Wayback Machine",
                evidence={"urls": urls[:100]})

    # 9. Waybackurls
    log("Running waybackurls...")
    stdout, _, _ = run_command(
        f"echo {domain} | waybackurls 2>/dev/null | head -200",
        timeout=120,
    )
    if stdout:
        urls = [u.strip() for u in stdout.strip().split("\n") if u.strip()]
        if urls:
            save_result("recon", "waybackurls", "info",
                f"Wayback found {len(urls)} URLs",
                "URLs from Wayback Machine",
                evidence={"urls": urls[:100]})

    # 10. Dnsx
    log("Running dnsx...")
    stdout, _, _ = run_command(
        f"echo {domain} | dnsx -silent -a -resp 2>/dev/null",
        timeout=60,
    )
    if stdout:
        save_result("recon", "dnsx", "info",
            "DNS records resolved",
            "DNS A records for target",
            evidence={"output": stdout[:500]})

    # 11. Naabu
    log("Running naabu...")
    stdout, _, _ = run_command(
        f"naabu -host {domain} -top-ports 100 -silent 2>/dev/null",
        timeout=180,
    )
    if stdout:
        ports = [p.strip() for p in stdout.strip().split("\n") if p.strip()]
        if ports:
            save_result("recon", "naabu", "info",
                f"Naabu found {len(ports)} open ports",
                "Open ports discovered",
                evidence={"ports": ports})

    # 12. Tlsx
    log("Running tlsx...")
    stdout, _, _ = run_command(
        f"echo {domain} | tlsx -silent -san -cn -tls-version 2>/dev/null",
        timeout=60,
    )
    if stdout:
        save_result("recon", "tlsx", "info",
            "TLS/SSL information",
            "SSL certificate details",
            evidence={"output": stdout[:500]})

    # 13. WHOIS
    log("Running whois...")
    stdout, _, _ = run_command(f"whois {domain} 2>/dev/null | head -50", timeout=60)
    if stdout:
        save_result("recon", "whois", "info",
            "WHOIS information",
            "Domain registration details",
            evidence={"output": stdout[:1000]})

    # 14. Dig
    log("Running dig...")
    stdout, _, _ = run_command(f"dig {domain} ANY +short 2>/dev/null", timeout=30)
    if stdout:
        save_result("recon", "dig", "info",
            "DNS records",
            "DNS ANY query results",
            evidence={"output": stdout[:500]})

    # 15. CeWL
    log("Running cewl...")
    stdout, _, _ = run_command(f"cewl {TARGET_URL} -d 2 -m 5 2>/dev/null | head -50", timeout=120)
    if stdout:
        words = [w.strip() for w in stdout.strip().split("\n") if w.strip()]
        if words:
            save_result("recon", "cewl", "info",
                f"CeWL found {len(words)} words",
                "Custom wordlist generated",
                evidence={"words": words[:50]})

    # 16. SSLyze
    log("Running sslyze...")
    stdout, _, _ = run_command(
        f"sslyze --regular {domain} 2>/dev/null | head -100",
        timeout=120,
    )
    if stdout:
        save_result("recon", "sslyze", "info",
            "SSL/TLS deep scan",
            "Certificate and cipher analysis",
            evidence={"output": stdout[:1000]})

    # 17. DNSRecon
    log("Running dnsrecon...")
    stdout, _, _ = run_command(
        f"dnsrecon -d {domain} -t std 2>/dev/null | head -80",
        timeout=120,
    )
    if stdout:
        save_result("recon", "dnsrecon", "info",
            "DNS reconnaissance",
            "DNS enumeration results",
            evidence={"output": stdout[:1000]})

    # 18. Fierce
    log("Running fierce...")
    stdout, _, _ = run_command(
        f"fierce --domain {domain} 2>/dev/null | head -50",
        timeout=120,
    )
    if stdout:
        save_result("recon", "fierce", "info",
            "Fierce DNS scan",
            "DNS enumeration and zone transfer attempt",
            evidence={"output": stdout[:1000]})

    # 19. TheHarvester
    log("Running theharvester...")
    stdout, _, _ = run_command(
        f"theHarvester -d {domain} -b all -l 100 2>/dev/null | head -80",
        timeout=180,
    )
    if stdout:
        save_result("recon", "theharvester", "info",
            "OSINT gathering",
            "Emails, hosts, and subdomains discovered",
            evidence={"output": stdout[:2000]})

    # 20. SpiderFoot
    log("Running spiderfoot...")
    stdout, _, _ = run_command(
        f"python3 /opt/spiderfoot/sf.py -s {domain} -q -o json 2>/dev/null | head -100",
        timeout=180,
    )
    if stdout:
        save_result("recon", "spiderfoot", "info",
            "SpiderFoot OSINT",
            "Comprehensive OSINT scan results",
            evidence={"output": stdout[:2000]})

        # ============== PHASE 2: KNOWN VULNERABILITIES ==============

def phase_known_vulns():
    log("Starting known vulnerabilities phase")

    # 21. Nuclei
    log("Running nuclei...")
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        output_file = f.name
    run_command(
        f"nuclei -u {TARGET_URL} -severity critical,high,medium,low "
        f"-json-export {output_file} -silent -timeout 600 2>/dev/null",
        timeout=900,
    )
    try:
        with open(output_file, 'r') as f:
            for line in f:
                try:
                    finding = json.loads(line)
                    info = finding.get("info", {})
                    save_result(
                        "known_vulns", "nuclei",
                        info.get("severity", "info"),
                        info.get("name", "Unknown vulnerability"),
                        info.get("description", ""),
                        evidence={
                            "matched_at": finding.get("matched-at"),
                            "template": finding.get("template-id"),
                            "type": finding.get("type"),
                        },
                        remediation=info.get("remediation", ""),
                        cve_id=",".join(info.get("classification", {}).get("cve-id", []) or []) or None,
                    )
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        log("Nuclei output file not found", "warning")

    # 22. Nikto
    log("Running nikto...")
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        nikto_out = f.name
    run_command(
        f"nikto -h {TARGET_URL} -Format json -output {nikto_out} -maxtime 300 2>/dev/null",
        timeout=400,
    )
    try:
        with open(nikto_out, 'r') as f:
            content = f.read()
            if content:
                data = json.loads(content)
                for vuln in data.get("vulnerabilities", []):
                    save_result(
                        "known_vulns", "nikto", "medium",
                        vuln.get("msg", "Nikto finding"),
                        f"URL: {vuln.get('url', '')}, Method: {vuln.get('method', '')}",
                        evidence={"id": vuln.get("id"), "osvdb": vuln.get("OSVDB")},
                    )
    except Exception as e:
        log(f"Nikto parse error: {e}", "warning")

    # 23. SQLMap
    log("Running sqlmap...")
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        sqlmap_out = f.name
    run_command(
        f"sqlmap -u '{TARGET_URL}' --batch --level=1 --risk=1 "
        f"--output-dir=/tmp/sqlmap --forms --crawl=1 --timeout=10 --retries=1 "
        f"2>/dev/null | tee {sqlmap_out}",
        timeout=600,
    )
    try:
        with open(sqlmap_out, 'r') as f:
            content = f.read()
            if "is vulnerable" in content.lower() or "injectable" in content.lower():
                save_result(
                    "known_vulns", "sqlmap", "critical",
                    "SQL Injection detected",
                    "SQLMap found injectable parameter",
                    evidence={"output": content[:2000]},
                    remediation="Use prepared statements and parameterized queries",
                )
    except Exception as e:
        log(f"SQLMap parse error: {e}", "warning")

    # 24. Wapiti
    log("Running wapiti...")
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        wapiti_out = f.name
    run_command(
        f"wapiti -u {TARGET_URL} -f json -o {wapiti_out} -m all --flush-session 2>/dev/null",
        timeout=600,
    )
    try:
        with open(wapiti_out, 'r') as f:
            data = json.load(f)
            for vuln_type, vulns in data.get("vulnerabilities", {}).items():
                for v in vulns:
                    save_result(
                        "known_vulns", "wapiti",
                        v.get("level", "medium"),
                        f"{vuln_type}: {v.get('info', '')}",
                        v.get("parameter", ""),
                        evidence=v,
                    )
    except Exception as e:
        log(f"Wapiti parse error: {e}", "warning")

    # 25. Gobuster
    log("Running gobuster...")
    stdout, _, _ = run_command(
        f"gobuster dir -u {TARGET_URL} -w /usr/share/wordlists/dirb/common.txt "
        f"-t 20 -q 2>/dev/null | head -50",
        timeout=300,
    )
    if stdout:
        paths = [p.strip() for p in stdout.strip().split("\n") if p.strip()]
        if paths:
            save_result("known_vulns", "gobuster", "info",
                f"Gobuster found {len(paths)} paths",
                "Directory brute-force results",
                evidence={"paths": paths[:50]})

    # 26. FFuf
    log("Running ffuf...")
    stdout, _, _ = run_command(
        f"ffuf -u {TARGET_URL}/FUZZ -w /usr/share/wordlists/dirb/common.txt "
        f"-mc 200,301,302,403 -t 20 -s 2>/dev/null | head -30",
        timeout=300,
    )
    if stdout:
        save_result("known_vulns", "ffuf", "info",
            "FFuf fuzzing completed",
            "Directory/parameter fuzzing results",
            evidence={"output": stdout[:1000]})

    # 27. Dirsearch
    log("Running dirsearch...")
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        dirsearch_out = f.name
    run_command(
        f"dirsearch -u {TARGET_URL} -e php,html,js,txt,json -t 20 "
        f"--format=json -o {dirsearch_out} 2>/dev/null",
        timeout=300,
    )
    try:
        with open(dirsearch_out, 'r') as f:
            data = json.load(f)
            for r in data.get("results", []):
                save_result("known_vulns", "dirsearch", "info",
                    f"Path found: {r.get('path', '')}",
                    f"Status: {r.get('status', '')}, Size: {r.get('content-length', '')}",
                    evidence=r)
    except Exception as e:
        log(f"Dirsearch parse error: {e}", "warning")

    # 28. Wfuzz
    log("Running wfuzz...")
    stdout, _, _ = run_command(
        f"wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt "
        f"--hc 404 -t 20 {TARGET_URL}/FUZZ 2>/dev/null | head -30",
        timeout=300,
    )
    if stdout:
        save_result("known_vulns", "wfuzz", "info",
            "Wfuzz completed",
            "Fuzzing results",
            evidence={"output": stdout[:1000]})

    # 29. Dalfox
    log("Running dalfox...")
    stdout, _, _ = run_command(
        f"dalfox url {TARGET_URL} --silence --no-color 2>/dev/null | head -30",
        timeout=300,
    )
    if stdout and "vulnerable" in stdout.lower():
        save_result("known_vulns", "dalfox", "high",
            "XSS vulnerability detected",
            "Dalfox found XSS vulnerability",
            evidence={"output": stdout[:2000]},
            remediation="Sanitize user input and use output encoding")

    # 30. Retire.js
    log("Running retire.js...")
    stdout, _, _ = run_command(
        f"retire --js --url {TARGET_URL} --outputformat json 2>/dev/null",
        timeout=120,
    )
    if stdout:
        try:
            data = json.loads(stdout)
            for finding in (data if isinstance(data, list) else []):
                save_result("known_vulns", "retirejs", "medium",
                    f"Vulnerable JS library: {finding.get('library', '')}",
                    str(finding.get("vulnerabilities", [{}])[0].get("info", ""))[:500],
                    evidence=finding)
        except json.JSONDecodeError:
            pass

    # 31. WPScan (WordPress)
    log("Running wpscan...")
    stdout, _, _ = run_command(
        f"wpscan --url {TARGET_URL} --no-update --format json 2>/dev/null | head -100",
        timeout=300,
    )
    if stdout and "wordpress" in stdout.lower():
        save_result("known_vulns", "wpscan", "info",
            "WPScan results",
            "WordPress vulnerability scan",
            evidence={"output": stdout[:2000]})

    # 32. Skipfish
    log("Running skipfish...")
    stdout, _, _ = run_command(
        f"timeout 60 skipfish -o /tmp/skipfish_out {TARGET_URL} 2>/dev/null | head -30",
        timeout=120,
    )
    if stdout:
        save_result("known_vulns", "skipfish", "info",
            "Skipfish scan",
            "Web security scan results",
            evidence={"output": stdout[:1000]})

    # 33. Commix
    log("Running commix...")
    stdout, _, _ = run_command(
        f"commix --url='{TARGET_URL}' --batch --level=1 2>/dev/null | head -30",
        timeout=300,
    )
    if stdout and "vulnerable" in stdout.lower():
        save_result("known_vulns", "commix", "critical",
            "Command Injection detected",
            "Commix found command injection vulnerability",
            evidence={"output": stdout[:2000]},
            remediation="Sanitize all user input and avoid system calls")

    # 34. XSStrike
    log("Running xsstrike...")
    stdout, _, _ = run_command(
        f"timeout 120 python3 /opt/XSStrike/xsstrike.py -u {TARGET_URL} --skip 2>/dev/null | head -30",
        timeout=180,
    )
    if stdout and "vulnerable" in stdout.lower():
        save_result("known_vulns", "xsstrike", "high",
            "XSS vulnerability detected (XSStrike)",
            "XSStrike found XSS vulnerability",
            evidence={"output": stdout[:2000]})

    # ============== PHASE 3: ZERO-DAY / ANOMALY ==============

def phase_zero_day():
    log("Starting zero-day / anomaly phase")

    # 35. Katana sensitive endpoints
    log("Analyzing sensitive endpoints...")
    stdout, _, _ = run_command(
        f"katana -u {TARGET_URL} -silent -d 3 2>/dev/null | head -500",
        timeout=600,
    )
    if stdout:
        urls = [u.strip() for u in stdout.strip().split("\n") if u.strip()]
        sensitive_patterns = [
            r'\.(env|git|sql|bak|config|log|yml|yaml|xml|json)$',
            r'(admin|backup|config|api|graphql|swagger|debug|test)',
            r'(\.well-known|\.git/|\.svn/|\.htaccess|\.DS_Store)',
            r'(phpinfo|server-status|server-info)',
            r'(wp-admin|wp-config|xmlrpc)',
        ]
        for url in urls:
            for pattern in sensitive_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    save_result("zero_day", "katana", "medium",
                        f"Potentially sensitive endpoint: {url}",
                        f"Endpoint matched pattern: {pattern}",
                        evidence={"url": url, "pattern": pattern},
                        remediation="Review if this endpoint should be publicly accessible")
                    break

    # 36. Security Headers Analysis
    log("Checking security headers...")
    stdout, _, _ = run_command(f"curl -sI {TARGET_URL} 2>/dev/null", timeout=30)
    if stdout:
        missing = []
        for header in ["strict-transport-security", "content-security-policy",
                       "x-frame-options", "x-content-type-options", "referrer-policy"]:
            if header not in stdout.lower():
                missing.append(header)
        if missing:
            save_result("zero_day", "httpx", "medium",
                f"Missing security headers ({len(missing)})",
                f"Missing: {', '.join(missing)}",
                evidence={"missing": missing, "raw_headers": stdout[:1500]},
                remediation="Add these headers to server configuration")

    # 37. Cookie Security Analysis
    log("Analyzing cookie security...")
    stdout, _, _ = run_command(
        f"curl -sI {TARGET_URL} 2>/dev/null | grep -i 'set-cookie'",
        timeout=30,
    )
    if stdout:
        cookies = stdout.strip().split("\n")
        insecure_flags = []
        for cookie in cookies:
            if "httponly" not in cookie.lower():
                insecure_flags.append("Missing HttpOnly")
            if "secure" not in cookie.lower():
                insecure_flags.append("Missing Secure")
            if "samesite" not in cookie.lower():
                insecure_flags.append("Missing SameSite")
        if insecure_flags:
            save_result("zero_day", "custom", "medium",
                "Insecure cookie flags",
                f"Issues: {', '.join(set(insecure_flags))}",
                evidence={"cookies": cookies, "issues": list(set(insecure_flags))},
                remediation="Set HttpOnly, Secure, and SameSite flags on cookies")

    # 38. CORS Misconfiguration
    log("Checking CORS...")
    stdout, _, _ = run_command(
        f"curl -sI -H 'Origin: https://evil.com' {TARGET_URL} 2>/dev/null | grep -i 'access-control'",
        timeout=30,
    )
    if stdout and "evil.com" in stdout:
        save_result("zero_day", "custom", "high",
            "CORS misconfiguration",
            "Server reflects arbitrary Origin header",
            evidence={"cors_header": stdout.strip()},
            remediation="Validate Origin header against whitelist")

    # 39. Open Redirect
    log("Checking open redirect...")
    redirect_payloads = ["//evil.com", "https://evil.com", "/\\evil.com"]
    for payload in redirect_payloads:
        stdout, _, _ = run_command(
            f"curl -sI '{TARGET_URL}?url={payload}' 2>/dev/null | grep -i 'location'",
            timeout=15,
        )
        if stdout and "evil.com" in stdout:
            save_result("zero_day", "custom", "high",
                "Open redirect vulnerability",
                "Parameter 'url' redirects to external domain",
                evidence={"payload": payload, "response": stdout.strip()},
                remediation="Validate redirect URLs against whitelist")
            break

    # 40. HTTP Methods Check
    log("Checking HTTP methods...")
    stdout, _, _ = run_command(
        f"curl -sX OPTIONS -i {TARGET_URL} 2>/dev/null | grep -i 'allow'",
        timeout=30,
    )
    if stdout:
        save_result("zero_day", "custom", "info",
            "HTTP methods allowed",
            f"Server allows: {stdout.strip()}",
            evidence={"methods": stdout.strip()},
            remediation="Disable unnecessary HTTP methods (PUT, DELETE, TRACE)")

    # 41. Directory Traversal
    log("Checking directory traversal...")
    traversal_payloads = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"]
    for payload in traversal_payloads:
        stdout, _, _ = run_command(
            f"curl -s '{TARGET_URL}/{payload}' 2>/dev/null | head -5",
            timeout=15,
        )
        if stdout and "root:" in stdout:
            save_result("zero_day", "custom", "critical",
                "Directory Traversal vulnerability",
                "Server allows path traversal to /etc/passwd",
                evidence={"payload": payload, "output": stdout[:500]},
                remediation="Validate file paths and restrict access to allowed directories")
            break

    # 42. Information Disclosure
    log("Checking information disclosure...")
    sensitive_files = [".env", ".git/config", "wp-config.php.bak", "backup.sql",
                       "phpinfo.php", "server-status", ".htaccess", ".DS_Store"]
    for f in sensitive_files:
        stdout, _, _ = run_command(
            f"curl -s -o /dev/null -w '%{{http_code}}' {TARGET_URL}/{f} 2>/dev/null",
            timeout=15,
        )
        if stdout and stdout.strip() == "200":
            save_result("zero_day", "custom", "high",
                f"Sensitive file exposed: /{f}",
                f"File /{f} is publicly accessible",
                evidence={"file": f, "status": 200, "url": f"{TARGET_URL}/{f}"},
                remediation=f"Remove or restrict access to /{f}")

    # 43. Server Banner Grabbing
    log("Grabbing server banners...")
    stdout, _, _ = run_command(
        f"curl -sI {TARGET_URL} 2>/dev/null | grep -iE 'server|x-powered-by|x-aspnet'",
        timeout=30,
    )
    if stdout:
        save_result("zero_day", "custom", "info",
            "Server banners exposed",
            f"Server information: {stdout.strip()}",
            evidence={"banners": stdout.strip()},
            remediation="Remove or obscure server version headers")

    # 44. TLS/SSL Configuration Weakness
    log("Checking TLS configuration...")
    domain = urlparse(TARGET_URL).netloc
    stdout, _, _ = run_command(
        f"echo | openssl s_client -connect {domain}:443 "
        f"-tls1_1 2>/dev/null | grep -i 'protocol\\|cipher' | head -5",
        timeout=30,
    )
    if stdout:
        save_result("zero_day", "custom", "medium",
            "TLS configuration issues",
            "Check for weak protocols/ciphers",
            evidence={"output": stdout[:500]},
            remediation="Disable TLS 1.0/1.1, use strong ciphers only")

    # 45. Robots.txt Analysis
    log("Checking robots.txt...")
    stdout, _, _ = run_command(
        f"curl -s {TARGET_URL}/robots.txt 2>/dev/null | head -30",
        timeout=15,
    )
    if stdout and ("disallow" in stdout.lower() or "allow" in stdout.lower()):
        save_result("zero_day", "custom", "info",
            "robots.txt found",
            "Discovered paths from robots.txt",
            evidence={"content": stdout[:1000]},
            remediation="Review if sensitive paths are listed in robots.txt")

    # 46. Sitemap.xml Analysis
    log("Checking sitemap.xml...")
    stdout, _, _ = run_command(
        f"curl -s {TARGET_URL}/sitemap.xml 2>/dev/null | head -30",
        timeout=15,
    )
    if stdout and ("<urlset" in stdout.lower() or "<sitemapindex" in stdout.lower()):
        save_result("zero_day", "custom", "info",
            "Sitemap found",
            "URLs discovered from sitemap.xml",
            evidence={"content": stdout[:1000]})

    # 47. HTTP/2 Support Check
    log("Checking HTTP/2...")
    stdout, _, _ = run_command(
        f"curl -sI --http2 {TARGET_URL} 2>/dev/null | head -1",
        timeout=15,
    )
    if stdout and "HTTP/2" in stdout:
        save_result("zero_day", "custom", "info",
            "HTTP/2 supported",
            f"Server response: {stdout.strip()}",
            evidence={"protocol": "HTTP/2"})

    # 48. HTTP/3 (QUIC) Support Check
    log("Checking HTTP/3...")
    stdout, _, _ = run_command(
        f"curl -sI --http3 {TARGET_URL} 2>/dev/null | head -1",
        timeout=15,
    )
    if stdout and "HTTP/3" in stdout:
        save_result("zero_day", "custom", "info",
            "HTTP/3 supported",
            f"Server response: {stdout.strip()}",
            evidence={"protocol": "HTTP/3"})

    # 49. Certificate Expiry Check
    log("Checking certificate expiry...")
    stdout, _, _ = run_command(
        f"echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null | "
        f"openssl x509 -noout -dates -subject -issuer 2>/dev/null",
        timeout=30,
    )
    if stdout:
        save_result("zero_day", "custom", "info",
            "SSL Certificate details",
            "Certificate information",
            evidence={"output": stdout[:500]})

    # 50. Rate Limiting Check
    log("Checking rate limiting...")
    stdout, _, _ = run_command(
        f"for i in $(seq 1 20); do curl -s -o /dev/null -w '%{{http_code}}\\n' {TARGET_URL} 2>/dev/null; done | sort | uniq -c",
        timeout=60,
    )
    if stdout:
        codes = stdout.strip()
        save_result("zero_day", "custom", "info",
            "Rate limiting analysis",
            f"Response code distribution: {codes}",
            evidence={"codes": codes},
            remediation="Implement rate limiting to prevent abuse")


# ============== MAIN ==============

def main():
    log(f"Starting scan for {TARGET_URL}")

    try:
        supabase.table("scans").update({
            "status": "running",
            "started_at": datetime.utcnow().isoformat(),
        }).eq("id", SCAN_ID).execute()

        phase_recon()
        phase_known_vulns()
        phase_zero_day()

        results = supabase.table("results").select("severity").eq("scan_id", SCAN_ID).execute()
        results_data = results.data or []

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in results_data:
            sev = r.get("severity")
            if sev in counts:
                counts[sev] += 1

        supabase.table("scans").update({
            "status": "completed",
            "completed_at": datetime.utcnow().isoformat(),
            "total_findings": len(results_data),
            "critical_count": counts["critical"],
            "high_count": counts["high"],
            "medium_count": counts["medium"],
            "low_count": counts["low"],
        }).eq("id", SCAN_ID).execute()

        log(f"Scan completed. Total findings: {len(results_data)}", "success")

        # Generate reports (TXT + HTML)
        try:
            from reporter import main as generate_reports
            generate_reports()
            log("Reports generated successfully", "success")
        except Exception as e:
            log(f"Report generation failed: {str(e)}", "warning")

    except Exception as e:
        log(f"Scan failed: {str(e)}", "error")
        supabase.table("scans").update({
            "status": "failed",
            "error_message": str(e),
        }).eq("id", SCAN_ID).execute()
        raise


if __name__ == "__main__":
    main()    