const API_URL = "https://10blackfingers-api.vercel.app";

const form = document.getElementById("scan-form");
const urlInput = document.getElementById("target-url");
const consentCheck = document.getElementById("consent-check");
const scanButton = document.getElementById("scan-button");
const progressContainer = document.getElementById("progress-container");
const progressStatus = document.getElementById("progress-status");
const progressDetail = document.getElementById("progress-detail");
const progressFill = document.getElementById("progress-fill");
const terminalLogs = document.getElementById("terminal-logs");
const resultsContainer = document.getElementById("results-container");
const resultsMeta = document.getElementById("results-meta");
const statsGrid = document.getElementById("stats-grid");
const findingsList = document.getElementById("findings-list");
const errorContainer = document.getElementById("error-container");
const errorMessage = document.getElementById("error-message");

let currentScanId = null;
let pollInterval = null;
let currentResultsCache = [];
let currentFilter = "all";

const SEVERITY_LABELS = {
    critical: "حرجة",
    high: "عالية",
    medium: "متوسطة",
    low: "منخفضة",
    info: "معلومات"
};

function getSessionId() {
    let sid = localStorage.getItem("10bf_session");
    if (!sid) {
        sid = "sess_" + Math.random().toString(36).substring(2, 15) + Date.now().toString(36);
        localStorage.setItem("10bf_session", sid);
    }
    return sid;
}

form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!consentCheck.checked) {
        alert("يجب الموافقة على التصريح القانوني قبل بدء الفحص");
        return;
    }
    const targetUrl = urlInput.value.trim();
    if (!targetUrl) return;

    hideAll();
    showProgress();
    scanButton.disabled = true;
    scanButton.querySelector(".btn-text").textContent = "جاري تنفيذ الفحص السيبراني...";

    try {
        const res = await fetch(`${API_URL}/api/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url: targetUrl,
                consent: true,
                session_id: getSessionId()
            })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({ detail: res.statusText }));
            throw new Error(err.detail || "فشل الاتصال بمحرك الفحص");
        }

        const data = await res.json();
        currentScanId = data.scan_id;
        appendTerminalLog(`[+] Scan job successfully queued. ID: ${currentScanId}`);
        startPolling();
    } catch (err) {
        showError(err.message);
        resetButton();
    }
});

function startPolling() {
    let elapsed = 0;
    pollInterval = setInterval(async () => {
        elapsed += 3;
        updateProgressText(elapsed);

        try {
            const res = await fetch(`${API_URL}/api/scan/${currentScanId}`);
            if (!res.ok) return;
            const data = await res.json();
            const scan = data.scan;

            if (scan.status === "completed") {
                clearInterval(pollInterval);
                appendTerminalLog("[+] Scan orchestration completed successfully.");
                currentResultsCache = data.results || [];
                showResults(scan, currentResultsCache);
                resetButton();
            } else if (scan.status === "failed") {
                clearInterval(pollInterval);
                appendTerminalLog(`[-] Scan failed: ${scan.error_message || "Unknown error"}`);
                showError(scan.error_message || "فشل الفحص الأمني");
                resetButton();
            }
        } catch (e) {
            // تخطي أخطاء الشبكة المؤقتة أثناء الـ polling
        }
    }, 3000);
}

function updateProgressText(seconds) {
    const pct = Math.min(95, (seconds / 250) * 100);
    progressFill.style.width = pct + "%";

    if (seconds < 25) {
        progressStatus.textContent = "المرحلة الأولى: الاستطلاع السريع (Reconnaissance)...";
        progressDetail.textContent = "تشغيل أدوات Nmap, Subfinder, WhatWeb, WAFW00F...";
        if (seconds === 6) appendTerminalLog("[*] Probing target ports and web infrastructure...");
        if (seconds === 15) appendTerminalLog("[*] Running passive reconnaissance modules...");
    } else if (seconds < 100) {
        progressStatus.textContent = "المرحلة الثانية: فحص الثغرات النشطة (Active Vulnerabilities)...";
        progressDetail.textContent = "تشغيل فحص Nuclei, SQLMap, Nikto, Dalfox...";
        if (seconds === 35) appendTerminalLog("[*] Injecting fuzz payloads and analyzing responses...");
        if (seconds === 70) appendTerminalLog("[*] Checking for SQL Injection and XSS vectors...");
    } else if (seconds < 180) {
        progressStatus.textContent = "المرحلة الثالثة: تحليل الشذوذ الأمني والـ Zero-Day...";
        progressDetail.textContent = "فحص Headers, Cookies, CORS, Information Disclosure...";
        if (seconds === 110) appendTerminalLog("[*] Inspecting security headers and cookie flags...");
    } else {
        progressStatus.textContent = "المرحلة الأخيرة: إعداد وتوليد التقارير السيبرانية...";
        progressDetail.textContent = "تجهيز ملفات TXT, HTML والتقرير الرسمي PDF";
        if (seconds === 200) appendTerminalLog("[*] Compiling vulnerability metrics and building PDF report...");
    }
}

function appendTerminalLog(text) {
    if (!terminalLogs) return;
    const div = document.createElement("div");
    div.className = "terminal-line";
    div.textContent = text;
    terminalLogs.appendChild(div);
    terminalLogs.scrollTop = terminalLogs.scrollHeight;
}

function showResults(scan, results) {
    hideAll();
    resultsContainer.classList.remove("hidden");

    resultsMeta.textContent = scan.target_url;
    progressFill.style.width = "100%";

    statsGrid.innerHTML = `
        <div class="stat-card total"><div class="num">${scan.total_findings || 0}</div><div class="label">إجمالي النتائج</div></div>
        <div class="stat-card critical"><div class="num">${scan.critical_count || 0}</div><div class="label">ثغرات حرجة</div></div>
        <div class="stat-card high"><div class="num">${scan.high_count || 0}</div><div class="label">ثغرات عالية</div></div>
        <div class="stat-card medium"><div class="num">${scan.medium_count || 0}</div><div class="label">ثغرات متوسطة</div></div>
        <div class="stat-card low"><div class="num">${scan.low_count || 0}</div><div class="label">ثغرات منخفضة</div></div>
    `;

    renderFindingsList(results);
}

function filterFindings(severity) {
    currentFilter = severity;
    document.querySelectorAll(".filter-tab").forEach(btn => btn.classList.remove("active"));
    event.target.classList.add("active");

    if (severity === "all") {
        renderFindingsList(currentResultsCache);
    } else {
        const filtered = currentResultsCache.filter(r => r.severity === severity);
        renderFindingsList(filtered);
    }
}

function renderFindingsList(results) {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sorted = [...results].sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));

    if (sorted.length === 0) {
        findingsList.innerHTML = '<p style="text-align:center;color:#94a3b8;padding:30px;">لا توجد نتائج مطابقة لهذا التصنيف</p>';
    } else {
        findingsList.innerHTML = sorted.map(r => `
            <div class="finding-item ${r.severity}">
                <h4>${escapeHtml(r.title || "Untitled Finding")}</h4>
                <p style="font-size:0.9rem;color:#cbd5e1;margin:8px 0;">${escapeHtml(r.description || "")}</p>
                <div class="tool-info">
                    <span class="sev-badge ${r.severity}">${SEVERITY_LABELS[r.severity] || r.severity}</span>
                    <span>🔧 الأداة: ${escapeHtml(r.tool_name || "N/A")}</span>
                    <span>📁 المرحلة: ${escapeHtml(r.phase || "N/A")}</span>
                    ${r.cve_id ? `<span>🆔 CVE: ${escapeHtml(r.cve_id)}</span>` : ""}
                    ${r.cvss_score ? `<span>📊 CVSS: ${r.cvss_score}</span>` : ""}
                </div>
                ${r.remediation ? `<div style="margin-top:10px;font-size:0.85rem;color:#34d399;"><strong>الإصلاح:</strong> ${escapeHtml(r.remediation)}</div>` : ""}
            </div>
        `).join("");
    }
}

function downloadReport(type) {
    if (!currentScanId) return;
    const url = `${API_URL}/api/scan/${currentScanId}/report/${type}`;
    if (type === "html") {
        window.open(url, "_blank");
    } else {
        window.location.href = url;
    }
}

function showError(msg) {
    hideAll();
    errorContainer.classList.remove("hidden");
    errorMessage.textContent = msg;
}

function showProgress() {
    progressContainer.classList.remove("hidden");
    progressFill.style.width = "5%";
    progressStatus.textContent = "جاري تهيئة الحاويات السحابية...";
    progressDetail.textContent = "إنشاء جلسة فحص آمنة";
    if (terminalLogs) terminalLogs.innerHTML = '<div class="terminal-line">[+] Allocating isolated security scanning node...</div>';
}

function resetButton() {
    scanButton.disabled = false;
    scanButton.querySelector(".btn-text").textContent = "إطلاق المحرك وبدء الفحص السيبراني الشامل";
}

function hideAll() {
    progressContainer.classList.add("hidden");
    resultsContainer.classList.add("hidden");
    errorContainer.classList.add("hidden");
}

function resetScan() {
    if (pollInterval) clearInterval(pollInterval);
    currentScanId = null;
    currentResultsCache = [];
    hideAll();
    form.reset();
    resetButton();
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str || "";
    return div.innerHTML;
}

// Service worker registration (PWA)
if ("serviceWorker" in navigator) {
    window.addEventListener("load", () => {
        navigator.serviceWorker.register("sw.js").catch(() => {});
    });
}