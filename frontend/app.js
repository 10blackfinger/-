const API_URL = "https://10blackfingers-api.vercel.app";

const form = document.getElementById("scan-form");
const urlInput = document.getElementById("target-url");
const consentCheck = document.getElementById("consent-check");
const scanButton = document.getElementById("scan-button");
const progressContainer = document.getElementById("progress-container");
const progressStatus = document.getElementById("progress-status");
const progressDetail = document.getElementById("progress-detail");
const progressFill = document.getElementById("progress-fill");
const resultsContainer = document.getElementById("results-container");
const resultsMeta = document.getElementById("results-meta");
const statsGrid = document.getElementById("stats-grid");
const findingsList = document.getElementById("findings-list");
const errorContainer = document.getElementById("error-container");
const errorMessage = document.getElementById("error-message");

let currentScanId = null;
let pollInterval = null;

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
        alert("يجب الموافقة على التصريح قبل الفحص");
        return;
    }
    const targetUrl = urlInput.value.trim();
    if (!targetUrl) return;

    hideAll();
    showProgress();
    scanButton.disabled = true;
    scanButton.querySelector(".btn-text").textContent = "جاري الفحص...";

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
            throw new Error(err.detail || "فشل بدء الفحص");
        }

        const data = await res.json();
        currentScanId = data.scan_id;
        startPolling(targetUrl);
    } catch (err) {
        showError(err.message);
        resetButton();
    }
});

function startPolling(targetUrl) {
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
                showResults(scan, data.results || []);
                resetButton();
            } else if (scan.status === "failed") {
                clearInterval(pollInterval);
                showError(scan.error_message || "فشل الفحص");
                resetButton();
            }
        } catch (e) {
            // ignore polling errors
        }
    }, 3000);
}

function updateProgressText(seconds) {
    const pct = Math.min(90, (seconds / 300) * 100);
    progressFill.style.width = pct + "%";

    if (seconds < 30) {
        progressStatus.textContent = "جاري الاستطلاع (Reconnaissance)...";
        progressDetail.textContent = "Nmap, Subfinder, WhatWeb, WAFW00F...";
    } else if (seconds < 120) {
        progressStatus.textContent = "جاري الفحص النشط (Active Scanning)...";
        progressDetail.textContent = "Nuclei, SQLMap, Nikto, Dalfox...";
    } else if (seconds < 240) {
        progressStatus.textContent = "جاري تحليل Zero-Day...";
        progressDetail.textContent = "Headers, Cookies, CORS, Info Disclosure...";
    } else {
        progressStatus.textContent = "جاري توليد التقارير...";
        progressDetail.textContent = "TXT, HTML, PDF";
    }
}

function showResults(scan, results) {
    hideAll();
    resultsContainer.classList.remove("hidden");

    resultsMeta.textContent = scan.target_url;
    progressFill.style.width = "100%";

    statsGrid.innerHTML = `
        <div class="stat-card total"><div class="num">${scan.total_findings || 0}</div><div class="label">Total</div></div>
        <div class="stat-card critical"><div class="num">${scan.critical_count || 0}</div><div class="label">Critical</div></div>
        <div class="stat-card high"><div class="num">${scan.high_count || 0}</div><div class="label">High</div></div>
        <div class="stat-card medium"><div class="num">${scan.medium_count || 0}</div><div class="label">Medium</div></div>
        <div class="stat-card low"><div class="num">${scan.low_count || 0}</div><div class="label">Low</div></div>
    `;

    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sorted = [...results].sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));

    if (sorted.length === 0) {
        findingsList.innerHTML = '<p style="text-align:center;color:#94a3b8;padding:30px;">لم يتم العثور على ثغرات</p>';
    } else {
        findingsList.innerHTML = sorted.map(r => `
            <div class="finding-item ${r.severity}">
                <h4>${escapeHtml(r.title || "Untitled")}</h4>
                <div class="tool-info">
                    <span class="sev-badge ${r.severity}">${SEVERITY_LABELS[r.severity] || r.severity}</span>
                    <span>🔧 ${escapeHtml(r.tool_name || "")}</span>
                    <span>📁 ${escapeHtml(r.phase || "")}</span>
                    ${r.cve_id ? `<span>🆔 ${escapeHtml(r.cve_id)}</span>` : ""}
                    ${r.cvss_score ? `<span>📊 CVSS ${r.cvss_score}</span>` : ""}
                </div>
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
    progressStatus.textContent = "جاري التحضير...";
    progressDetail.textContent = "بدء الفحص الأمني";
}

function resetButton() {
    scanButton.disabled = false;
    scanButton.querySelector(".btn-text").textContent = "ابدأ الفحص";
}

function hideAll() {
    progressContainer.classList.add("hidden");
    resultsContainer.classList.add("hidden");
    errorContainer.classList.add("hidden");
}

function resetScan() {
    if (pollInterval) clearInterval(pollInterval);
    currentScanId = null;
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