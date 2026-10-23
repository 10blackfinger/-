
const API_URL = "https://10blackfingers-api.vercel.app";

const form = document.getElementById("scan-form");
const urlInput = document.getElementById("target-url");
const consentCheck = document.getElementById("consent-check");
const scanButton = document.getElementById("scan-button");
const progressContainer = document.getElementById("progress-container");
const progressStatus = document.getElementById("progress-status");
const progressDetail = document.getElementById("progress-detail");
const progressFill = document.getElementById("progress-fill");
const progressTimer = document.getElementById("progress-timer");
const progressPhaseBadge = document.getElementById("progress-phase-badge");
const progressFindings = document.getElementById("progress-findings");
const resultsContainer = document.getElementById("results-container");
const resultsMeta = document.getElementById("results-meta");
const resultsDuration = document.getElementById("results-duration");
const statsGrid = document.getElementById("stats-grid");
const findingsList = document.getElementById("findings-list");
const errorContainer = document.getElementById("error-container");
const errorMessage = document.getElementById("error-message");
const overallBanner = document.getElementById("overall-banner");
const filterButtons = document.querySelectorAll(".filter-btn");
const modalOverlay = document.getElementById("modal-overlay");
const modalBody = document.getElementById("modal-body");
const modalClose = document.getElementById("modal-close");

const POLL_INTERVAL_MS = 3000;
const MAX_CONSECUTIVE_ERRORS = 20;
const RESULTS_FETCH_LIMIT = 500;
const RESULTS_MAX_TOTAL = 10000;

let currentScanId = null;
let pollInterval = null;
let currentScanData = null;
let currentResults = [];
let activeFilter = "all";
let lastPhase = "";
let consecutiveErrors = 0;

const SEVERITY_LABELS = {
    critical: "حرجة",
    high: "عالية",
    medium: "متوسطة",
    low: "منخفضة",
    info: "معلومات"
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const PHASE_LABELS = {
    starting: "جاري التحضير",
    recon: "الاستطلاع (Reconnaissance)",
    known_vulns: "الفحص النشط (Active Scanning)",
    zero_day: "تحليل الثغرات (Zero-Day)",
    exploitation: "الاستغلال وسحب البيانات",
    reporting: "توليد التقارير",
    completed: "انتهى الفحص",
    failed: "فشل الفحص",
    pending: "في الطابور",
    queued: "في الطابور"
};

const PHASE_DETAILS = {
    starting: "التحقق من الموقع وجمع الأدلة الأولية...",
    recon: "Nmap, Subfinder, WhatWeb, WHOIS, Katana, DNS...",
    known_vulns: "Nuclei, ZAP, SQLMap, Nikto, Dalfox, FFuf...",
    zero_day: "Headers, Cookies, CORS, Sensitive Files...",
    exploitation: "DB Dumps, PII Extraction, Secrets...",
    reporting: "TXT, HTML, PDF, Excel...",
    completed: "التقرير جاهز للتحميل"
};

const PHASE_PROGRESS_MAP = {
    starting: 3,
    recon: 15,
    known_vulns: 40,
    zero_day: 60,
    exploitation: 78,
    reporting: 92,
    completed: 100,
    failed: 100
};

function getSessionId() {
    let sid = localStorage.getItem("10bf_session");
    if (!sid) {
        sid = "sess_" + Math.random().toString(36).substring(2, 15) + Date.now().toString(36);
        localStorage.setItem("10bf_session", sid);
    }
    return sid;
}

function formatDuration(seconds) {
    if (seconds === null || seconds === undefined || isNaN(seconds)) {
        return "0 ثانية";
    }
    const s = Math.max(0, Math.floor(seconds));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    if (h > 0) return `${h} ساعة و ${m} دقيقة و ${sec} ثانية`;
    if (m > 0) return `${m} دقيقة و ${sec} ثانية`;
    return `${sec} ثانية`;
}

function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#x27;");
}

function resetState() {
    if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
    }
    lastPhase = "";
    currentScanData = null;
    currentResults = [];
    activeFilter = "all";
    consecutiveErrors = 0;
}

form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!consentCheck.checked) {
        alert("يجب الموافقة على التصريح قبل الفحص");
        return;
    }
    const targetUrl = urlInput.value.trim();
    if (!targetUrl) {
        alert("من فضلك اكتب رابط الموقع");
        return;
    }

    resetState();
    currentScanId = null;
    hideAll();
    showProgress();
    scanButton.disabled = true;
    scanButton.querySelector(".btn-text").textContent = "جاري الفحص...";
    setPhaseUI("starting");

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
        startPolling();
    } catch (err) {
        showError(err.message || "تعذر الاتصال بالسيرفر");
        resetButton();
    }
});

function startPolling() {
    if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
    }
    consecutiveErrors = 0;

    pollInterval = setInterval(async () => {
        const myScanId = currentScanId;
        if (!myScanId) {
            clearInterval(pollInterval);
            pollInterval = null;
            return;
        }

        try {
            const res = await fetch(`${API_URL}/api/scan/${myScanId}/status`);

            if (currentScanId !== myScanId) return;

            if (!res.ok) {
                consecutiveErrors++;
                if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
                    clearInterval(pollInterval);
                    pollInterval = null;
                    showError("تعذر الحصول على حالة الفحص بعد عدة محاولات");
                    resetButton();
                }
                return;
            }

            consecutiveErrors = 0;

            const data = await res.json();

            if (currentScanId !== myScanId) return;

            const scan = data.scan || {};

            updateProgressFromServer(scan);

            if (scan.status === "completed") {
                clearInterval(pollInterval);
                pollInterval = null;
                const ok = await loadAndShowResults(scan);
                if (ok) resetButton();
            } else if (scan.status === "failed") {
                clearInterval(pollInterval);
                pollInterval = null;
                showError(scan.error_message || "فشل الفحص");
                resetButton();
            }
        } catch (e) {
            if (currentScanId !== myScanId) return;
            consecutiveErrors++;
            if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
                clearInterval(pollInterval);
                pollInterval = null;
                showError("انقطع الاتصال بالسيرفر");
                resetButton();
            }
        }
    }, POLL_INTERVAL_MS);
}

async function loadAndShowResults(scan) {
    const scanId = currentScanId;
    if (!scanId) return false;

    progressStatus.textContent = "جاري تحميل النتائج...";
    progressDetail.textContent = "يتم جلب التقارير والأدلة...";

    currentScanData = scan;
    currentResults = [];

    const sessionId = encodeURIComponent(getSessionId());
    const collected = [];

    try {
        let offset = 0;
        let hasMore = true;

        while (hasMore) {
            let res, data;
            try {
                res = await fetch(
                    `${API_URL}/api/scan/${scanId}/results?offset=${offset}&limit=${RESULTS_FETCH_LIMIT}&session_id=${sessionId}`
                );
                if (!res.ok) break;
                data = await res.json();
            } catch (batchErr) {
                break;
            }

            if (currentScanId !== scanId) return false;

            const batch = data.results || [];
            for (const r of batch) {
                collected.push(r);
            }

            hasMore = data.has_more === true && batch.length > 0;
            offset += batch.length;

            if (offset >= RESULTS_MAX_TOTAL) break;
        }
    } catch (e) {
        if (currentScanId !== scanId) return false;
    }

    if (currentScanId !== scanId) return false;

    currentResults = collected;
    showResults(scan, currentResults);
    return true;
}

function updateProgressFromServer(scan) {
    const phase = scan.current_phase || "starting";
    const progress = typeof scan.progress_percent === "number" ? scan.progress_percent : PHASE_PROGRESS_MAP[phase] || 5;
    const elapsed = typeof scan.elapsed_seconds === "number" ? scan.elapsed_seconds : 0;

    progressFill.style.width = Math.min(99, progress) + "%";

    if (phase !== lastPhase) {
        setPhaseUI(phase);
        lastPhase = phase;
    }

    if (progressTimer) {
        progressTimer.textContent = "⏱ " + formatDuration(elapsed);
    }

    const totalFindings = (scan.total_findings || 0) ||
        ((scan.critical_count || 0) + (scan.high_count || 0) + (scan.medium_count || 0) + (scan.low_count || 0));
    if (progressFindings) {
        progressFindings.textContent = "🎯 " + totalFindings + " نتيجة";
    }
}

function setPhaseUI(phase) {
    const label = PHASE_LABELS[phase] || "جاري الفحص";
    const detail = PHASE_DETAILS[phase] || "قد يستغرق من 5 إلى 15 دقيقة";

    progressStatus.textContent = label;
    progressDetail.textContent = detail;

    if (progressPhaseBadge) {
        progressPhaseBadge.textContent = label;
        progressPhaseBadge.className = "phase-badge phase-" + phase;
    }
}

function showResults(scan, results) {
    hideAll();
    resultsContainer.classList.remove("hidden");
    progressFill.style.width = "100%";

    resultsMeta.textContent = scan.target_url || "";
    if (resultsDuration) {
        resultsDuration.textContent = "⏱ المدة: " + formatDuration(scan.elapsed_seconds || 0);
    }

    const total = scan.total_findings || 0;
    const critical = scan.critical_count || 0;
    const high = scan.high_count || 0;
    const medium = scan.medium_count || 0;
    const low = scan.low_count || 0;

    statsGrid.innerHTML = `
        <div class="stat-card total"><div class="num">${total}</div><div class="label">إجمالي</div></div>
        <div class="stat-card critical"><div class="num">${critical}</div><div class="label">حرجة</div></div>
        <div class="stat-card high"><div class="num">${high}</div><div class="label">عالية</div></div>
        <div class="stat-card medium"><div class="num">${medium}</div><div class="label">متوسطة</div></div>
        <div class="stat-card low"><div class="num">${low}</div><div class="label">منخفضة</div></div>
    `;

    if (overallBanner) {
        let cls, msg;
        if (critical > 0) {
            cls = "danger";
            msg = "⚠️ خطر — يوجد " + critical + " ثغرة حرجة تحتاج إصلاح فوري";
        } else if (high > 0) {
            cls = "warning";
            msg = "⚠️ يحتاج انتباه — يوجد " + high + " ثغرة عالية الخطورة";
        } else if (medium > 0) {
            cls = "medium";
            msg = "ℹ️ متوسط — يوجد " + medium + " ثغرة متوسطة";
        } else if (total > 0) {
            cls = "safe";
            msg = "✅ آمن نسبيًا — لا يوجد ثغرات حرجة";
        } else {
            cls = "safe";
            msg = "✅ آمن — لم يتم العثور على ثغرات";
        }
        overallBanner.className = "overall-banner " + cls;
        overallBanner.textContent = msg;
        overallBanner.classList.remove("hidden");
    }

    activeFilter = "all";
    updateFilterButtons();
    renderFindings();
}

function updateFilterButtons() {
    filterButtons.forEach(btn => {
        const f = btn.getAttribute("data-filter");
        if (f === activeFilter) {
            btn.classList.add("active");
        } else {
            btn.classList.remove("active");
        }
    });
}

filterButtons.forEach(btn => {
    btn.addEventListener("click", () => {
        activeFilter = btn.getAttribute("data-filter") || "all";
        updateFilterButtons();
        renderFindings();
    });
});

function renderFindings() {
    let filtered = currentResults;
    if (activeFilter !== "all") {
        filtered = currentResults.filter(r => r.severity === activeFilter);
    }

    const sorted = [...filtered].sort((a, b) => {
        const oa = SEVERITY_ORDER[a.severity] !== undefined ? SEVERITY_ORDER[a.severity] : 5;
        const ob = SEVERITY_ORDER[b.severity] !== undefined ? SEVERITY_ORDER[b.severity] : 5;
        return oa - ob;
    });

    if (sorted.length === 0) {
        findingsList.innerHTML = '<div class="empty-state">لا توجد نتائج مطابقة للفلتر المحدد</div>';
        return;
    }

    findingsList.innerHTML = sorted.map((r) => {
        const sev = r.severity || "info";
        const label = SEVERITY_LABELS[sev] || sev;
        const realIdx = currentResults.indexOf(r);
        const title = escapeHtml(r.title || "Untitled");
        const tool = escapeHtml(r.tool_name || "N/A");
        const phase = escapeHtml(r.phase || "N/A");
        const cve = r.cve_id ? `<span class="chip">CVE: ${escapeHtml(r.cve_id)}</span>` : "";
        const cvss = r.cvss_score ? `<span class="chip">CVSS: ${escapeHtml(r.cvss_score)}</span>` : "";
        const hasEvidence = r.evidence && (typeof r.evidence === "object" ? Object.keys(r.evidence).length > 0 : String(r.evidence).length > 0);

        return `
            <div class="finding-item ${sev}" data-index="${realIdx}">
                <div class="finding-head">
                    <h4>${title}</h4>
                    <span class="sev-badge ${sev}">${escapeHtml(label)}</span>
                </div>
                <div class="tool-info">
                    <span class="chip">🔧 ${tool}</span>
                    <span class="chip">📁 ${phase}</span>
                    ${cve}${cvss}
                    ${hasEvidence ? '<span class="chip evidence-chip">🔍 دليل متاح</span>' : ''}
                </div>
                <button class="details-btn" onclick="openFindingDetails(${realIdx})">
                    عرض التفاصيل والأدلة ←
                </button>
            </div>
        `;
    }).join("");
}

window.openFindingDetails = function (idx) {
    const r = currentResults[idx];
    if (!r) return;

    const sev = r.severity || "info";
    const label = SEVERITY_LABELS[sev] || sev;

    let evidenceHtml = "";
    const ev = r.evidence;
    if (ev && typeof ev === "object" && Object.keys(ev).length > 0) {
        evidenceHtml += '<div class="modal-section"><h4>🔍 الأدلة والبيانات المستخرجة</h4>';
        evidenceHtml += renderEvidenceModal(ev);
        evidenceHtml += '</div>';
    } else if (ev && typeof ev === "string" && ev.trim()) {
        evidenceHtml += '<div class="modal-section"><h4>🔍 الأدلة</h4>';
        evidenceHtml += `<pre class="modal-pre">${escapeHtml(ev)}</pre>`;
        evidenceHtml += '</div>';
    }

    const descHtml = r.description
        ? `<div class="modal-section"><h4>📝 الوصف</h4><p class="modal-desc">${escapeHtml(r.description)}</p></div>`
        : "";

    const remHtml = r.remediation
        ? `<div class="modal-section remediation-section"><h4>🛠️ كيفية الإصلاح</h4><pre class="modal-pre">${escapeHtml(r.remediation)}</pre></div>`
        : "";

    const metaHtml = `
        <div class="modal-meta">
            <span class="chip">🔧 ${escapeHtml(r.tool_name || "N/A")}</span>
            <span class="chip">📁 ${escapeHtml(r.phase || "N/A")}</span>
            ${r.cve_id ? `<span class="chip">CVE: ${escapeHtml(r.cve_id)}</span>` : ""}
            ${r.cvss_score ? `<span class="chip">CVSS: ${escapeHtml(r.cvss_score)}</span>` : ""}
        </div>
    `;

    modalBody.innerHTML = `
        <div class="modal-header">
            <h3>${escapeHtml(r.title || "Untitled")}</h3>
            <span class="sev-badge ${sev}">${escapeHtml(label)}</span>
        </div>
        ${metaHtml}
        ${descHtml}
        ${evidenceHtml}
        ${remHtml}
    `;

    modalOverlay.classList.remove("hidden");
    document.body.style.overflow = "hidden";
};

function renderEvidenceModal(ev) {
    let html = "";

    function valueToList(v) {
        if (Array.isArray(v)) return v;
        return [v];
    }

    const skipKeys = new Set();
    ["extracted_pii", "aggregated"].forEach(key => {
        if (ev[key] && typeof ev[key] === "object") {
            skipKeys.add(key);
            html += '<div class="pii-block">';
            html += `<h5 class="pii-title">🔐 ${key === "extracted_pii" ? "بيانات PII مستخرجة" : "بيانات PII مجمّعة"}</h5>`;
            html += '<table class="data-table"><thead><tr><th>النوع</th><th>القيمة</th></tr></thead><tbody>';
            Object.keys(ev[key]).forEach(k => {
                if (k === "source_url") return;
                valueToList(ev[key][k]).slice(0, 200).forEach(v => {
                    html += `<tr><td><strong>${escapeHtml(k)}</strong></td><td><code>${escapeHtml(String(v))}</code></td></tr>`;
                });
            });
            html += '</tbody></table></div>';
        }
    });

    if (ev.pii_data && Array.isArray(ev.pii_data)) {
        skipKeys.add("pii_data");
        ev.pii_data.slice(0, 10).forEach((item, i) => {
            if (typeof item !== "object") return;
            html += '<div class="pii-block">';
            html += `<h5 class="pii-title">🔐 بيانات PII من ${escapeHtml(item.source_url || ("مصدر " + (i + 1)))}</h5>`;
            html += '<table class="data-table"><thead><tr><th>النوع</th><th>القيمة</th></tr></thead><tbody>';
            Object.keys(item).forEach(k => {
                if (k === "source_url") return;
                valueToList(item[k]).slice(0, 100).forEach(v => {
                    html += `<tr><td><strong>${escapeHtml(k)}</strong></td><td><code>${escapeHtml(String(v))}</code></td></tr>`;
                });
            });
            html += '</tbody></table></div>';
        });
    }

    if (ev.dumped_files_preview && typeof ev.dumped_files_preview === "object") {
        skipKeys.add("dumped_files_preview");
        html += '<div class="db-dump-block"><h5 class="db-title">🗄️ ملفات قاعدة البيانات المسحوبة</h5>';
        Object.keys(ev.dumped_files_preview).slice(0, 10).forEach(fn => {
            html += `<div class="db-file"><div class="db-file-name">📄 ${escapeHtml(fn)}</div>`;
            html += `<pre class="modal-pre dark">${escapeHtml(String(ev.dumped_files_preview[fn]).substring(0, 5000))}</pre></div>`;
        });
        html += '</div>';
    }

    if (ev.extracted_files && Array.isArray(ev.extracted_files)) {
        skipKeys.add("extracted_files");
        html += '<div class="files-block"><h5 class="files-title">📁 الملفات الحساسة المسحوبة</h5>';
        ev.extracted_files.slice(0, 10).forEach(f => {
            if (typeof f !== "object") return;
            html += '<div class="file-item">';
            html += `<div class="file-item-name">${escapeHtml(f.file || "")} — <code>${escapeHtml(f.url || "")}</code></div>`;
            if (f.content) {
                html += `<pre class="modal-pre dark">${escapeHtml(String(f.content).substring(0, 3000))}</pre>`;
            }
            html += '</div>';
        });
        html += '</div>';
    }

    Object.keys(ev).forEach(k => {
        if (skipKeys.has(k)) return;
        const v = ev[k];
        if (v === null || v === undefined || v === "" || (Array.isArray(v) && v.length === 0) || (typeof v === "object" && !Array.isArray(v) && Object.keys(v).length === 0)) {
            return;
        }
        let text;
        if (typeof v === "object") {
            try {
                text = JSON.stringify(v, null, 2);
            } catch (e) {
                text = String(v);
            }
        } else {
            text = String(v);
        }
        if (text.length > 5000) {
            text = text.substring(0, 5000) + "... (مقتطع)";
        }
        html += `<div class="evidence-field"><div class="evidence-key">${escapeHtml(k)}</div>`;
        html += `<pre class="modal-pre dark">${escapeHtml(text)}</pre></div>`;
    });

    return html;
}

modalClose.addEventListener("click", closeModal);
modalOverlay.addEventListener("click", (e) => {
    if (e.target === modalOverlay) closeModal();
});
document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
});

function closeModal() {
    modalOverlay.classList.add("hidden");
    document.body.style.overflow = "";
}

function downloadReport(type) {
    if (!currentScanId) {
        alert("لا يوجد فحص حالي");
        return;
    }
    const sessionId = encodeURIComponent(getSessionId());
    const url = `${API_URL}/api/scan/${currentScanId}/report/${type}?session_id=${sessionId}`;
    if (type === "html") {
        window.open(url, "_blank");
    } else {
        const a = document.createElement("a");
        a.href = url;
        a.target = "_blank";
        a.rel = "noopener";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    }
}
window.downloadReport = downloadReport;

function showError(msg) {
    hideAll();
    errorContainer.classList.remove("hidden");
    errorMessage.textContent = msg || "حدث خطأ غير معروف";
}

function showProgress() {
    progressContainer.classList.remove("hidden");
    progressFill.style.width = "3%";
    progressStatus.textContent = "جاري التحضير...";
    progressDetail.textContent = "بدء الفحص الأمني";
    if (progressTimer) progressTimer.textContent = "⏱ 0 ثانية";
    if (progressFindings) progressFindings.textContent = "🎯 0 نتيجة";
    if (progressPhaseBadge) {
        progressPhaseBadge.textContent = "في الطابور";
        progressPhaseBadge.className = "phase-badge phase-starting";
    }
}

function resetButton() {
    scanButton.disabled = false;
    scanButton.querySelector(".btn-text").textContent = "ابدأ الفحص";
}

function hideAll() {
    progressContainer.classList.add("hidden");
    resultsContainer.classList.add("hidden");
    errorContainer.classList.add("hidden");
    if (overallBanner) overallBanner.classList.add("hidden");
}

function resetScan() {
    resetState();
    currentScanId = null;
    hideAll();
    closeModal();
    form.reset();
    resetButton();
}
window.resetScan = resetScan;

if ("serviceWorker" in navigator) {
    window.addEventListener("load", () => {
        navigator.serviceWorker.register("sw.js").catch(() => {});
    });
}