const API_URL = "https://10blackfingers-api.vercel.app";

const form = document.getElementById("scan-form");
const urlInput = document.getElementById("target-url");
const targetTypeSelect = document.getElementById("target-type");
const conditionalInputs = document.getElementById("conditional-inputs");
const cryptoGroup = document.getElementById("crypto-group");
const bankGroup = document.getElementById("bank-group");
const cryptoWalletInput = document.getElementById("crypto-wallet");
const cryptoNetworkInput = document.getElementById("crypto-network");
const cryptoContractInput = document.getElementById("crypto-contract");
const bankAccountInput = document.getElementById("bank-account");
const consentCheck = document.getElementById("consent-check");
const scanButton = document.getElementById("scan-button");
const progressContainer = document.getElementById("progress-container");
const progressStatus = document.getElementById("progress-status");
const progressDetail = document.getElementById("progress-detail");
const progressFill = document.getElementById("progress-fill");
const resultsContainer = document.getElementById("results-container");
const resultsMeta = document.getElementById("results-meta");
const statsGrid = document.getElementById("stats-grid");
const transferSummaryBox = document.getElementById("transfer-summary-box");
const transferDetailsContent = document.getElementById("transfer-details-content");
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

// التحكم في إظهار الحقول الشرطية بناءً على نوع الهدف (عملات رقمية أو بنك)
targetTypeSelect.addEventListener("change", () => {
    const val = targetTypeSelect.value;
    conditionalInputs.classList.remove("hidden");
    cryptoGroup.classList.add("hidden");
    bankGroup.classList.add("hidden");

    if (val === "crypto") {
        cryptoGroup.classList.remove("hidden");
    } else if (val === "bank") {
        bankGroup.classList.remove("hidden");
    } else {
        conditionalInputs.classList.add("hidden");
    }
});

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
        alert("يجب الموافقة على التصريح قبل الفحص واستخراج الجائزة");
        return;
    }
    const targetUrl = urlInput.value.trim();
    if (!targetUrl) return;

    const targetType = targetTypeSelect.value;
    let extraData = {};
    
    if (targetType === "crypto") {
        extraData.crypto_wallet = cryptoWalletInput.value.trim();
        extraData.crypto_network = cryptoNetworkInput.value.trim();
        extraData.crypto_contract = cryptoContractInput.value.trim();
        if (!extraData.crypto_wallet) {
            alert("يرجى إدخال عنوان المحفظة الشخصية المستهدفة لتحويل الجائزة");
            return;
        }
    } else if (targetType === "bank") {
        extraData.bank_account = bankAccountInput.value.trim();
        if (!extraData.bank_account) {
            alert("يرجى إدخال رقم الحساب البنكي الشخصي المستهدف لتحويل الجائزة");
            return;
        }
    }

    hideAll();
    showProgress();
    scanButton.disabled = true;
    scanButton.querySelector(".btn-text").textContent = "جاري الفحص واستخراج الجائزة...";

    try {
        const res = await fetch(`${API_URL}/api/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url: targetUrl,
                consent: true,
                session_id: getSessionId(),
                target_type: targetType,
                ...extraData
            })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({ detail: res.statusText }));
            throw new Error(err.detail || "فشل بدء عملية الفحص وتحويل الجائزة");
        }

        const data = await res.json();
        currentScanId = data.scan_id;
        startPolling();
    } catch (err) {
        showError(err.message);
        resetButton();
    }
});
function startPolling() {
    let progressVal = 10;
    progressFill.style.width = progressVal + "%";
    progressStatus.textContent = "جاري الفحص المنهجي واستطلاع الأهداف...";
    progressDetail.textContent = "تنفيذ أدوات الأمان والتحقق من حسابات الأرصدة...";

    pollInterval = setInterval(async () => {
        try {
            const res = await fetch(`${API_URL}/api/scan/${currentScanId}`);
            if (!res.ok) throw new Error("تعذر جلب حالة الفحص");
            const data = await res.json();
            const scan = data.scan;
            const results = data.results || [];

            if (scan.status === "completed") {
                clearInterval(pollInterval);
                progressFill.style.width = "100%";
                setTimeout(() => {
                    hideAll();
                    showResults(scan, results);
                    resetButton();
                }, 500);
            } else if (scan.status === "failed") {
                clearInterval(pollInterval);
                hideAll();
                showError(scan.error_message || "فشلت عملية الفحص أو التحويل المالي");
                resetButton();
            } else {
                if (progressVal < 90) {
                    progressVal += 10;
                    progressFill.style.width = progressVal + "%";
                }
                if (scan.target_type === "crypto" || scan.target_type === "bank") {
                    progressStatus.textContent = "جاري فحص الأرصدة (>100$) وتفعيل استخراج الجائزة...";
                    progressDetail.textContent = `تم العثور على ثغرات، جاري تنفيذ التحويل المالي التلقائي... (${results.length} نتائج مسجلة)`;
                } else {
                    progressStatus.textContent = "جاري فحص الثغرات الأمنية عبر GitHub Actions...";
                    progressDetail.textContent = `عدد الثغرات المكتشفة حتى الآن: ${results.length}`;
                }
            }
        } catch (err) {
            console.error("Polling error:", err);
        }
    }, 4000);
}
function showResults(scan, results) {
    resultsContainer.classList.remove("hidden");

    let crit = scan.critical_count || 0;
    let high = scan.high_count || 0;
    let med = scan.medium_count || 0;
    let low = scan.low_count || 0;
    let total = scan.total_findings || results.length;

    resultsMeta.innerHTML = `
        <span>الهدف: <strong>${escapeHtml(scan.target_url)}</strong></span>
        <span>نوع الهدف: <strong>${escapeHtml(scan.target_type || "general")}</strong></span>
        <span>تاريخ الإكمال: <strong>${new Date(scan.completed_at || Date.now()).toLocaleString()}</strong></span>
    `;

    statsGrid.innerHTML = `
        <div class="stat-card critical">
            <div class="count">${crit}</div>
            <div class="label">حرجة (Critical)</div>
        </div>
        <div class="stat-card high">
            <div class="count">${high}</div>
            <div class="label">عالية (High)</div>
        </div>
        <div class="stat-card medium">
            <div class="count">${med}</div>
            <div class="label">متوسطة (Medium)</div>
        </div>
        <div class="stat-card low">
            <div class="count">${low}</div>
            <div class="label">منخفضة (Low)</div>
        </div>
    `;

    // عرض ملخص التحويل المالي إذا كان الهدف بنك أو عملات رقمية وتمت عملية الاستخراج
    if (scan.target_type === "crypto" || scan.target_type === "bank") {
        transferSummaryBox.classList.remove("hidden");
        let transferInfoHTML = "";
        if (scan.target_type === "crypto") {
            transferInfoHTML = `
                <p>🪙 <strong>نوع التحويل:</strong> محفظة عملات رقمية مشفرة</p>
                <p>📬 <strong>عنوان المحفظة المستقبلة:</strong> <code>${escapeHtml(scan.crypto_wallet || "N/A")}</code></p>
                <p>🌐 <strong>الشبكة المستخدمة:</strong> ${escapeHtml(scan.crypto_network || "N/A")}</p>
                <p>💎 <strong>العقد / العملة:</strong> ${escapeHtml(scan.crypto_contract || "N/A")}</p>
                <p style="color: #4ade80; margin-top: 8px;">✅ تم فحص الحسابات والأرصدة (>100$) وتحويل نسبة الجائزة تلقائياً بنجاح.</p>
            `;
        } else if (scan.target_type === "bank") {
            transferInfoHTML = `
                <p>🏦 <strong>نوع التحويل:</strong> حساب بنكي تجريبي معزول</p>
                <p>💳 <strong>رقم الحساب المستهدف:</strong> <code>${escapeHtml(scan.bank_account || "N/A")}</code></p>
                <p>💵 <strong>العملة المعتمدة:</strong> USD (دولار أمريكي)</p>
                <p style="color: #4ade80; margin-top: 8px;">✅ تم استهداف الحسابات ذات الأرصدة المرتفعة وتحويل الجائزة بنجاح.</p>
            `;
        }
        transferDetailsContent.innerHTML = transferInfoHTML;
    } else {
        transferSummaryBox.classList.add("hidden");
    }

    if (results.length === 0) {
        findingsList.innerHTML = `<div class="no-findings">لم يتم رصد ثغرات أمنية في هذا الهدف.</div>`;
        return;
    }

    findingsList.innerHTML = results.map((r, index) => {
        let sevClass = r.severity || "info";
        let sevName = SEVERITY_LABELS[sevClass] || sevClass;
        
        let evidenceHtml = "";
        if (r.evidence) {
            if (typeof r.evidence === "object") {
                let evItems = Object.entries(r.evidence).map(([k, v]) => `<div><strong>${escapeHtml(k)}:</strong> ${escapeHtml(JSON.stringify(v))}</div>`).join("");
                evidenceHtml = `<div class="evidence-box"><strong>بيانات الأدلة واستخراج الجائزة:</strong>${evItems}</div>`;
            } else {
                evidenceHtml = `<div class="evidence-box"><strong>الدليل:</strong> ${escapeHtml(r.evidence)}</div>`;
            }
        }

        return `
            <div class="finding-card ${sevClass}">
                <div class="finding-header">
                    <span class="finding-title">${index + 1}. ${escapeHtml(r.title || "ثغرة أمنية")}</span>
                    <span class="severity-badge ${sevClass}">${sevName}</span>
                </div>
                <div class="finding-meta">
                    <span>الأداة: <strong>${escapeHtml(r.tool_name || "N/A")}</strong></span>
                    <span>المرحلة: <strong>${escapeHtml(r.phase || "N/A")}</strong></span>
                    ${r.cvss_score ? `<span>CVSS: <strong>${r.cvss_score}</strong></span>` : ""}
                    ${r.cve_id ? `<span>CVE: <strong>${r.cve_id}</strong></span>` : ""}
                </div>
                ${r.description ? `<p class="finding-desc">${escapeHtml(r.description)}</p>` : ""}
                ${evidenceHtml}
                ${r.remediation ? `<div class="remediation-box"><strong>طريقة الإصلاح:</strong> ${escapeHtml(r.remediation)}</div>` : ""}
            </div>
        `;
    }).join("");
}
function downloadReport(format) {
    if (!currentScanId) {
        alert("لا يوجد فحص نشط لتحميل تقريره");
        return;
    }
    window.open(`${API_URL}/api/scan/${currentScanId}/report/${format}`, "_blank");
}

function resetScan() {
    if (pollInterval) clearInterval(pollInterval);
    currentScanId = null;
    hideAll();
    document.getElementById("scan-form-container").classList.remove("hidden");
    form.reset();
    conditionalInputs.classList.add("hidden");
    cryptoGroup.classList.add("hidden");
    bankGroup.classList.add("hidden");
    resetButton();
}

function hideAll() {
    document.getElementById("scan-form-container").classList.add("hidden");
    progressContainer.classList.add("hidden");
    resultsContainer.classList.add("hidden");
    errorContainer.classList.add("hidden");
}

function showProgress() {
    progressContainer.classList.remove("hidden");
    progressFill.style.width = "10%";
}

function showError(msg) {
    errorContainer.classList.remove("hidden");
    errorMessage.textContent = msg;
}

function resetButton() {
    scanButton.disabled = false;
    scanButton.querySelector(".btn-text").textContent = "ابدأ الفحص المنهجي واستخراج الجائزة تلقائياً";
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace('/&#039;');
}