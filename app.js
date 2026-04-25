const tabs = document.querySelectorAll(".tab");
const tabButtons = document.querySelectorAll("[data-tab-btn]");
const statusEl = document.getElementById("status");
const statusNoteEl = document.getElementById("statusNote");
const statsEl = document.getElementById("stats");
const metaEl = document.getElementById("meta");
const loadingWrapEl = document.getElementById("loadingWrap");
const urlInput = document.getElementById("urlInput");
const fileInput = document.getElementById("fileInput");
const urlScanBtn = document.getElementById("urlScanBtn");
const fileScanBtn = document.getElementById("fileScanBtn");

tabButtons.forEach((button) => {
    button.addEventListener("click", () => switchTab(button.dataset.tabBtn));
});

urlScanBtn.addEventListener("click", scanURL);
fileScanBtn.addEventListener("click", scanFile);

function switchTab(tabName) {
    tabs.forEach((tab) => tab.classList.remove("active"));
    tabButtons.forEach((button) => button.classList.remove("active"));
    document.getElementById(tabName).classList.add("active");
    document.querySelector(`[data-tab-btn="${tabName}"]`).classList.add("active");
    resetResult();
}

function showLoadingBar() {
    loadingWrapEl.classList.remove("hidden");
}

function hideLoadingBar() {
    loadingWrapEl.classList.add("hidden");
}

function resetResult() {
    statusEl.textContent = "San sang quet.";
    statusEl.className = "status-banner status-neutral";
    statusNoteEl.textContent = "Nhap URL hoac chon file de bat dau.";
    statsEl.innerHTML = "";
    statsEl.classList.add("hidden");
    metaEl.innerHTML = "";
    hideLoadingBar();
}

function setLoading(message) {
    statusEl.textContent = message;
    statusEl.className = "status-banner status-neutral";
    statusNoteEl.textContent = "He thong dang tra ket qua.";
    statsEl.innerHTML = "";
    statsEl.classList.add("hidden");
    metaEl.innerHTML = "";
    showLoadingBar();
}

function getErrorMessage(data, fallbackMessage) {
    const error = data?.error;

    if (typeof error === "string" && error.trim()) {
        return error;
    }

    if (error && typeof error === "object") {
        if (typeof error.message === "string" && error.message.trim()) {
            return error.message;
        }

        if (typeof error.code === "string" && error.code.trim()) {
            return `Loi: ${error.code}`;
        }
    }

    return fallbackMessage;
}

function renderStats(stats) {
    const cards = [
        { label: "Malicious", value: stats.malicious ?? 0 },
        { label: "Suspicious", value: stats.suspicious ?? 0 },
        { label: "Undetected", value: stats.undetected ?? 0 },
        { label: "Harmless", value: stats.harmless ?? 0 }
    ];

    statsEl.innerHTML = cards.map((item) => `
        <div class="stat-card">
            <span class="stat-label">${item.label}</span>
            <span class="stat-value">${item.value}</span>
        </div>
    `).join("");

    statsEl.classList.remove("hidden");
}

function renderMeta(data) {
    const lines = [];
    const attributes = data?.data?.attributes || {};

    if (attributes.date) {
        lines.push(`Thoi gian quet: ${new Date(attributes.date * 1000).toLocaleString("vi-VN")}`);
    }

    if (attributes.status) {
        lines.push(`Trang thai phan tich: ${attributes.status}`);
    }

    if (data?.meta?.file_info?.sha256) {
        lines.push(`SHA256: ${data.meta.file_info.sha256}`);
    }

    if (data?.analysisId) {
        lines.push(`Analysis ID: ${data.analysisId}`);
    }

    if (data?.pending) {
        lines.push("Trang thai: pending");
    }

    metaEl.innerHTML = lines.map((line) => `<div class="meta-item">${line}</div>`).join("");
}

function showError(data, fallbackMessage) {
    hideLoadingBar();
    statusEl.textContent = fallbackMessage;
    statusEl.className = "status-banner status-danger";
    statusNoteEl.textContent = getErrorMessage(data, "He thong khong the hoan tat yeu cau nay.");
    statsEl.innerHTML = "";
    statsEl.classList.add("hidden");
    metaEl.innerHTML = "";
}

function showPending(data) {
    showLoadingBar();
    statusEl.textContent = "Dang phan tich them.";
    statusEl.className = "status-banner status-warning";
    statusNoteEl.textContent = getErrorMessage(data, "Virus Checker can them thoi gian de hoan tat quet file nay.");
    statsEl.innerHTML = "";
    statsEl.classList.add("hidden");
    renderMeta(data);
}

function showResult(data) {
    hideLoadingBar();
    const stats = data?.data?.attributes?.stats;

    if (!stats) {
        showError(data, "Khong lay duoc ket qua quet.");
        return;
    }

    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;

    if (malicious > 0) {
        statusEl.textContent = "Phat hien nguy co.";
        statusEl.className = "status-banner status-danger";
        statusNoteEl.textContent = `Co ${malicious} engine danh dau file hoac URL nay la nguy hiem.`;
    } else if (suspicious > 0) {
        statusEl.textContent = "Can kiem tra them.";
        statusEl.className = "status-banner status-warning";
        statusNoteEl.textContent = `Co ${suspicious} engine danh dau dang nghi. Nen kiem tra ky hon truoc khi mo hoac tai xuong.`;
    } else {
        statusEl.textContent = "Tam thoi an toan.";
        statusEl.className = "status-banner status-safe";
        statusNoteEl.textContent = "Khong co engine nao danh dau malware trong lan quet nay. Ket qua nay khong dam bao an toan 100%.";
    }

    renderStats(stats);
    renderMeta(data);
}

async function scanURL() {
    const url = urlInput.value.trim();

    if (!url) {
        showError({ error: "Thieu URL" }, "Ban chua nhap URL.");
        return;
    }

    try {
        urlScanBtn.disabled = true;
        fileScanBtn.disabled = true;
        setLoading("Dang quet URL...");

        const response = await fetch("/scan-url", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (response.status === 202) {
            showPending(data);
            return;
        }

        if (!response.ok) {
            showError(data, "Quet URL that bai.");
            return;
        }

        showResult(data);
    } catch (error) {
        showError({ error: error.message }, "Loi ket noi toi server.");
    } finally {
        urlScanBtn.disabled = false;
        fileScanBtn.disabled = false;
    }
}

async function scanFile() {
    const file = fileInput.files[0];

    if (!file) {
        showError({ error: "Chua chon file" }, "Ban chua chon file.");
        return;
    }

    try {
        urlScanBtn.disabled = true;
        fileScanBtn.disabled = true;
        setLoading("Dang quet file...");

        const formData = new FormData();
        formData.append("file", file);

        const response = await fetch("/scan-file", {
            method: "POST",
            body: formData
        });

        const data = await response.json();

        if (response.status === 202) {
            showPending(data);
            return;
        }

        if (!response.ok) {
            showError(data, "Quet file that bai.");
            return;
        }

        showResult(data);
    } catch (error) {
        showError({ error: error.message }, "Loi ket noi toi server.");
    } finally {
        urlScanBtn.disabled = false;
        fileScanBtn.disabled = false;
    }
}
