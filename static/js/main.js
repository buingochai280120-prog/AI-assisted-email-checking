/* main.js — logic cho trang Dashboard (form quét email + hiển thị kết quả AI) */

(function () {
  const form = document.getElementById("scan-form");
  if (!form) return;

  const scanBtn = document.getElementById("scan-btn");
  const loadingLine = document.getElementById("loading-line");
  const resultBox = document.getElementById("result-box");
  const scoreDial = document.getElementById("score-dial");
  const scoreNum = document.getElementById("score-num");
  const riskPill = document.getElementById("risk-pill");
  const riskText = document.getElementById("risk-text");
  const reasonsList = document.getElementById("reasons-list");
  const mlProbaText = document.getElementById("ml-proba-text");
  const historyList = document.querySelector(".history-list");

  const fileInput = document.getElementById("file-upload");
  const dropzone = document.getElementById("upload-dropzone");
  const uploadFilenameEl = document.getElementById("upload-filename");
  const senderInput = document.getElementById("sender");
  const subjectInput = document.getElementById("subject");
  const contentInput = document.getElementById("content");
  const replyToInput = document.getElementById("reply_to");
  const authResultsInput = document.getElementById("auth_results");
  const authBadge = document.getElementById("auth-badge");

  function showAuthBadge(authResultsRaw) {
    if (!authResultsRaw) {
      authBadge.style.display = "none";
      return;
    }
    const text = authResultsRaw.toLowerCase();
    const hasFail = /(spf|dkim|dmarc)=fail/.test(text);
    const hasPass = /(spf|dkim|dmarc)=pass/.test(text);

    authBadge.style.display = "inline-flex";
    if (hasFail) {
      authBadge.className = "auth-badge fail";
      authBadge.textContent = "⚠ File .eml này KHÔNG vượt qua xác thực SPF/DKIM/DMARC";
    } else if (hasPass) {
      authBadge.className = "auth-badge pass";
      authBadge.textContent = "✓ File .eml này đã được xác thực SPF/DKIM/DMARC hợp lệ";
    } else {
      authBadge.className = "auth-badge none";
      authBadge.textContent = "File .eml có header xác thực nhưng không đọc được kết quả rõ ràng";
    }
  }

  const ALLOWED_EXT = ["txt", "eml"];

  function getExtension(name) {
    return (name.split(".").pop() || "").toLowerCase();
  }

  async function uploadEmailFile(file) {
    if (!file) return;

    const ext = getExtension(file.name);
    if (!ALLOWED_EXT.includes(ext)) {
      alert("Chỉ hỗ trợ file định dạng .txt hoặc .eml.");
      return;
    }

    uploadFilenameEl.textContent = "Đang đọc " + file.name + "...";

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch("/api/parse-file", { method: "POST", body: formData });
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Không thể đọc file này.");
      }

      if (data.sender) senderInput.value = data.sender;
      if (data.subject) subjectInput.value = data.subject;
      contentInput.value = data.content;
      replyToInput.value = data.reply_to || "";
      authResultsInput.value = data.auth_results || "";
      showAuthBadge(data.auth_results || "");

      uploadFilenameEl.textContent = "Đã nạp: " + file.name;
      contentInput.focus();
    } catch (err) {
      uploadFilenameEl.textContent = "";
      alert(err.message || "Có lỗi xảy ra khi đọc file.");
    }
  }

  if (fileInput && dropzone) {
    fileInput.addEventListener("change", () => {
      uploadEmailFile(fileInput.files[0]);
    });

    ["dragenter", "dragover"].forEach((evt) => {
      dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        dropzone.classList.add("drag-over");
      });
    });
    ["dragleave", "drop"].forEach((evt) => {
      dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        dropzone.classList.remove("drag-over");
      });
    });
    dropzone.addEventListener("drop", (e) => {
      const file = e.dataTransfer.files && e.dataTransfer.files[0];
      if (file) uploadEmailFile(file);
    });
  }

  const RISK_META = {
    "An toàn": { cls: "safe", color: "var(--safe)", dim: "var(--safe-dim)" },
    "Nghi ngờ": { cls: "warn", color: "var(--warning)", dim: "var(--warning-dim)" },
    "Nguy hiểm": { cls: "danger", color: "var(--danger)", dim: "var(--danger-dim)" },
  };

  function setLoading(isLoading) {
    scanBtn.disabled = isLoading;
    loadingLine.style.display = isLoading ? "flex" : "none";
    scanBtn.textContent = isLoading ? "Đang phân tích..." : "Phân tích ngay";
  }

  function renderResult(result) {
    const meta = RISK_META[result.risk_level] || RISK_META["Nghi ngờ"];

    scoreNum.textContent = result.score;
    scoreDial.style.background =
      `conic-gradient(${meta.color} ${result.score * 3.6}deg, ${meta.dim} 0deg)`;

    riskPill.className = "risk-pill " + meta.cls;
    riskText.textContent = result.risk_level;

    mlProbaText.textContent =
      `Xác suất theo mô hình học máy (Naive Bayes): ${(result.ml_probability * 100).toFixed(1)}%`;

    reasonsList.innerHTML = "";
    result.reasons.forEach((reason) => {
      const li = document.createElement("li");
      li.className = "tag-" + meta.cls;
      li.textContent = reason;
      reasonsList.appendChild(li);
    });

    resultBox.classList.add("visible");
    resultBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function prependToHistory(payload, result) {
    if (!historyList) return;

    const emptyState = document.querySelector(".empty-state");
    if (emptyState) emptyState.remove();

    const meta = RISK_META[result.risk_level] || RISK_META["Nghi ngờ"];
    const item = document.createElement("div");
    item.className = "history-item";

    const now = new Date();
    const when = now.toISOString().slice(0, 16).replace("T", " ");

    item.innerHTML = `
      <div class="risk-pill ${meta.cls}"><span class="dot"></span>${result.risk_level}</div>
      <div>
        <div class="subj">${escapeHtml(payload.subject) || "(Không có tiêu đề)"}</div>
        <div class="meta">${escapeHtml(payload.sender) || "Không rõ người gửi"}</div>
      </div>
      <div class="score-mini">${result.score}</div>
      <div class="when">${when}</div>
    `;
    historyList.prepend(item);

    // Giới hạn danh sách "gần đây" hiển thị tối đa 8 mục trên dashboard
    const items = historyList.querySelectorAll(".history-item");
    if (items.length > 8) {
      items[items.length - 1].remove();
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  form.addEventListener("submit", async function (e) {
    e.preventDefault();

    const payload = {
      sender: document.getElementById("sender").value.trim(),
      subject: document.getElementById("subject").value.trim(),
      content: document.getElementById("content").value.trim(),
      reply_to: replyToInput.value.trim(),
      auth_results: authResultsInput.value.trim(),
    };

    if (!payload.content) {
      alert("Vui lòng nhập nội dung email cần kiểm tra.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || "Có lỗi xảy ra, vui lòng thử lại.");
      }

      const result = await res.json();
      renderResult(result);
      prependToHistory(payload, result);
    } catch (err) {
      alert(err.message || "Không thể kết nối tới máy chủ.");
    } finally {
      setLoading(false);
    }
  });
})();
