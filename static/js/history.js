/* history.js — logic cho trang Lịch sử (modal chi tiết + xóa mục) */

(function () {
  const list = document.getElementById("history-list");
  const backdrop = document.getElementById("detail-backdrop");
  if (!list || !backdrop) return;

  const closeBtn = document.getElementById("detail-close");
  const deleteBtn = document.getElementById("detail-delete");

  const riskEl = document.getElementById("detail-risk");
  const riskTextEl = document.getElementById("detail-risk-text");
  const subjectEl = document.getElementById("detail-subject");
  const senderEl = document.getElementById("detail-sender");
  const whenEl = document.getElementById("detail-when");
  const reasonsEl = document.getElementById("detail-reasons");
  const contentEl = document.getElementById("detail-content");

  const RISK_CLASS = { "An toàn": "safe", "Nghi ngờ": "warn", "Nguy hiểm": "danger" };

  let activeId = null;

  function openModal(row) {
    activeId = row.dataset.id;

    const riskLevel = row.querySelector(".risk-pill span:last-child").textContent.trim();
    const cls = RISK_CLASS[riskLevel] || "warn";

    riskEl.className = "risk-pill " + cls;
    riskTextEl.textContent = riskLevel;

    subjectEl.textContent = row.dataset.subject || "(Không có tiêu đề)";
    senderEl.textContent = row.dataset.sender || "Không rõ người gửi";
    whenEl.textContent = "Kiểm tra lúc: " + row.dataset.checked;
    contentEl.textContent = row.dataset.content;

    reasonsEl.innerHTML = "";
    let reasons = [];
    try {
      reasons = JSON.parse(row.dataset.reasons);
    } catch (e) {
      reasons = [];
    }
    reasons.forEach((r) => {
      const li = document.createElement("li");
      li.className = "tag-" + cls;
      li.textContent = r;
      reasonsEl.appendChild(li);
    });

    backdrop.classList.add("visible");
  }

  function closeModal() {
    backdrop.classList.remove("visible");
    activeId = null;
  }

  list.addEventListener("click", (e) => {
    const row = e.target.closest(".history-item");
    if (row) openModal(row);
  });

  closeBtn.addEventListener("click", closeModal);
  backdrop.addEventListener("click", (e) => {
    if (e.target === backdrop) closeModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });

  deleteBtn.addEventListener("click", async () => {
    if (!activeId) return;
    if (!confirm("Xóa mục lịch sử này? Hành động không thể hoàn tác.")) return;

    try {
      const res = await fetch(`/api/history/${activeId}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Xóa thất bại.");

      const row = list.querySelector(`.history-item[data-id="${activeId}"]`);
      if (row) row.remove();
      closeModal();

      if (!list.querySelector(".history-item")) {
        location.reload();
      }
    } catch (err) {
      alert(err.message || "Có lỗi xảy ra khi xóa.");
    }
  });
})();
