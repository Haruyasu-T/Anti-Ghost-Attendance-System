// SPDX-FileCopyrightText: 2026 田中晴康
// SPDX-License-Identifier: Apache-2.0

"use strict";
const tbody = document.querySelector("#history-rows"),
  errorBox = document.querySelector("#history-error"),
  labels = { present: "出席", late: "遅刻", absent: "欠席" };
function cell(value) {
  const td = document.createElement("td");
  td.textContent = value == null ? "" : String(value);
  return td;
}
function renderRow(row) {
  const tr = document.createElement("tr");
  tr.append(cell(row.course_name), cell(row.scheduled_start_at || row.date));
  const statusCell = document.createElement("td"),
    status = Object.hasOwn(labels, row.status) ? row.status : "empty",
    badge = document.createElement("span");
  badge.classList.add("status", "status-" + status);
  badge.textContent = labels[row.status] || "未登録";
  statusCell.append(badge);
  tr.append(statusCell, cell(row.scan_count == null ? "—" : row.scan_count));
  return tr;
}
(async function () {
  try {
    const response = await fetch("/me/attendances", {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) throw new Error();
    const data = await response.json(),
      rows = Array.isArray(data) ? data : data.rows || [];
    tbody.replaceChildren();
    if (rows.length) {
      tbody.append(...rows.map(renderRow));
    } else {
      const tr = document.createElement("tr"),
        td = cell("出席履歴はまだありません。");
      td.colSpan = 4;
      tr.append(td);
      tbody.append(tr);
    }
  } catch (e) {
    errorBox.textContent = "出席履歴を読み込めませんでした。";
    errorBox.hidden = false;
  }
})();
