// SPDX-FileCopyrightText: 2026 田中晴康
// SPDX-License-Identifier: Apache-2.0

"use strict";
const root = document.querySelector("[data-qr-screen]"),
  sessionId = root.dataset.sessionId,
  csrf = root.dataset.csrfToken,
  errorBox = document.querySelector("#qr-error"),
  qrHost = document.querySelector("#qrcode");
let rotateSeconds = 5,
  nextRotate = 0,
  refreshing = false;
function renderToken(token) {
  const url = new URL("/scan", location.origin);
  url.searchParams.set("s", sessionId);
  url.searchParams.set("t", token);
  qrHost.replaceChildren();
  new QRCode(qrHost, {
    text: url.toString(),
    width: 620,
    height: 620,
    correctLevel: QRCode.CorrectLevel.M,
  });
}
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    const response = await fetch("/attendance-sessions/" + sessionId + "/token", {
      credentials: "same-origin",
    });
    if (!response.ok) throw new Error();
    const data = await response.json();
    rotateSeconds = data.rotate_seconds || 5;
    nextRotate = Date.parse(data.next_rotate_at) || Date.now() + rotateSeconds * 1000;
    renderToken(data.token);
    errorBox.hidden = true;
  } catch (e) {
    errorBox.textContent = "QRを更新できません。接続とログイン状態を確認してください。";
    errorBox.hidden = false;
  } finally {
    refreshing = false;
  }
}
async function refreshCount() {
  try {
    const response = await fetch("/attendance-sessions/" + sessionId + "/attendances", {
      credentials: "same-origin",
    });
    if (!response.ok) return;
    const data = await response.json();
    const rows = data.rows || [];
    document.querySelector("#registered-count").textContent =
      rows.filter(function (row) {
        return row.status;
      }).length +
      " / " +
      rows.length;
  } catch (e) {
    /* 次回の更新で再試行する */
  }
}
function tick() {
  const remaining = Math.max(0, nextRotate - Date.now()),
    ratio = Math.min(1, remaining / (rotateSeconds * 1000));
  document.querySelector("#countdown-bar").style.transform = "scaleX(" + ratio + ")";
  document.querySelector("#countdown-label").textContent =
    "更新まで " + (remaining / 1000).toFixed(1) + " 秒";
  if (remaining <= 0) refresh();
}
function updateScanRound(count) {
  document.querySelector("#scan-round").textContent = count + "回目";
  document.querySelector("#rescan-button").textContent = count + 1 + "回目のQRを表示";
}
async function action(path, confirmText) {
  if (confirmText && !confirm(confirmText)) return;
  const button = document.querySelector(path === "rescan" ? "#rescan-button" : "#rotate-button");
  if (button.disabled) return;
  button.disabled = true;
  try {
    const response = await fetch("/attendance-sessions/" + sessionId + "/" + path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-CSRF-Token": csrf },
    });
    if (!response.ok) throw new Error();
    const data = await response.json();
    updateScanRound(data.required_scan_count);
    await refresh();
  } catch (e) {
    errorBox.textContent = "操作を完了できませんでした。";
    errorBox.hidden = false;
  } finally {
    button.disabled = false;
  }
}
document.querySelector("#rescan-button").addEventListener("click", function () {
  action("rescan");
});
document.querySelector("#rotate-button").addEventListener("click", function () {
  action("rotate-token", "現在表示中のQRをすべて無効にして作り直しますか？");
});
refresh();
refreshCount();
setInterval(tick, 100);
setInterval(refreshCount, 5000);

// ---- 授業開始時刻の変更 ---------------------------------------------------
// 上のコードは通常のスクリプトとして全ページで名前を共有するので，追加分は
// 即時関数に閉じ込める（トップレベルの const が被るとページ全体が止まる）．
(function () {
  const dialog = document.querySelector("#start-time-dialog");
  const form = document.querySelector("#start-time-form");
  const input = document.querySelector("#start-time-input");
  const windowBox = document.querySelector("#start-time-window");
  const reasonInput = document.querySelector("#start-time-reason");
  const dialogError = document.querySelector("#start-time-error");
  const submitButton = document.querySelector("#start-time-submit");
  const openButton = document.querySelector("#change-start-button");
  if (!dialog || !form || !input || !reasonInput || !openButton) return;

  // 受付時間帯の分数はサーバーから受け取る（JSに直書きしない）．
  const minutes = {
    before: Number(root.dataset.presentBeforeMinutes),
    after: Number(root.dataset.presentAfterMinutes),
    lateUntil: Number(root.dataset.lateUntilMinutes),
  };

  function toLocalInputValue(date) {
    const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
    return local.toISOString().slice(0, 16);
  }

  function formatTime(date) {
    return new Intl.DateTimeFormat("ja-JP", {
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).format(date);
  }

  function updateWindow() {
    const start = new Date(input.value);
    if (Number.isNaN(start.getTime())) {
      windowBox.textContent = "開始時刻を入力すると受付時間帯を表示します。";
      return;
    }
    const shifted = function (m) {
      return new Date(start.getTime() + m * 60000);
    };
    windowBox.textContent =
      "出席：" +
      formatTime(shifted(-minutes.before)) +
      "〜" +
      formatTime(shifted(minutes.after)) +
      "　" +
      "遅刻：" +
      formatTime(shifted(minutes.after)) +
      "〜" +
      formatTime(shifted(minutes.lateUntil));
  }

  function messageFor(status) {
    if (status === 400 || status === 422) {
      return "入力内容を確認してください。開始時刻は現在時刻から3時間以内、理由は必須（500文字以内）です。";
    }
    if (status === 409) return "このセッションは終了しています。";
    if (status === 401) return "ログインし直してください。";
    if (status === 403 || status === 404)
      return "このセッションの開始時刻を変更する権限がありません。";
    return "変更できませんでした。時間をおいて再度お試しください。";
  }

  openButton.addEventListener("click", function () {
    const current = new Date(root.dataset.scheduledStartAt);
    input.value = Number.isNaN(current.getTime()) ? "" : toLocalInputValue(current);
    reasonInput.value = "";
    dialogError.hidden = true;
    updateWindow();
    dialog.showModal();
    input.focus();
  });
  document.querySelector("#start-time-cancel").addEventListener("click", function () {
    dialog.close();
  });
  input.addEventListener("input", updateWindow);

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    if (submitButton.disabled || !form.reportValidity()) return;
    const scheduledStart = new Date(input.value);
    if (Number.isNaN(scheduledStart.getTime())) {
      dialogError.textContent = "開始時刻を正しく入力してください。";
      dialogError.hidden = false;
      return;
    }
    // required はスペースだけの入力を通すので，ここでも確認する（サーバーも拒否する）．
    const reason = reasonInput.value.trim();
    if (!reason) {
      dialogError.textContent = "変更理由を入力してください。";
      dialogError.hidden = false;
      reasonInput.focus();
      return;
    }
    dialogError.hidden = true;
    submitButton.disabled = true;
    try {
      const response = await fetch("/attendance-sessions/" + sessionId + "/scheduled-start", {
        method: "PUT",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ scheduled_start_at: scheduledStart.toISOString(), reason: reason }),
      });
      if (response.ok) {
        // 画面の開始時刻表示はサーバーがJSTに整形した文字列なので，
        // 自前で組み立て直さず再読み込みして整合させる．
        window.location.reload();
        return;
      }
      dialogError.textContent = messageFor(response.status);
      dialogError.hidden = false;
    } catch (e) {
      dialogError.textContent = "通信に失敗しました。接続を確認して再度お試しください。";
      dialogError.hidden = false;
    } finally {
      submitButton.disabled = false;
    }
  });
})();
