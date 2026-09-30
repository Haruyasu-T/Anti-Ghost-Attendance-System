"use strict";
const shell = document.querySelector(".scanner-shell"),
  readerId = "qr-reader",
  result = document.querySelector("#scan-result"),
  errorBox = document.querySelector("#scanner-error");
let scanner = null,
  submitting = false;
function parsePayload(value) {
  try {
    const url = new URL(value, location.origin);
    if (url.origin !== location.origin || url.pathname !== "/scan") return null;
    const s = Number(url.searchParams.get("s")),
      t = url.searchParams.get("t");
    return Number.isInteger(s) && s > 0 && t ? { attendance_session_id: s, token: t } : null;
  } catch (e) {
    return null;
  }
}
// サーバーは拒否の理由を detail に入れて返す（FastAPI の HTTPException の形式）。
// 以前は message を読んでいたため、学外からのアクセスも期限切れのQRも
// 同じ文言になり、学生にも我々にも原因が分からなかった。
// 理由が分かる文言はそのまま出し、無いときだけ汎用の文言に落とす。
function detailOf(data) {
  return data && typeof data.detail === "string" && data.detail ? data.detail : "";
}
function messageFor(status, data) {
  if (status === 401) return "ログインし直してから、もう一度読み取ってください。";
  if (status === 403) return detailOf(data) || "このQRでは出席登録できませんでした。";
  if (status === 409)
    return detailOf(data) || "すでに登録済み、または受付が終了しています。";
  return detailOf(data) || "出席登録に失敗しました。もう一度お試しください。";
}
async function submit(payload) {
  if (submitting) return;
  submitting = true;
  try {
    if (scanner) scanner.stop().catch(function () {});
    const response = await fetch("/attendances", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": shell.dataset.csrfToken },
      body: JSON.stringify(payload),
    });
    let data = {};
    try {
      data = await response.json();
    } catch (e) {}
    result.hidden = false;
    result.className = "card result-card " + (response.ok ? "result-success" : "result-error");
    result.querySelector(".result-symbol").textContent = response.ok ? "✓" : "!";
    document.querySelector("#result-title").textContent = response.ok
      ? data.status === "late"
        ? "遅刻として記録しました"
        : "出席を記録しました"
      : "登録できませんでした";
    document.querySelector("#result-message").textContent = response.ok
      ? String(data.scan_seq || 1) + "回目の読み取りを受け付けました。"
      : messageFor(response.status, data);
  } catch (e) {
    errorBox.textContent = "通信できませんでした。接続を確認してください。";
    errorBox.hidden = false;
  } finally {
    submitting = false;
  }
}
async function start() {
  const startButton = document.querySelector("#start-scan");
  startButton.removeEventListener("click", start);
  startButton.disabled = true;

  result.hidden = true;
  errorBox.hidden = true;
  if (typeof Html5Qrcode === "undefined") {
    errorBox.textContent = "QR読み取り機能を読み込めませんでした。再読み込みしてください。";
    errorBox.hidden = false;
    return;
  }
  scanner = new Html5Qrcode(readerId);
  try {
    await scanner.start(
      { facingMode: "environment" },
      { fps: 10, qrbox: { width: 240, height: 240 } },
      function (text) {
        const payload = parsePayload(text);
        if (payload) submit(payload);
      },
    );

    startButton.hidden = true;
  } catch (e) {
    errorBox.textContent = "カメラを起動できません。権限とHTTPS接続を確認してください。";
    errorBox.hidden = false;

    startButton.disabled = false;
  }
}

document.querySelector("#start-scan").addEventListener("click", start);
document.querySelector("#retry-scan").addEventListener("click", start);
const direct = parsePayload(location.href);
if (direct) submit(direct);
