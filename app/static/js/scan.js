// SPDX-FileCopyrightText: 2026 田中晴康
// SPDX-License-Identifier: Apache-2.0

"use strict";
const shell = document.querySelector(".scanner-shell"),
  readerId = "qr-reader",
  result = document.querySelector("#scan-result"),
  errorBox = document.querySelector("#scanner-error"),
  zoomRow = document.querySelector("#zoom-row"),
  zoomInput = document.querySelector("#zoom"),
  zoomValue = document.querySelector("#zoom-value");
let scanner = null,
  submitting = false,
  zooming = false;
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
  if (status === 409) return detailOf(data) || "すでに登録済み、または受付が終了しています。";
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
// 教室の後ろの席からだと、QRが小さくて読み取りに時間がかかるという声が
// 実地テストで出た（2026-11-12）。カメラ側のズームを使えるようにする。
//
// ズームは端末とブラウザで対応がまちまちで、非対応でも例外にならず黙って
// 無視されることがある。操作できる見た目だけ出して効かないと「壊れている」と
// 受け取られるので、**カメラの能力を問い合わせて、対応しているときだけ出す**。
function showZoomValue(value) {
  zoomValue.textContent = Number(value).toFixed(1) + "倍";
}

function setUpZoom() {
  if (!zoomRow || !scanner || typeof scanner.getRunningTrackCapabilities !== "function") {
    if (zoomRow) zoomRow.hidden = true;
    return;
  }

  let zoom = null;
  try {
    const capabilities = scanner.getRunningTrackCapabilities();
    zoom = capabilities ? capabilities.zoom : null;
  } catch (e) {
    zoom = null;
  }

  // max が無い・min と同じなら、対応していても動かせる幅が無い。出さない。
  if (
    !zoom ||
    typeof zoom.min !== "number" ||
    typeof zoom.max !== "number" ||
    zoom.max <= zoom.min
  ) {
    zoomRow.hidden = true;
    return;
  }

  zoomInput.min = String(zoom.min);
  zoomInput.max = String(zoom.max);
  zoomInput.step = String(zoom.step || 0.1);
  zoomInput.value = String(zoom.min);
  showZoomValue(zoom.min);
  zoomRow.hidden = false;
}

function applyZoom() {
  const value = Number(zoomInput.value);
  showZoomValue(value);

  if (!scanner || typeof scanner.applyVideoConstraints !== "function") return;
  // スライダーを動かすと input が連続で発火する。前の適用が終わる前に
  // 重ねて投げるとカメラ側が詰まるので、1つずつ送る。
  if (zooming) return;
  zooming = true;
  scanner
    .applyVideoConstraints({ advanced: [{ zoom: value }] })
    .catch(function () {
      // 対応していてもカメラが拒否することがある。読み取り自体は続くので、
      // エラーは出さない（ここで赤い文字を出す方が混乱を招く）。
    })
    .then(function () {
      zooming = false;
    });
}

if (zoomInput) zoomInput.addEventListener("input", applyZoom);

async function start() {
  const startButton = document.querySelector("#start-scan");
  startButton.removeEventListener("click", start);
  startButton.disabled = true;

  result.hidden = true;
  errorBox.hidden = true;
  // 「もう一度読む」で入り直すとカメラを取り直すので、能力も取り直す。
  // 前回の値が残ったままだと、対応していない端末に切り替わったときに出続ける。
  if (zoomRow) zoomRow.hidden = true;
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
    setUpZoom();
  } catch (e) {
    errorBox.textContent = "カメラを起動できません。権限とHTTPS接続を確認してください。";
    errorBox.hidden = false;
    if (zoomRow) zoomRow.hidden = true;

    startButton.disabled = false;
  }
}

document.querySelector("#start-scan").addEventListener("click", start);
document.querySelector("#retry-scan").addEventListener("click", start);
const direct = parsePayload(location.href);
if (direct) submit(direct);
