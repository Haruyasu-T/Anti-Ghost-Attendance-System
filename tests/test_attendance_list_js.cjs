// SPDX-FileCopyrightText: 2026 田中晴康
// SPDX-License-Identifier: Apache-2.0

// Run with: node tests/test_attendance_list_js.cjs
//
// 教員画面のアラート表示。サーバー側（検知・API）はPython側で固定してあるが、
// **画面に出るところだけテストが無かった**（実地テストでも誤検知ゼロは見たが、
// 検知が働いたときの表示は試していない）。
//
// ここは単純な描画ではなく、出席一覧APIとアラートAPIの**2か所から来た注意を
// 突き合わせて重複を除く**処理が入っている。片方が落ちたときの挙動もここで決まる。
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

function makeEl(tagName) {
    const classes = [];
    return {
        tagName, textContent: "", className: "", colSpan: 0, type: "", value: "",
        hidden: false, dataset: {}, children: [], handlers: {},
        classList: {classes, add(...names) { classes.push(...names); }},
        append(...kids) { this.children.push(...kids); },
        replaceChildren(...kids) { this.children = kids.slice(); },
        addEventListener(type, fn) { this.handlers[type] = fn; },
        querySelector() { return makeEl("div"); },
        showModal() {}, close() {},
    };
}

// 1行は renderRow が この順で組む：
//   学籍番号 / 氏名 / 状態 / 読取回数 / **注意** / 操作
const WARNING_CELL = 4;

function alertsOf(row) {
    const cell = row.children[WARNING_CELL];
    if (!cell.children.length) return cell.textContent;
    return cell.children[0].children.map((span) => span.textContent);
}

function alertClassesOf(row) {
    return row.children[WARNING_CELL].children[0].children[0].classList.classes;
}

async function render({rows, alertRows, listOk = true, alertsFail = false}) {
    const elements = new Map();
    const getElement = (selector) => {
        if (!elements.has(selector)) {
            elements.set(selector, Object.assign(makeEl("div"), {
                dataset: {sessionId: "1", csrfToken: "test-csrf"},
            }));
        }
        return elements.get(selector);
    };

    const context = vm.createContext({
        document: {querySelector: getElement, createElement: makeEl},
        Object, Array, Set, Map, Number, String, JSON, Promise, encodeURIComponent,
        fetch: async (url) => {
            if (url.endsWith("/alerts")) {
                if (alertsFail) throw new Error("network failure");
                return {ok: true, json: async () => ({rows: alertRows || []})};
            }
            if (!listOk) return {ok: false, json: async () => ({})};
            return {
                ok: true,
                json: async () => ({
                    session: {course_name: "テスト授業", required_scan_count: 2},
                    rows: rows || [],
                }),
            };
        },
    });

    vm.runInContext(fs.readFileSync("app/static/js/attendance-list.js", "utf8"), context);
    // load() は評価と同時に走る。入れ子の await が解けるまで待つ。
    for (let i = 0; i < 8; i++) await new Promise((resolve) => setImmediate(resolve));

    return {rendered: getElement("#attendance-rows").children, error: getElement("#list-error")};
}

async function main() {
    // --- 2か所から来た注意が1つにまとまること ---
    const merged = await render({
        rows: [{user_id: 1, login_id: "S0001", display_name: "学生01", status: "present",
                scan_count: 1, alerts: ["同じ端末で複数アカウント"]}],
        alertRows: [{user_id: 1, alerts: ["同じ端末で複数アカウント", "短時間に同じ端末から複数人"]}],
    });
    assert.equal(merged.rendered.length, 1);
    assert.deepEqual(
        alertsOf(merged.rendered[0]),
        ["⚠ 同じ端末で複数アカウント", "⚠ 短時間に同じ端末から複数人"],
        "重複を1つにまとめ、両方の注意を出すこと",
    );
    assert.ok(
        alertClassesOf(merged.rendered[0]).includes("status-alert"),
        "注意だと分かる見た目にすること",
    );

    // --- アラートAPI側にしか無い注意も出ること（登録時に記録された分） ---
    const onlyFromAlertsApi = await render({
        rows: [{user_id: 7, login_id: "S0007", display_name: "学生07", status: "present",
                scan_count: 1, alerts: []}],
        alertRows: [{user_id: 7, alerts: ["別アカウントに紐付いた端末"]}],
    });
    assert.deepEqual(alertsOf(onlyFromAlertsApi.rendered[0]), ["⚠ 別アカウントに紐付いた端末"]);

    // --- 注意が無い人は「—」になること（空欄にしない） ---
    const clean = await render({
        rows: [{user_id: 2, login_id: "S0002", display_name: "学生02", status: "present",
                scan_count: 1, alerts: []}],
        alertRows: [],
    });
    assert.equal(alertsOf(clean.rendered[0]), "—", "注意が無いことを明示すること");

    // --- アラートAPIが落ちても、出席一覧側の注意は出すこと ---
    const degraded = await render({
        rows: [{user_id: 3, login_id: "S0003", display_name: "学生03", status: "present",
                scan_count: 1, alerts: ["同じ端末で複数アカウント"]}],
        alertsFail: true,
    });
    assert.deepEqual(
        alertsOf(degraded.rendered[0]), ["⚠ 同じ端末で複数アカウント"],
        "片方が落ちても、取れている注意は消さないこと",
    );
    assert.equal(degraded.error.hidden, false, "取れなかったことは伝えること");
    assert.ok(
        degraded.error.textContent.includes("一部の注意情報を取得できませんでした"),
        "「出席状況が読めない」と混同させない文言にすること",
    );

    // --- 出席一覧そのものが落ちたときは、注意ではなく読み込み失敗を出すこと ---
    const broken = await render({listOk: false});
    assert.equal(broken.rendered.length, 0);
    assert.equal(broken.error.hidden, false);
    assert.ok(broken.error.textContent.includes("出席状況を読み込めませんでした"));

    // --- 履修者がいないときの表示 ---
    const empty = await render({rows: [], alertRows: []});
    assert.equal(empty.rendered.length, 1);
    assert.equal(empty.rendered[0].children[0].textContent, "履修者はいません。");

    console.log("attendance-list.js alerts: all assertions passed");
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
