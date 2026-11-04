// SPDX-FileCopyrightText: 2026 田中晴康
// SPDX-License-Identifier: Apache-2.0

// Run with: node tests/test_teacher_qr_js.cjs
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

async function main() {
    const elements = new Map();
    const getElement = (selector) => {
        if (!elements.has(selector)) elements.set(selector, {
            dataset: {sessionId: "1", csrfToken: "test-csrf"},
            textContent: "1回目", disabled: false, hidden: true, style: {},
            replaceChildren() {}, addEventListener() {},
        });
        return elements.get(selector);
    };
    let fail = false;
    let release;
    let rescanCalls = 0;
    const context = vm.createContext({
        document: {querySelector: getElement}, URL,
        location: {origin: "https://testserver"},
        confirm: () => true, setInterval() {},
        QRCode: Object.assign(function () {}, {CorrectLevel: {M: 0}}),
        fetch: async (url) => {
            if (url.endsWith("/rescan")) {
                rescanCalls++;
                await new Promise(resolve => { release = resolve; });
                if (fail) throw new Error("network failure");
                // Another tab has advanced the server to round 4.
                return {ok: true, json: async () => ({required_scan_count: 4})};
            }
            return {ok: true, json: async () => ({
                rows: [], token: "test-token", rotate_seconds: 5,
                next_rotate_at: new Date(Date.now() + 5000).toISOString(),
            })};
        },
    });
    vm.runInContext(fs.readFileSync("app/static/js/teacher-qr.js", "utf8"), context);
    const first = vm.runInContext('action("rescan")', context);
    assert.equal(getElement("#rescan-button").disabled, true);
    await vm.runInContext('action("rescan")', context);
    assert.equal(rescanCalls, 1, "double click must not advance two rounds");
    release();
    await first;
    assert.equal(getElement("#scan-round").textContent, "4回目");
    assert.equal(getElement("#rescan-button").textContent, "5回目のQRを表示");
    assert.equal(getElement("#rescan-button").disabled, false);
    fail = true;
    const failed = vm.runInContext('action("rescan")', context);
    release();
    await failed;
    assert.equal(getElement("#rescan-button").disabled, false);
    assert.equal(getElement("#qr-error").hidden, false);
    assert.equal(getElement("#scan-round").textContent, "4回目");
    console.log("QR actions: server round, double click, network failure passed");
}

main().catch(error => { console.error(error); process.exitCode = 1; });
