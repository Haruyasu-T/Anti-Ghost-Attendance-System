// SPDX-FileCopyrightText: 2026 田中晴康
// SPDX-License-Identifier: Apache-2.0

// Run with: node tests/test_scan_zoom_js.cjs
//
// 読み取り画面のズームは「カメラが対応しているときだけ出す」ことに意味がある。
// 非対応の端末で操作できる見た目だけ出すと、動かないものを触らせることになる。
// 分岐がブラウザの能力に依存して手では試しにくいので、ここで固定しておく。
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

function makeElement(overrides) {
    return Object.assign({
        dataset: {csrfToken: "test-csrf"},
        textContent: "", hidden: false, disabled: false, style: {},
        handlers: {},
        addEventListener(type, fn) { this.handlers[type] = fn; },
        removeEventListener() {},
        querySelector() { return makeElement({}); },
    }, overrides);
}

// `capabilities` が null のときは getRunningTrackCapabilities 自体を生やさない
// （古い版のライブラリや、トラックを取れない状況を模す）。
function run({capabilities, hasCapabilityApi = true, applyBehavior}) {
    const elements = new Map();
    const getElement = (selector) => {
        if (!elements.has(selector)) elements.set(selector, makeElement({}));
        return elements.get(selector);
    };

    const applied = [];
    let resolveApply = null;

    class FakeScanner {
        async start() {}
        async stop() {}
        applyVideoConstraints(constraints) {
            applied.push(constraints);
            if (applyBehavior === "reject") return Promise.reject(new Error("refused"));
            if (applyBehavior === "pending") {
                return new Promise((resolve) => { resolveApply = resolve; });
            }
            return Promise.resolve();
        }
    }
    if (hasCapabilityApi) {
        FakeScanner.prototype.getRunningTrackCapabilities = function () {
            if (capabilities === "throws") throw new Error("no track");
            return capabilities;
        };
    }

    const context = vm.createContext({
        document: {querySelector: getElement},
        URL,
        // `/scan` に直接着地した形にしない（着地すると submit が走ってしまう）
        location: {origin: "https://testserver", href: "https://testserver/scan"},
        fetch: async () => ({ok: true, json: async () => ({})}),
        Html5Qrcode: FakeScanner,
    });

    vm.runInContext(fs.readFileSync("app/static/js/scan.js", "utf8"), context);

    return {
        elements, applied,
        releaseApply: () => resolveApply && resolveApply(),
        row: getElement("#zoom-row"),
        input: getElement("#zoom"),
        value: getElement("#zoom-value"),
        startScan: () => getElement("#start-scan").handlers.click(),
        slide: (v) => { getElement("#zoom").value = String(v); getElement("#zoom").handlers.input(); },
    };
}

async function main() {
    // --- 対応していないときは出さない ---
    for (const [name, options] of [
        ["ズームの項目が無い", {capabilities: {}}],
        ["capabilities が取れない", {capabilities: null}],
        ["問い合わせで例外", {capabilities: "throws"}],
        ["問い合わせAPIが無い", {capabilities: null, hasCapabilityApi: false}],
        ["動かせる幅が無い", {capabilities: {zoom: {min: 2, max: 2}}}],
        ["max が数値でない", {capabilities: {zoom: {min: 1, max: null}}}],
    ]) {
        const app = run(options);
        await app.startScan();
        assert.equal(app.row.hidden, true, `${name}: ズームを出してはいけない`);
    }

    // --- 対応していれば出す ---
    const ok = run({capabilities: {zoom: {min: 1, max: 4, step: 0.5}}});
    await ok.startScan();
    assert.equal(ok.row.hidden, false, "対応していれば出すこと");
    assert.equal(ok.input.min, "1");
    assert.equal(ok.input.max, "4");
    assert.equal(ok.input.step, "0.5");
    assert.equal(ok.input.value, "1", "はじめは最小から始めること");
    assert.equal(ok.value.textContent, "1.0倍");

    // step が無いカメラでも動くこと（既定の刻みを入れる）
    const noStep = run({capabilities: {zoom: {min: 1, max: 3}}});
    await noStep.startScan();
    assert.equal(noStep.input.step, "0.1");

    // --- スライダーを動かすとカメラに渡る ---
    const moved = run({capabilities: {zoom: {min: 1, max: 4, step: 0.5}}});
    await moved.startScan();
    moved.slide(2.5);
    // vm の中で作られたオブジェクトは Object.prototype が別（realm が違う）ため、
    // deepStrictEqual は中身が同じでも落ちる。値を直接見る。
    assert.equal(moved.applied.length, 1, "1回だけ渡すこと");
    assert.equal(moved.applied[0].advanced[0].zoom, 2.5, "ズーム値を渡すこと");
    assert.equal(moved.value.textContent, "2.5倍", "倍率の表示を更新すること");

    // --- 連続で動かしても重ねて投げない ---
    const busy = run({capabilities: {zoom: {min: 1, max: 4}}, applyBehavior: "pending"});
    await busy.startScan();
    busy.slide(2);
    busy.slide(3);
    busy.slide(4);
    assert.equal(busy.applied.length, 1, "前の適用が終わるまで重ねて投げないこと");
    assert.equal(busy.value.textContent, "4.0倍", "表示だけは追従すること");
    busy.releaseApply();
    await new Promise((resolve) => setImmediate(resolve));
    busy.slide(3);
    assert.equal(busy.applied.length, 2, "終わったら次を投げられること");

    // --- カメラに拒否されても壊れないこと ---
    const refused = run({capabilities: {zoom: {min: 1, max: 4}}, applyBehavior: "reject"});
    await refused.startScan();
    refused.slide(3);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(
        refused.elements.get("#scanner-error").hidden, true,
        "カメラに拒否されてもエラー表示は出さないこと（読み取り自体は続いている）",
    );
    assert.equal(refused.row.hidden, false, "拒否されてもスライダーは残すこと");

    console.log("scan.js zoom: all assertions passed");
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
