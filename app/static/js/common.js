// SPDX-FileCopyrightText: 2026 田中晴康
// SPDX-License-Identifier: Apache-2.0

"use strict";

document.querySelectorAll("[data-logout]").forEach((button) => {
    button.addEventListener("click", async () => {
        button.disabled = true;
        try {
            const response = await fetch("/auth/logout", {
                method: "POST",
                credentials: "same-origin",
                headers: {"X-CSRF-Token": button.dataset.csrfToken},
            });
            if (!response.ok && response.status !== 401) throw new Error("logout-failed");
            window.location.assign("/login");
        } catch (error) {
            window.alert("ログアウトできませんでした。通信状態を確認して、もう一度お試しください。");
            button.disabled = false;
        }
    });
});
