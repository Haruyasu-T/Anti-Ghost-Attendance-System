"use strict";

document.querySelectorAll("[data-logout]").forEach((button) => {
    button.addEventListener("click", async () => {
        button.disabled = true;
        try {
            await fetch("/auth/logout", {
                method: "POST",
                credentials: "same-origin",
                headers: {"X-CSRF-Token": button.dataset.csrfToken},
            });
        } finally {
            window.location.assign("/login");
        }
    });
});
