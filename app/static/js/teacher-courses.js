"use strict";

const courseList = document.querySelector("#courses-list");
const errorBox = document.querySelector("#courses-error");

function showMessage(message) {
    courseList.replaceChildren();
    const text = document.createElement("p");
    text.className = "muted";
    text.textContent = message;
    courseList.append(text);
}

function renderCourses(courses) {
    courseList.replaceChildren();
    for (const course of courses) {
        const card = document.createElement("article");
        card.className = "action-card";

        const icon = document.createElement("span");
        icon.className = "action-icon";
        icon.setAttribute("aria-hidden", "true");
        icon.textContent = "▤";

        const name = document.createElement("span");
        name.textContent = course.name;

        const description = document.createElement("small");
        description.textContent = "出席セッションの開始・確認";

        card.append(icon, name, description);
        courseList.append(card);
    }
}

async function loadCourses() {
    try {
        const response = await fetch("/courses", {credentials: "same-origin"});
        if (response.status === 401) {
            window.location.assign("/login");
            return;
        }
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const courses = await response.json();
        if (!Array.isArray(courses) || courses.length === 0) {
            showMessage("担当授業は登録されていません。");
            return;
        }
        renderCourses(courses);
    } catch (error) {
        errorBox.textContent = "授業一覧を取得できませんでした。時間をおいて再度お試しください。";
        errorBox.hidden = false;
        showMessage("授業を表示できません。");
    } finally {
        courseList.setAttribute("aria-busy", "false");
    }
}

if (courseList && errorBox) loadCourses();
