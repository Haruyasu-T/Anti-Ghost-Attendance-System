"use strict";

const courseList = document.querySelector("#courses-list");
const errorBox = document.querySelector("#courses-error");
const page = document.querySelector("[data-teacher-courses]");
const dialog = document.querySelector("#start-session-dialog");
const startForm = document.querySelector("#start-session-form");
const startInput = document.querySelector("#scheduled-start-at");
const startCourse = document.querySelector("#start-session-course");
const windowBox = document.querySelector("#attendance-window");
const startError = document.querySelector("#start-session-error");
const confirmButton = document.querySelector("#confirm-session-button");
let selectedCourseId = null;

const attendanceSettings = page ? {
    presentBefore: Number(page.dataset.presentBeforeMinutes),
    presentAfter: Number(page.dataset.presentAfterMinutes),
    lateUntil: Number(page.dataset.lateUntilMinutes),
} : null;

function showMessage(message) {
    courseList.replaceChildren();
    const text = document.createElement("p");
    text.className = "muted";
    text.textContent = message;
    courseList.append(text);
}

function buttonLink(label, href, className = "btn-secondary") {
    const link = document.createElement("a");
    link.className = `btn ${className}`;
    link.href = href;
    link.textContent = label;
    return link;
}

function renderCourses(coursesWithSessions) {
    courseList.replaceChildren();
    for (const {course, sessions} of coursesWithSessions) {
        const card = document.createElement("article");
        card.className = "course-card";

        const name = document.createElement("h2");
        name.className = "course-card-title";
        name.textContent = course.name;

        const body = document.createElement("div");
        body.className = "course-card-body";
        const openSession = sessions.find((session) => session.status === "open");

        const status = document.createElement("p");
        status.className = openSession ? "session-state session-state-open" : "session-state";
        status.textContent = openSession ? "開催中のセッションあり" : "セッションなし";

        const actions = document.createElement("div");
        actions.className = "button-row";
        if (openSession) {
            actions.append(
                buttonLink("QR表示", `/attendance-sessions/${openSession.id}/qr`, "btn-primary"),
                buttonLink("状況", `/attendance-sessions/${openSession.id}/attendances/view`),
            );
        } else {
            const startButton = document.createElement("button");
            startButton.className = "btn btn-primary";
            startButton.type = "button";
            startButton.textContent = "開始";
            startButton.addEventListener("click", () => openStartDialog(course));
            actions.append(startButton);
        }

        body.append(status, actions);
        card.append(name, body);
        courseList.append(card);
    }
}

function toLocalInputValue(date) {
    const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
    return local.toISOString().slice(0, 16);
}

function roundedNow() {
    const date = new Date();
    date.setSeconds(0, 0);
    date.setMinutes(Math.round(date.getMinutes() / 5) * 5);
    return date;
}

function formatTime(date) {
    return new Intl.DateTimeFormat("ja-JP", {
        hour: "2-digit", minute: "2-digit", hour12: false,
    }).format(date);
}

function updateAttendanceWindow() {
    const start = new Date(startInput.value);
    if (Number.isNaN(start.getTime())) {
        windowBox.textContent = "開始時刻を入力すると受付時間帯を表示します。";
        return;
    }
    const shifted = (minutes) => new Date(start.getTime() + minutes * 60000);
    windowBox.textContent =
        `出席：${formatTime(shifted(-attendanceSettings.presentBefore))}〜` +
        `${formatTime(shifted(attendanceSettings.presentAfter))}　` +
        `遅刻：${formatTime(shifted(attendanceSettings.presentAfter))}〜` +
        `${formatTime(shifted(attendanceSettings.lateUntil))}`;
}

function openStartDialog(course) {
    selectedCourseId = course.id;
    startCourse.textContent = course.name;
    startInput.value = toLocalInputValue(roundedNow());
    startError.hidden = true;
    updateAttendanceWindow();
    dialog.showModal();
    startInput.focus();
}

async function loadCourseSessions(course) {
    const response = await fetch(`/courses/${course.id}/attendance-sessions`, {
        credentials: "same-origin",
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const sessions = await response.json();
    return {course, sessions: Array.isArray(sessions) ? sessions : []};
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
        const coursesWithSessions = await Promise.all(courses.map(loadCourseSessions));
        renderCourses(coursesWithSessions);
    } catch (error) {
        errorBox.textContent = "授業一覧を取得できませんでした。時間をおいて再度お試しください。";
        errorBox.hidden = false;
        showMessage("授業を表示できません。");
    } finally {
        courseList.setAttribute("aria-busy", "false");
    }
}

startInput?.addEventListener("input", updateAttendanceWindow);
document.querySelector("#cancel-session-button")?.addEventListener("click", () => dialog.close());
startForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!startForm.reportValidity() || selectedCourseId === null) return;

    startError.hidden = true;
    confirmButton.disabled = true;
    try {
        const scheduledStart = new Date(startInput.value);
        if (Number.isNaN(scheduledStart.getTime())) throw new Error("invalid-date");
        const response = await fetch(`/courses/${selectedCourseId}/attendance-sessions`, {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": page.dataset.csrfToken,
            },
            body: JSON.stringify({scheduled_start_at: scheduledStart.toISOString()}),
        });
        if (response.ok) {
            const session = await response.json();
            window.location.assign(`/attendance-sessions/${session.id}/qr`);
            return;
        }
        if (response.status === 400) {
            startError.textContent = "開始時刻を確認してください。現在時刻から3時間以内の日時を入力してください。";
        } else if (response.status === 409) {
            startError.textContent = "この授業には開催中のセッションが既にあります。画面を再読み込みしてください。";
        } else if (response.status === 403) {
            startError.textContent = "この授業のセッションを開始する権限がありません。";
        } else {
            startError.textContent = "セッションを開始できませんでした。時間をおいて再度お試しください。";
        }
        startError.hidden = false;
    } catch (error) {
        startError.textContent = error.message === "invalid-date"
            ? "開始時刻を正しく入力してください。"
            : "通信に失敗しました。接続を確認して再度お試しください。";
        startError.hidden = false;
    } finally {
        confirmButton.disabled = false;
    }
});

if (courseList && errorBox && page && dialog) loadCourses();
