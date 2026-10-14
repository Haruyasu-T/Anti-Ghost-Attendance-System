"use strict";

// DOMは createElement と textContent で組み立てる。文字列連結でHTMLを作らない
// （授業名も氏名も人が入力した値なので、連結するとそこがXSSの入口になる）。

const page = document.querySelector("[data-admin-console]");
const errorBox = document.querySelector("#admin-error");
const tbody = document.querySelector("#admin-courses");
const newCourseButton = document.querySelector("#new-course-button");
const retryButton = document.querySelector("#admin-retry");

const courseDialog = document.querySelector("#course-dialog");
const courseForm = document.querySelector("#course-form");
const courseTitle = document.querySelector("#course-dialog-title");
const courseName = document.querySelector("#course-name");
const courseTeacher = document.querySelector("#course-teacher");
const courseError = document.querySelector("#course-error");
const teacherWarning = document.querySelector("#teacher-change-warning");

const enrollmentDialog = document.querySelector("#enrollment-dialog");
const enrollmentForm = document.querySelector("#enrollment-form");
const enrollmentCourse = document.querySelector("#enrollment-course");
const enrollmentList = document.querySelector("#enrollment-list");
const enrollmentError = document.querySelector("#enrollment-error");

let teachers = [];
let students = [];
let editingCourse = null;
let enrollingCourse = null;
let enrollmentRequest = 0;
let enrollmentReady = false;

function setSaving(form, saving) {
    form.dataset.saving = String(saving);
    form.setAttribute("aria-busy", String(saving));
    form.querySelectorAll("button, input, select").forEach((control) => {
        control.disabled = saving;
    });
    form.querySelector('[type="submit"]').textContent = saving ? "保存中…" : "保存";
}

function csrfHeaders() {
    return {"Content-Type": "application/json", "X-CSRF-Token": page.dataset.csrfToken};
}

async function getJson(url) {
    const response = await fetch(url, {credentials: "same-origin"});
    if (response.status === 401) {
        window.location.assign("/login");
        throw new Error("unauthorized");
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
}

async function send(url, method, body, box) {
    box.hidden = true;
    let response;
    try {
        response = await fetch(url, {
            method,
            credentials: "same-origin",
            headers: csrfHeaders(),
            body: JSON.stringify(body),
        });
    } catch (error) {
        box.textContent = "通信できませんでした。通信状態を確認して、もう一度お試しください。";
        box.hidden = false;
        throw error;
    }
    if (response.ok) return;
    if (response.status === 401) {
        window.location.assign("/login");
        throw new Error("unauthorized");
    }

    let detail = "";
    try {
        detail = (await response.json()).detail || "";
    } catch (e) { /* JSONでない応答はメッセージなしで扱う */ }

    if (response.status === 400 || response.status === 422) {
        box.textContent = typeof detail === "string" && detail ? detail : "入力内容を確認してください。";
    } else if (response.status === 403) {
        box.textContent = "権限がありません。";
    } else if (response.status === 404) {
        box.textContent = "対象が見つかりません。画面を再読み込みしてください。";
    } else {
        box.textContent = "保存できませんでした。時間をおいて再度お試しください。";
    }
    box.hidden = false;
    throw new Error("request-failed");
}

function cell(text) {
    const td = document.createElement("td");
    td.textContent = text;
    return td;
}

function actionButton(label, className, onClick) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `btn btn-small ${className}`;
    button.textContent = label;
    button.addEventListener("click", onClick);
    return button;
}

function renderCourses(courses) {
    tbody.replaceChildren();
    if (!courses.length) {
        const tr = document.createElement("tr");
        const td = cell("授業がまだありません。");
        td.colSpan = 5;
        tr.append(td);
        tbody.append(tr);
        return;
    }
    for (const course of courses) {
        const tr = document.createElement("tr");
        tr.append(
            cell(course.name),
            cell(`${course.teacher_display_name}（${course.teacher_login_id}）`),
            cell(`${course.enrolled_count}人`),
            cell(`${course.session_count}回`),
        );
        const actions = document.createElement("td");
        const row = document.createElement("div");
        row.className = "button-row";
        row.append(
            actionButton("編集", "btn-secondary", () => openCourseDialog(course)),
            actionButton("履修者", "btn-secondary", () => openEnrollmentDialog(course)),
        );
        actions.append(row);
        tr.append(actions);
        tbody.append(tr);
    }
}

function fillTeacherOptions(selectedId) {
    courseTeacher.replaceChildren();
    for (const teacher of teachers) {
        const option = document.createElement("option");
        option.value = String(teacher.id);
        option.textContent = `${teacher.display_name}（${teacher.login_id}）`;
        if (teacher.id === selectedId) option.selected = true;
        courseTeacher.append(option);
    }
}

function updateTeacherWarning() {
    // 担当教員を変えると、その授業の過去の出席記録の閲覧権限も新しい担当へ移る。
    // 引き継ぎでは必要な挙動だが、気付かずに変えると記録が別の人に見える。
    const changed = editingCourse
        && Number(courseTeacher.value) !== editingCourse.teacher_id;
    if (changed && editingCourse.session_count > 0) {
        teacherWarning.textContent =
            `この授業は${editingCourse.session_count}回実施されています。`
            + "担当教員を変えると、過去の出席記録も新しい担当教員が見られるようになります。";
        teacherWarning.hidden = false;
    } else {
        teacherWarning.hidden = true;
    }
}

function openCourseDialog(course) {
    if (!teachers.length) return;
    editingCourse = course || null;
    courseTitle.textContent = course ? "授業を編集" : "授業を追加";
    courseName.value = course ? course.name : "";
    fillTeacherOptions(course ? course.teacher_id : (teachers[0] && teachers[0].id));
    courseError.hidden = true;
    updateTeacherWarning();
    courseDialog.showModal();
    courseName.focus();
}

async function openEnrollmentDialog(course) {
    const request = ++enrollmentRequest;
    enrollmentReady = false;
    enrollingCourse = course;
    enrollmentCourse.textContent = course.name;
    enrollmentError.hidden = true;
    enrollmentList.replaceChildren();
    enrollmentList.textContent = "履修者を読み込んでいます…";
    enrollmentList.setAttribute("aria-busy", "true");
    document.querySelector("#enrollment-submit").disabled = true;
    enrollmentDialog.showModal();

    let enrolled;
    try {
        enrolled = await getJson(`/admin/courses/${course.id}/enrollments`);
    } catch (e) {
        if (request !== enrollmentRequest || !enrollmentDialog.open) return;
        enrollmentList.replaceChildren();
        enrollmentList.setAttribute("aria-busy", "false");
        enrollmentError.textContent = "履修者を読み込めませんでした。閉じてから、もう一度開いてください。";
        enrollmentError.hidden = false;
        return;
    }
    if (request !== enrollmentRequest || !enrollmentDialog.open) return;
    enrollmentList.replaceChildren();
    enrollmentList.setAttribute("aria-busy", "false");
    const enrolledIds = new Set(enrolled.map((u) => u.id));

    for (const student of students) {
        const label = document.createElement("label");
        label.className = "checkbox-row";
        const input = document.createElement("input");
        input.type = "checkbox";
        input.value = String(student.id);
        input.checked = enrolledIds.has(student.id);
        const text = document.createElement("span");
        text.textContent = `${student.display_name}（${student.login_id}）`;
        label.append(input, text);
        enrollmentList.append(label);
    }
    if (!students.length) enrollmentList.textContent = "学生アカウントがまだありません。";
    enrollmentReady = true;
    document.querySelector("#enrollment-submit").disabled = false;
}

async function loadAll() {
    newCourseButton.disabled = true;
    retryButton.hidden = true;
    tbody.setAttribute("aria-busy", "true");
    try {
        const [users, courses] = await Promise.all([
            getJson("/admin/users"),
            getJson("/admin/courses"),
        ]);
        teachers = users.filter((u) => u.role === "teacher");
        students = users.filter((u) => u.role === "student");
        renderCourses(courses);
        errorBox.hidden = true;
        newCourseButton.disabled = !teachers.length;
        document.querySelector("#no-teachers").hidden = !!teachers.length;
    } catch (e) {
        if (e.message === "unauthorized") return;
        tbody.replaceChildren();
        errorBox.textContent = "読み込めませんでした。通信状態を確認して、再読み込みしてください。";
        errorBox.hidden = false;
        retryButton.hidden = false;
    } finally {
        tbody.setAttribute("aria-busy", "false");
    }
}

courseTeacher?.addEventListener("change", updateTeacherWarning);
document.querySelector("#new-course-button")?.addEventListener("click", () => openCourseDialog(null));
document.querySelector("#course-cancel")?.addEventListener("click", () => courseDialog.close());
document.querySelector("#enrollment-cancel")?.addEventListener("click", () => enrollmentDialog.close());
enrollmentDialog?.addEventListener("close", () => {
    ++enrollmentRequest;
    enrollmentReady = false;
});
retryButton?.addEventListener("click", loadAll);
for (const [dialog, form] of [[courseDialog, courseForm], [enrollmentDialog, enrollmentForm]]) {
    dialog?.addEventListener("cancel", (event) => {
        if (form.dataset.saving === "true") event.preventDefault();
    });
}

courseForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (courseForm.dataset.saving === "true") return;
    courseName.value = courseName.value.trim();
    if (!courseForm.reportValidity()) return;
    const body = {name: courseName.value.trim(), teacher_id: Number(courseTeacher.value)};
    const url = editingCourse ? `/admin/courses/${editingCourse.id}` : "/admin/courses";
    setSaving(courseForm, true);
    try {
        await send(url, editingCourse ? "PUT" : "POST", body, courseError);
        courseDialog.close();
        await loadAll();
    } catch (e) { /* メッセージは send が表示済み */ }
    finally { setSaving(courseForm, false); }
});

enrollmentForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!enrollmentReady || enrollmentForm.dataset.saving === "true") return;
    const checked = [...enrollmentList.querySelectorAll("input:checked")]
        .map((input) => Number(input.value));
    setSaving(enrollmentForm, true);
    try {
        await send(
            `/admin/courses/${enrollingCourse.id}/enrollments`,
            "PUT",
            {user_ids: checked},
            enrollmentError,
        );
        enrollmentDialog.close();
        await loadAll();
    } catch (e) { /* メッセージは send が表示済み */ }
    finally { setSaving(enrollmentForm, false); }
});

if (page && tbody) loadAll();

const windowForm = document.querySelector("#attendance-window-form");
windowForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (windowForm.dataset.saving === "true" || !windowForm.reportValidity()) return;
    const box = document.querySelector("#attendance-window-error");
    const saved = document.querySelector("#attendance-window-saved");
    saved.hidden = true;
    const body = Object.fromEntries(new FormData(windowForm));
    for (const name of Object.keys(body)) body[name] = Number(body[name]);
    if (body.late_until_minutes < body.present_after_minutes) {
        box.textContent = "受付終了は出席扱いの終了以降にしてください。";
        box.hidden = false;
        return;
    }
    setSaving(windowForm, true);
    try {
        await send("/admin/attendance-window", "PUT", body, box);
        saved.hidden = false;
    } catch (e) { /* メッセージは send が表示済み */ }
    finally { setSaving(windowForm, false); }
});
