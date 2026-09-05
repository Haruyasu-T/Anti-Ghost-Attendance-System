"use strict";

// DOMは createElement と textContent で組み立てる。文字列連結でHTMLを作らない
// （授業名も氏名も人が入力した値なので、連結するとそこがXSSの入口になる）。

const page = document.querySelector("[data-admin-console]");
const errorBox = document.querySelector("#admin-error");
const tbody = document.querySelector("#admin-courses");

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
    const response = await fetch(url, {
        method,
        credentials: "same-origin",
        headers: csrfHeaders(),
        body: JSON.stringify(body),
    });
    if (response.ok) return response.json();

    let detail = "";
    try {
        detail = (await response.json()).detail || "";
    } catch (e) { /* JSONでない応答はメッセージなしで扱う */ }

    if (response.status === 400) {
        box.textContent = detail || "入力内容を確認してください。";
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
    enrollingCourse = course;
    enrollmentCourse.textContent = course.name;
    enrollmentError.hidden = true;
    enrollmentList.replaceChildren();

    let enrolled = [];
    try {
        enrolled = await getJson(`/admin/courses/${course.id}/enrollments`);
    } catch (e) {
        enrollmentError.textContent = "履修者を読み込めませんでした。";
        enrollmentError.hidden = false;
    }
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
    enrollmentDialog.showModal();
}

async function loadAll() {
    try {
        const [users, courses] = await Promise.all([
            getJson("/admin/users"),
            getJson("/admin/courses"),
        ]);
        teachers = users.filter((u) => u.role === "teacher");
        students = users.filter((u) => u.role === "student");
        renderCourses(courses);
        errorBox.hidden = true;
    } catch (e) {
        if (e.message === "unauthorized") return;
        errorBox.textContent = "読み込めませんでした。時間をおいて再度お試しください。";
        errorBox.hidden = false;
    }
}

courseTeacher?.addEventListener("change", updateTeacherWarning);
document.querySelector("#new-course-button")?.addEventListener("click", () => openCourseDialog(null));
document.querySelector("#course-cancel")?.addEventListener("click", () => courseDialog.close());
document.querySelector("#enrollment-cancel")?.addEventListener("click", () => enrollmentDialog.close());

courseForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!courseForm.reportValidity()) return;
    const body = {name: courseName.value.trim(), teacher_id: Number(courseTeacher.value)};
    const url = editingCourse ? `/admin/courses/${editingCourse.id}` : "/admin/courses";
    try {
        await send(url, editingCourse ? "PUT" : "POST", body, courseError);
        courseDialog.close();
        await loadAll();
    } catch (e) { /* メッセージは send が表示済み */ }
});

enrollmentForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const checked = [...enrollmentList.querySelectorAll("input:checked")]
        .map((input) => Number(input.value));
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
});

if (page && tbody) loadAll();
