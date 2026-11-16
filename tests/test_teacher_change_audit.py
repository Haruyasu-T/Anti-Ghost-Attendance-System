# SPDX-FileCopyrightText: 2026 田中晴康
# SPDX-License-Identifier: Apache-2.0

"""担当教員を変えた後，操作が「操作した本人」として記録されるかのテスト.

以前は `sess.created_by`（セッションを作った人）を監査ログの `actor_user_id` と
`manual_corrections.teacher_id` に使っていた。管理者が担当教員を変更すると，
**新担当の操作が旧担当の名前で記録される**。

出席の訂正は記録を書き換えられる特権操作なので，「誰がやったか」が違うと
追跡可能性（原則⑥）そのものが成り立たない。

`session_start_time_update` だけは当初から本人を使っていた。同じ考え方が
他の4つに及んでいなかったので，**5つとも**ここで固定する。
"""

import datetime as dt

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models, security
from app.db import get_db
from app.main import app

PASSWORD = "teacher-change-password"


@pytest.fixture
def world(tmp_path):
    """旧担当→新担当に付け替えた授業と，開いているセッションを作る."""
    engine = models.create_db_engine(f"sqlite:///{tmp_path / 'handover.db'}")
    models.Base.metadata.create_all(engine)
    db = Session(engine)

    def user(login_id, role):
        return models.User(
            login_id=login_id, role=role, display_name=f"{login_id}の氏名",
            password_hash=security.hash_password(PASSWORD),
        )

    old_teacher = user("T0001", "teacher")
    new_teacher = user("T0002", "teacher")
    student = user("S0001", "student")
    db.add_all([old_teacher, new_teacher, student])
    db.flush()

    course = models.Course(name="情報セキュリティ", teacher_id=old_teacher.id)
    db.add(course)
    db.flush()
    db.add(models.Enrollment(course_id=course.id, user_id=student.id))

    now = security.to_iso(dt.datetime.now(dt.timezone.utc))
    sess = models.AttendanceSession(
        course_id=course.id,
        scheduled_start_at=now,
        started_at=now,
        status="open",
        required_scan_count=1,
        token_salt=security.new_token_salt(),
        # セッションを作ったのは「旧担当」
        created_by=old_teacher.id,
    )
    db.add(sess)
    db.flush()

    db.add(models.Attendance(
        attendance_session_id=sess.id, user_id=student.id,
        status="present", first_recorded_at=now, record_source="auto",
    ))

    # 管理者が担当教員を付け替えた（ここが問題の前提）
    course.teacher_id = new_teacher.id
    db.commit()

    ids = {
        "session": sess.id,
        "old": old_teacher.id,
        "new": new_teacher.id,
        "student": student.id,
    }

    app.dependency_overrides[get_db] = lambda: db
    try:
        client = TestClient(app, base_url="https://testserver")
        login = client.post(
            "/auth/login", json={"login_id": "T0002", "password": PASSWORD}
        )
        assert login.status_code == 200, "新担当でログインできること"
        yield client, db, ids
    finally:
        app.dependency_overrides.clear()
        db.close()


def _csrf(client):
    """CSRFトークンは画面に埋め込んで渡す作りなので、テストでは直接作る."""
    return {"X-CSRF-Token": security.csrf_token_for_session(client.cookies.get("session"))}


def _actors(db, action):
    return [
        row[0]
        for row in db.query(models.AuditLog.actor_user_id)
        .filter(models.AuditLog.action == action, models.AuditLog.result == "success")
        .all()
    ]


def test_correction_is_recorded_as_the_teacher_who_did_it(world):
    """出席の訂正が，旧担当ではなく操作した新担当として記録されること."""
    client, db, ids = world

    response = client.put(
        f"/attendance-sessions/{ids['session']}/attendances/{ids['student']}",
        json={"status": "absent", "reason": "本人の申告により訂正"},
        headers=_csrf(client),
    )
    assert response.status_code == 200, response.text

    correction = db.query(models.ManualCorrection).one()
    assert correction.teacher_id == ids["new"], (
        "訂正した本人ではなく、セッションを作った旧担当が記録されている"
    )
    assert correction.teacher_id != ids["old"]

    assert _actors(db, "manual_correction") == [ids["new"]]


@pytest.mark.parametrize("path,action", [
    ("rescan", "rescan_start"),
    ("rotate-token", "token_rotate"),
    ("close", "session_close"),
])
def test_session_operations_are_recorded_as_the_teacher_who_did_them(world, path, action):
    """再表示・トークン再生成・終了も，操作した本人として記録されること."""
    client, db, ids = world

    response = client.post(
        f"/attendance-sessions/{ids['session']}/{path}",
        headers=_csrf(client),
    )
    assert response.status_code == 200, response.text

    assert _actors(db, action) == [ids["new"]], (
        f"{action} が旧担当として記録されている"
    )


def test_old_teacher_can_no_longer_operate(world):
    """付け替え後，旧担当は操作できないこと（認可そのものの確認）.

    記録の正しさだけ直しても、旧担当が操作できてしまっては意味がない。
    """
    client, db, ids = world

    client.post("/auth/logout", headers={"X-CSRF-Token": client.cookies.get("csrf_token") or ""})
    client.post("/auth/login", json={"login_id": "T0001", "password": PASSWORD})

    response = client.post(
        f"/attendance-sessions/{ids['session']}/close",
        headers=_csrf(client),
    )
    assert response.status_code == 404, "旧担当には見つからない扱いにすること"
