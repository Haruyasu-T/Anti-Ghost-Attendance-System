# SPDX-FileCopyrightText: 2026 田中晴康
# SPDX-License-Identifier: Apache-2.0

"""授業の出席セッション一覧（GET /courses/{id}/attendance-sessions）のテスト.

画面が「開催中の回があるか」を判断するために使うAPI．
他の教員の授業を覗けないこと，秘密の列が混ざらないことを固定しておく．
"""

import datetime as dt

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models, security
from app.db import get_db
from app.main import app

PASSWORD = "course-sessions-password"


def _iso(offset_minutes: int = 0) -> str:
    return security.to_iso(
        dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=offset_minutes)
    )


def _fixture(tmp_path):
    """教員2名・授業2つ（それぞれ別の教員）・学生1名を用意する."""
    engine = models.create_db_engine(f"sqlite:///{tmp_path / 'sessions.db'}")
    models.Base.metadata.create_all(engine)
    db = Session(engine)

    def user(login_id, role):
        return models.User(
            login_id=login_id, role=role, display_name=login_id,
            password_hash=security.hash_password(PASSWORD),
        )

    mine, other, student = user("T0001", "teacher"), user("T0002", "teacher"), user("S0001", "student")
    db.add_all([mine, other, student])
    db.flush()

    my_course = models.Course(name="情報セキュリティ", teacher_id=mine.id)
    other_course = models.Course(name="他教員の授業", teacher_id=other.id)
    db.add_all([my_course, other_course])
    db.flush()

    ids = {"my_course": my_course.id, "other_course": other_course.id}
    db.commit()
    return db, ids


def _client(db, login_id) -> TestClient:
    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app, base_url="https://testserver")
    client.post("/auth/login", json={"login_id": login_id, "password": PASSWORD})
    return client


def _add_session(db, course_id, *, status="open", offset=0):
    row = models.AttendanceSession(
        course_id=course_id,
        scheduled_start_at=_iso(offset),
        started_at=_iso(offset),
        closed_at=None if status == "open" else _iso(offset),
        status=status,
        required_scan_count=1,
        token_salt=security.new_token_salt(),
        created_by=1,
    )
    db.add(row)
    db.commit()
    return row.id


def test_returns_sessions_of_the_course_newest_first(tmp_path):
    db, ids = _fixture(tmp_path)
    old = _add_session(db, ids["my_course"], status="closed", offset=-120)
    recent = _add_session(db, ids["my_course"], offset=-5)
    try:
        response = _client(db, "T0001").get(f"/courses/{ids['my_course']}/attendance-sessions")
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 200
    assert [row["id"] for row in response.json()] == [recent, old]
    assert [row["status"] for row in response.json()] == ["open", "closed"]


def test_other_teachers_course_is_not_found(tmp_path):
    """他の教員の授業は403ではなく404にすること.

    403だと「そのIDの授業は存在する」と分かってしまう．
    """
    db, ids = _fixture(tmp_path)
    _add_session(db, ids["other_course"])
    try:
        response = _client(db, "T0001").get(f"/courses/{ids['other_course']}/attendance-sessions")
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 404


def test_student_cannot_list_sessions(tmp_path):
    db, ids = _fixture(tmp_path)
    _add_session(db, ids["my_course"])
    try:
        response = _client(db, "S0001").get(f"/courses/{ids['my_course']}/attendance-sessions")
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 403


def test_token_salt_is_not_exposed(tmp_path):
    """塩を返さないこと.

    塩が漏れると，秘密鍵と合わせてトークンを偽造される余地ができる．
    レスポンスの形を固定しているので混ざらないはずだが，モデルに列を足した
    ときに漏れ出さないことをここで押さえる．
    """
    db, ids = _fixture(tmp_path)
    _add_session(db, ids["my_course"])
    try:
        response = _client(db, "T0001").get(f"/courses/{ids['my_course']}/attendance-sessions")
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert "token_salt" not in response.text
    assert "created_by" not in response.text


def test_second_session_for_the_same_course_is_rejected(tmp_path):
    """開催中の回があるうちは、二重に作れないこと.

    押すたびに回ができると、学生がどちらのQRを読んだかで出席記録が
    分裂する．しかも教員は気付けない．画面側でもボタンを隠すが、
    URLを直接叩かれる前提で server 側でも弾く．
    """
    db, ids = _fixture(tmp_path)
    try:
        client = _client(db, "T0001")
        csrf = security.csrf_token_for_session(client.cookies.get("session"))
        body = {"scheduled_start_at": _iso()}
        first = client.post(f"/courses/{ids['my_course']}/attendance-sessions",
                            json=body, headers={"X-CSRF-Token": csrf})
        second = client.post(f"/courses/{ids['my_course']}/attendance-sessions",
                             json=body, headers={"X-CSRF-Token": csrf})
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert first.status_code == 200
    assert second.status_code == 409


def test_teacher_courses_page_passes_the_attendance_windows(tmp_path):
    """受付時間帯の分数を画面に渡していること.

    JS側に直書きさせないためにサーバーから渡す．直書きすると .env で値を
    変えたときに表示だけが古くなり、教員が見ている時間帯と実際の判定がずれる．
    """
    db, _ = _fixture(tmp_path)
    try:
        response = _client(db, "T0001").get("/teacher/courses")
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 200
    assert 'data-present-before-minutes="5"' in response.text
    assert 'data-present-after-minutes="5"' in response.text
    assert 'data-late-until-minutes="20"' in response.text


def test_qr_page_restores_saved_start_time_and_scan_round(tmp_path):
    db, ids = _fixture(tmp_path)
    session_id = _add_session(db, ids["my_course"])
    sess = db.get(models.AttendanceSession, session_id)
    sess.required_scan_count = 3
    sess.scheduled_start_at = "2026-10-04T01:00:00.000Z"
    db.commit()
    try:
        response = _client(db, "T0001").get(f"/attendance-sessions/{session_id}/qr")
        assert response.status_code == 200
        assert 'id="scan-round">3回目' in response.text
        assert '2026-10-04 10:00 JST' in response.text
        assert 'id="rescan-button"' in response.text
        assert '4回目のQRを表示' in response.text
        assert db.get(models.AttendanceSession, session_id).scheduled_start_at == "2026-10-04T01:00:00.000Z"
    finally:
        app.dependency_overrides.clear()
        db.close()
