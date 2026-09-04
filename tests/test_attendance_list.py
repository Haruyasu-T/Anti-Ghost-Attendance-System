"""出席状況一覧（GET /attendance-sessions/{id}/attendances）のテスト.

画面（attendance-list.js）が使う値が実際に返っているかを見る．
APIとJSの受け渡しは片方だけ直しても気付けないので，ここで固定しておく．
"""

import datetime as dt

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models, security
from app.db import get_db
from app.main import app

PASSWORD = "attendance-list-password"


def _fixture(tmp_path):
    engine = models.create_db_engine(f"sqlite:///{tmp_path / 'list.db'}")
    models.Base.metadata.create_all(engine)
    db = Session(engine)

    def user(login_id, role):
        return models.User(
            login_id=login_id, role=role, display_name=f"{login_id}の氏名",
            password_hash=security.hash_password(PASSWORD),
        )

    teacher, s1, s2 = user("T0001", "teacher"), user("S0001", "student"), user("S0002", "student")
    db.add_all([teacher, s1, s2])
    db.flush()

    course = models.Course(name="情報セキュリティ", teacher_id=teacher.id)
    db.add(course)
    db.flush()
    db.add_all([
        models.Enrollment(course_id=course.id, user_id=s1.id),
        models.Enrollment(course_id=course.id, user_id=s2.id),
    ])

    now = security.to_iso(dt.datetime.now(dt.timezone.utc))
    sess = models.AttendanceSession(
        course_id=course.id,
        scheduled_start_at=now,
        started_at=now,
        status="open",
        # 2回目の読み取りを要求している状態．1回目だけの学生に警告が付く．
        required_scan_count=2,
        token_salt=security.new_token_salt(),
        created_by=teacher.id,
    )
    db.add(sess)
    db.flush()

    # S0001 は1回だけ読んだ（中抜けの疑い）。S0002 は未登録。
    db.add(models.Attendance(
        attendance_session_id=sess.id, user_id=s1.id,
        status="present", first_recorded_at=now, record_source="auto",
    ))
    db.add(models.AttendanceScan(
        attendance_session_id=sess.id, user_id=s1.id, scan_seq=1,
        scanned_at=now, client_ip="192.168.1.10",
    ))
    db.commit()

    ids = {"session": sess.id, "s1": s1.id, "s2": s2.id}
    return db, ids


def _rows(db, session_id):
    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app, base_url="https://testserver")
    client.post("/auth/login", json={"login_id": "T0001", "password": PASSWORD})
    return client.get(f"/attendance-sessions/{session_id}/attendances")


def test_rows_carry_the_user_id_the_edit_button_needs(tmp_path):
    """修正ボタンの宛先になる user_id が返ること.

    PUT .../attendances/{user_id} を呼ぶのに要る。これが無いと画面の
    「修正」ボタンが宛先を持てず、手動修正API（B-7）を一度も呼べない。
    """
    db, ids = _fixture(tmp_path)
    try:
        response = _rows(db, ids["session"])
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 200
    assert {row["user_id"] for row in response.json()["rows"]} == {ids["s1"], ids["s2"]}


def test_row_shape_matches_what_the_screen_reads(tmp_path):
    """attendance-list.js が読む値が全部揃っていること."""
    db, ids = _fixture(tmp_path)
    try:
        body = _rows(db, ids["session"]).json()
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert set(body["session"]) >= {"course_name", "required_scan_count"}
    for row in body["rows"]:
        assert set(row) >= {
            "user_id", "login_id", "display_name", "status", "scan_count", "alerts",
        }


def test_single_scan_is_flagged_when_a_second_round_was_requested(tmp_path):
    """再表示したのに1回しか読んでいない学生に警告が付くこと.

    中抜けの検知。自動で欠席にはせず、判断は教員に委ねる。
    """
    db, ids = _fixture(tmp_path)
    try:
        rows = {r["user_id"]: r for r in _rows(db, ids["session"]).json()["rows"]}
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert rows[ids["s1"]]["alerts"] == ["1回目のみ"]
    # 未登録の学生には付けない（読んでいないので中抜けではない）
    assert rows[ids["s2"]]["alerts"] == []
    assert rows[ids["s2"]]["status"] is None


def test_manual_correction_accepts_the_user_id_from_the_list(tmp_path):
    """一覧が返した user_id をそのまま手動修正に渡せること.

    一覧と修正で宛先の形が食い違うと、画面からは直せない。
    """
    db, ids = _fixture(tmp_path)
    try:
        app.dependency_overrides[get_db] = lambda: db
        client = TestClient(app, base_url="https://testserver")
        client.post("/auth/login", json={"login_id": "T0001", "password": PASSWORD})
        listed = client.get(f"/attendance-sessions/{ids['session']}/attendances").json()
        target = [r for r in listed["rows"] if r["status"] is None][0]

        csrf = security.csrf_token_for_session(client.cookies.get("session"))
        response = client.put(
            f"/attendance-sessions/{ids['session']}/attendances/{target['user_id']}",
            json={"status": "present", "reason": "読み取り不良を口頭で確認した"},
            headers={"X-CSRF-Token": csrf},
        )
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 200
