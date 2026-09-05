from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import security
from app.db import get_db
from app.main import app, require_teacher
from app.models import AttendanceSession, Base, Course, User


def _test_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine)


def test_courses_returns_only_signed_in_teachers_courses():
    db = _test_session()
    db.add_all([
        Course(name="情報セキュリティ", teacher_id=10),
        Course(name="ネットワーク基礎", teacher_id=10),
        Course(name="他教員の授業", teacher_id=20),
    ])
    db.commit()

    app.dependency_overrides[require_teacher] = lambda: SimpleNamespace(
        id=10, role="teacher", display_name="担当教員"
    )
    app.dependency_overrides[get_db] = lambda: db
    try:
        response = TestClient(app).get("/courses")
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 200
    assert response.json() == [
        {"id": 2, "name": "ネットワーク基礎"},
        {"id": 1, "name": "情報セキュリティ"},
    ]


def test_courses_includes_only_each_courses_open_session():
    db = _test_session()
    own_course = Course(name="情報セキュリティ", teacher_id=10)
    other_course = Course(name="他教員の授業", teacher_id=20)
    db.add_all([own_course, other_course])
    db.flush()
    own_course_id = own_course.id
    session_values = {
        "scheduled_start_at": "2026-09-05T01:00:00.000Z",
        "started_at": "2026-09-05T01:00:00.000Z",
        "required_scan_count": 1,
        "token_salt": "test-salt",
    }
    db.add_all([
        AttendanceSession(
            course_id=own_course.id, status="closed", closed_at="2026-09-05T02:00:00.000Z",
            created_by=10, **session_values,
        ),
        AttendanceSession(
            course_id=own_course.id, status="open", created_by=10, **session_values,
        ),
        AttendanceSession(
            course_id=other_course.id, status="open", created_by=20, **session_values,
        ),
    ])
    db.commit()

    app.dependency_overrides[require_teacher] = lambda: SimpleNamespace(
        id=10, role="teacher", display_name="担当教員"
    )
    app.dependency_overrides[get_db] = lambda: db
    try:
        response = TestClient(app).get("/courses")
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 200
    assert response.json() == [{
        "id": own_course_id,
        "name": "情報セキュリティ",
        "open_session": {"id": 2, "status": "open"},
    }]


def test_closed_sessions_do_not_look_open():
    """終了したセッションしかない授業では open_session を返さないこと.

    変異テストで見つかった穴を塞ぐもの。上のテストは開催中（id=2）が
    終了済み（id=1）より新しいので、`status == "open"` の絞り込みを外しても
    id の降順で開催中が先に来て、結果が変わらず素通りしてしまう。

    実際に困るのはこの形。授業を終了した直後は開催中が1つも無く、絞り込みが
    効いていないと終了済みのセッションを「開催中」として返す。画面のカードに
    「開催中のセッションあり」と出て、終了済みのQR画面へのリンクが並ぶ。
    """
    db = _test_session()
    course = Course(name="情報セキュリティ", teacher_id=10)
    db.add(course)
    db.flush()
    course_id = course.id
    db.add(AttendanceSession(
        course_id=course.id, status="closed", closed_at="2026-09-05T02:00:00.000Z",
        scheduled_start_at="2026-09-05T01:00:00.000Z",
        started_at="2026-09-05T01:00:00.000Z",
        required_scan_count=1, token_salt="test-salt", created_by=10,
    ))
    db.commit()

    app.dependency_overrides[require_teacher] = lambda: SimpleNamespace(
        id=10, role="teacher", display_name="担当教員"
    )
    app.dependency_overrides[get_db] = lambda: db
    try:
        response = TestClient(app).get("/courses")
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.json() == [{"id": course_id, "name": "情報セキュリティ"}]


def test_teacher_courses_view_is_available_after_login():
    app.dependency_overrides[require_teacher] = lambda: SimpleNamespace(
        id=10, role="teacher", display_name="担当教員"
    )
    try:
        response = TestClient(app).get("/teacher/courses")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "担当授業" in response.text
    assert "担当教員" in response.text


def test_teacher_courses_requires_login():
    response = TestClient(app).get("/teacher/courses")

    assert response.status_code == 401


def test_student_cannot_access_courses():
    db = _test_session()
    db.add(User(
        login_id="S0001",
        role="student",
        display_name="学生",
        password_hash=security.hash_password("student-password"),
    ))
    db.commit()

    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app, base_url="https://testserver")
    try:
        login_response = client.post(
            "/auth/login",
            json={"login_id": "S0001", "password": "student-password"},
        )
        response = client.get("/courses")
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert login_response.status_code == 200
    assert response.status_code == 403
