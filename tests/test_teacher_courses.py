from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import get_db
from app.main import app, require_teacher
from app.models import Base, Course


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
