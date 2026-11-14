# SPDX-FileCopyrightText: 2026 田中晴康
# SPDX-License-Identifier: Apache-2.0

"""Every authenticated page must supply a working CSRF-protected logout."""

import datetime as dt
import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models, security
from app.db import get_db
from app.main import app


@pytest.mark.parametrize("role,path", [
    ("student", "/student"), ("student", "/history"), ("student", "/scan"),
    ("teacher", "/teacher/courses"),
    ("teacher", "/attendance-sessions/1/qr"),
    ("teacher", "/attendance-sessions/1/attendances/view"),
    ("admin", "/admin"),
])
def test_page_token_can_revoke_session(tmp_path, role, path):
    engine = models.create_db_engine(f"sqlite:///{tmp_path / 'logout.db'}")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        user = models.User(login_id="U0001", display_name="Test user", role=role,
                           password_hash="unused")
        db.add(user)
        db.flush()
        if role == "teacher":
            course = models.Course(name="Test course", teacher_id=user.id)
            db.add(course)
            db.flush()
            db.add(models.AttendanceSession(
                id=1, course_id=course.id, created_by=user.id,
                scheduled_start_at=security.to_iso(dt.datetime.now(dt.timezone.utc)),
                started_at=security.to_iso(dt.datetime.now(dt.timezone.utc)), token_salt="test-salt",
            ))
        raw_session = security.create_login_session(db, user.id)
        db.commit()
        app.dependency_overrides[get_db] = lambda: db
        try:
            client = TestClient(app, base_url="https://testserver")
            client.cookies.set("session", raw_session)
            response = client.get(path)
            assert response.status_code == 200
            # 属性の間は空白なら何でもよい（HTMLとして等価）ので `\s+` で受ける。
            # スペース1個に固定していたため、テンプレートの行を折り返しただけで
            # 7件まとめて落ちた。ここで見たいのは「ログアウト用のトークンが
            # ページにちょうど1つあること」で、書式ではない。
            tokens = re.findall(r'data-logout\s+data-csrf-token="([^"]+)"', response.text)
            assert len(tokens) == 1
            assert response.text.count("/static/js/common.js") == 1
            assert client.post("/auth/logout", headers={"X-CSRF-Token": tokens[0]}).status_code == 200
            assert security.get_session_user(db, raw_session) is None
        finally:
            app.dependency_overrides.clear()
    engine.dispose()
