"""出席登録を拒否したときの「理由」の返し方を固定する.

画面（scan.js）は拒否の理由をそのまま学生に見せる．サーバーが理由を
どの項目名で返すかが変わると，画面は理由を表示できなくなる．

実際にそれが起きた：画面側が `message` を読んでいたが，サーバーは `detail`
で返していたため，学外からのアクセスも期限切れのQRも同じ文言になり，
学生にも開発側にも原因が分からない状態だった。片方だけ直しても気付けない
種類の食い違いなので，ここで契約として固定する．
"""

import datetime as dt

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models, security
from app.db import get_db
from app.main import app

PASSWORD = "reject-reasons-password"
CAMPUS = ("192.168.1.10", 5000)      # conftest の CAMPUS_IP_RANGES に含まれる
OFF_CAMPUS = ("203.0.113.9", 5000)   # 含まれない


def _fixture(tmp_path, monkeypatch):
    """アプリ本体のエンジンをテスト用DBに向ける.

    拒否の経路は監査ログを**独立した接続**で書く（ロールバックで記録が
    消えないようにするため．db.py の方針）．そのため `get_db` だけを
    差し替えると，監査ログが本来のDBに書かれて外部キー違反になる．
    アプリが使うエンジンそのものをテスト用に向けて，両方を同じDBに揃える．
    """
    from app import config, db as db_module

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'reject.db'}")
    config.get_settings.cache_clear()
    db_module.get_engine.cache_clear()
    db_module.get_session_factory.cache_clear()

    engine = db_module.get_engine()
    models.Base.metadata.create_all(engine)
    db = Session(engine)

    def user(login_id, role):
        return models.User(
            login_id=login_id, role=role, display_name=f"{login_id}の氏名",
            password_hash=security.hash_password(PASSWORD),
        )

    teacher, student = user("T0001", "teacher"), user("S0001", "student")
    db.add_all([teacher, student])
    db.flush()

    course = models.Course(name="情報セキュリティ", teacher_id=teacher.id)
    db.add(course)
    db.flush()
    db.add(models.Enrollment(course_id=course.id, user_id=student.id))

    now = dt.datetime.now(dt.timezone.utc)
    sess = models.AttendanceSession(
        course_id=course.id,
        scheduled_start_at=security.to_iso(now),
        started_at=security.to_iso(now),
        status="open", required_scan_count=1,
        token_salt=security.new_token_salt(), created_by=teacher.id,
    )
    db.add(sess)
    db.flush()

    ids = {"session": sess.id, "salt": sess.token_salt}
    db.commit()
    return db, ids


def _reset_engine():
    """次のテストに影響しないよう、エンジンのキャッシュを捨てる."""
    from app import db as db_module

    db_module.get_engine.cache_clear()
    db_module.get_session_factory.cache_clear()


def _register(db, ids, *, client_ip, token):
    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app, base_url="https://testserver", client=client_ip)
    client.post("/auth/login", json={"login_id": "S0001", "password": PASSWORD})
    csrf = security.csrf_token_for_session(client.cookies.get("session"))
    return client.post(
        "/attendances",
        json={"attendance_session_id": ids["session"], "token": token},
        headers={"X-CSRF-Token": csrf},
    )


def test_off_campus_rejection_states_the_reason(tmp_path, monkeypatch):
    """学外からの登録は、理由が分かる文言で返すこと."""
    db, ids = _fixture(tmp_path, monkeypatch)
    token = security.generate_token(ids["session"], ids["salt"])
    try:
        response = _register(db, ids, client_ip=OFF_CAMPUS, token=token)
    finally:
        app.dependency_overrides.clear()
        db.close()
        _reset_engine()

    assert response.status_code == 403
    assert response.json()["detail"] == "学内ネットワークからアクセスしてください"


def test_bad_token_rejection_states_the_reason(tmp_path, monkeypatch):
    """学内からでも、QRが無効なら別の文言で返すこと.

    学外拒否と同じ文言になっていると、学生は何をすればよいか分からない。
    """
    db, ids = _fixture(tmp_path, monkeypatch)
    try:
        response = _register(db, ids, client_ip=CAMPUS, token="deadbeefdeadbeef")
    finally:
        app.dependency_overrides.clear()
        db.close()
        _reset_engine()

    assert response.status_code == 403
    assert response.json()["detail"] == "QRを読み取れませんでした。もう一度読み取ってください"


def test_the_two_reasons_are_not_interchangeable(tmp_path, monkeypatch):
    """2つの拒否が同じ文言にならないこと.

    どちらも403なので、文言が同じだと画面からは区別できない。
    実機テストのたびに原因の切り分けができなくなる。
    """
    db, ids = _fixture(tmp_path, monkeypatch)
    token = security.generate_token(ids["session"], ids["salt"])
    try:
        off_campus = _register(db, ids, client_ip=OFF_CAMPUS, token=token)
        bad_token = _register(db, ids, client_ip=CAMPUS, token="deadbeefdeadbeef")
    finally:
        app.dependency_overrides.clear()
        db.close()
        _reset_engine()

    assert off_campus.json()["detail"] != bad_token.json()["detail"]


def test_rejection_reason_is_returned_under_the_detail_key(tmp_path, monkeypatch):
    """理由は detail という項目で返すこと.

    画面（scan.js）がこの名前を読んでいる。別の名前に変えると、
    画面は理由を表示できず汎用の文言に落ちる。
    """
    db, ids = _fixture(tmp_path, monkeypatch)
    try:
        body = _register(db, ids, client_ip=OFF_CAMPUS, token="x").json()
    finally:
        app.dependency_overrides.clear()
        db.close()
        _reset_engine()

    assert "detail" in body
    assert isinstance(body["detail"], str) and body["detail"]
