"""出席登録のレート制限（A-10）をエンドポイント越しに固定する.

判定そのものの単体テストは tests/test_detection.py にある．ここで見るのは
アプリに繋いだときの振る舞いで，要点は次の2つ．

1. **待てば必ず解除される**
   弾いた試行を "attendance_register" の失敗として記録すると，それ自体が
   次のロックを延ばし，待っても永久に解除されない状態になる．
   記録する `action` を分けている理由がこれで，戻すとここが落ちる．

2. **巻き添えで他の学生を止めない**
   学内Wi-Fiでは全員が同じ出口IPで届くので，IPで数えた瞬間に教室全員が
   登録できなくなる．本人（`actor_user_id`）で数えていることを固定する．

どちらも「止められない」より「止めすぎる」方が高くつく場面．
誤って弾くと，授業に出ている学生が欠席として残る．
"""

import datetime as dt

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models, security
from app.db import get_db
from app.main import app

PASSWORD = "rate-limit-password"
CAMPUS = ("192.168.1.10", 5000)  # conftest の CAMPUS_IP_RANGES に含まれる
BAD_TOKEN = "deadbeefdeadbeef"

# 既定（10回）のままだと試行回数ぶんリクエストが必要になるので，
# テスト中だけ小さくする．閾値そのものの意味は test_detection.py 側で見ている．
MAX_FAILURES = 3
LOCKOUT_MINUTES = 2


def _fixture(tmp_path, monkeypatch):
    """アプリ本体のエンジンをテスト用DBに向ける.

    拒否の経路は監査ログを**独立した接続**で書くため，`get_db` だけを
    差し替えると監査ログが本来のDBに書かれてしまう
    （tests/test_attendance_reject_reasons.py と同じ事情）．
    """
    from app import config, db as db_module

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'rate.db'}")
    monkeypatch.setenv("ATTENDANCE_MAX_FAILURES", str(MAX_FAILURES))
    monkeypatch.setenv("ATTENDANCE_WINDOW_MINUTES", "5")
    monkeypatch.setenv("ATTENDANCE_LOCKOUT_MINUTES", str(LOCKOUT_MINUTES))
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

    teacher = user("T0001", "teacher")
    first, second = user("S0001", "student"), user("S0002", "student")
    db.add_all([teacher, first, second])
    db.flush()

    course = models.Course(name="情報セキュリティ", teacher_id=teacher.id)
    db.add(course)
    db.flush()
    for student in (first, second):
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

    ids = {"session": sess.id, "salt": sess.token_salt, "first": first.id}
    db.commit()
    return db, ids


def _reset_engine():
    from app import db as db_module

    db_module.get_engine.cache_clear()
    db_module.get_session_factory.cache_clear()


def _signed_in(db, login_id):
    """ログインを1回だけ済ませた client と CSRFトークンを返す.

    ログインセッションの行を `db.commit()` で確定させておく．`get_db` を
    差し替えているぶん本来のコミットが走らないので、確定させないと最初の
    拒否（`db.rollback()`）でログイン自体が巻き戻り、2回目以降が401になる。
    """
    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app, base_url="https://testserver", client=CAMPUS)
    client.post("/auth/login", json={"login_id": login_id, "password": PASSWORD})
    db.commit()
    return client, security.csrf_token_for_session(client.cookies.get("session"))


def _register(client, csrf, ids, token):
    return client.post(
        "/attendances",
        json={"attendance_session_id": ids["session"], "token": token},
        headers={"X-CSRF-Token": csrf},
    )


def _fail_until_blocked(client, csrf, ids):
    """閾値まで失敗させ，次の1回（弾かれるはずの応答）を返す."""
    for _ in range(MAX_FAILURES):
        _register(client, csrf, ids, BAD_TOKEN)
    return _register(client, csrf, ids, BAD_TOKEN)


def _count(db, action):
    db.rollback()  # 別接続がコミットした記録を見るため
    return (
        db.query(models.AuditLog)
        .filter(models.AuditLog.action == action,
                models.AuditLog.result == "failure")
        .count()
    )


def _backdate(db, action, minutes):
    """記録を過去にずらす（時間が経った状態を作る）."""
    db.rollback()
    rows = db.query(models.AuditLog).filter(models.AuditLog.action == action).all()
    for row in rows:
        row.occurred_at = security.to_iso(
            security.from_iso(row.occurred_at) - dt.timedelta(minutes=minutes)
        )
    db.commit()


def test_repeated_failures_are_rejected_with_429(tmp_path, monkeypatch):
    db, ids = _fixture(tmp_path, monkeypatch)
    try:
        client, csrf = _signed_in(db, "S0001")
        blocked = _fail_until_blocked(client, csrf, ids)
    finally:
        app.dependency_overrides.clear()
        db.close()
        _reset_engine()

    assert blocked.status_code == 429
    # 画面（scan.js）は detail をそのまま学生に見せる
    assert "待って" in blocked.json()["detail"]


def test_blocked_attempts_are_audited(tmp_path, monkeypatch):
    """弾いたことも記録すること.

    「総当たりを受けていたが止めた」が後から追えないと，攻撃の記録として
    使えない（⑥追跡可能性）．実地テストの報告書もここを見る．
    """
    db, ids = _fixture(tmp_path, monkeypatch)
    try:
        client, csrf = _signed_in(db, "S0001")
        _fail_until_blocked(client, csrf, ids)
        rejected = _count(db, security.RATE_LIMITED_ACTION)
    finally:
        app.dependency_overrides.clear()
        db.close()
        _reset_engine()

    assert rejected == 1


def test_blocked_attempts_are_audited_only_once(tmp_path, monkeypatch):
    """連打されても記録は1件に留めること.

    弾くたびに書くと，1リクエスト＝1行で audit_logs が増え続ける．
    **記録を残す仕組みを記録で溢れさせられる**ので、制限をかけた意味が半分
    無くなる。攻撃の有無は1行あれば判断できるので、行数の上限を取った（D-22）。
    """
    db, ids = _fixture(tmp_path, monkeypatch)
    try:
        client, csrf = _signed_in(db, "S0001")
        _fail_until_blocked(client, csrf, ids)
        for _ in range(5):
            assert _register(client, csrf, ids, BAD_TOKEN).status_code == 429
        rejected = _count(db, security.RATE_LIMITED_ACTION)
    finally:
        app.dependency_overrides.clear()
        db.close()
        _reset_engine()

    assert rejected == 1


def test_the_block_does_not_extend_itself(tmp_path, monkeypatch):
    """弾かれ続けても，ロック期間が過ぎれば解除されること.

    弾いた試行を "attendance_register" の失敗として書くと，連打している
    あいだロックが延び続け，授業が終わるまで登録できなくなる．
    """
    db, ids = _fixture(tmp_path, monkeypatch)
    try:
        client, csrf = _signed_in(db, "S0001")
        _fail_until_blocked(client, csrf, ids)

        # 弾かれた記録を直前のまま残し，本来数える失敗だけを過去にずらす．
        # 弾かれた記録まで数えていれば、ここでまだ 429 が返る．
        _backdate(db, "attendance_register", LOCKOUT_MINUTES + 1)
        after_waiting = _register(client, csrf, ids, BAD_TOKEN)
    finally:
        app.dependency_overrides.clear()
        db.close()
        _reset_engine()

    # 解除されているので，トークンが不正であることを理由に 403 まで進む
    assert after_waiting.status_code == 403


def test_another_student_is_not_blocked(tmp_path, monkeypatch):
    """同じ授業・同じIPの別の学生は止めないこと.

    学内Wi-Fi越しでは全員が同じ出口IPになる．IPで数えていると，
    この1件で教室全員が出席登録できなくなる．
    """
    db, ids = _fixture(tmp_path, monkeypatch)
    try:
        blocked_client, blocked_csrf = _signed_in(db, "S0001")
        _fail_until_blocked(blocked_client, blocked_csrf, ids)

        other_client, other_csrf = _signed_in(db, "S0002")
        token = security.generate_token(ids["session"], ids["salt"])
        accepted = _register(other_client, other_csrf, ids, token)
    finally:
        app.dependency_overrides.clear()
        db.close()
        _reset_engine()

    assert accepted.status_code == 200
    assert accepted.json()["status"] in ("present", "late")


def test_rate_limit_comes_before_token_verification(tmp_path, monkeypatch):
    """制限にかかっている間は，正しいQRでも受け付けないこと.

    トークン検証より先に見る（D-22）．順番を入れ替えると，正しいトークンを
    持っている相手には制限が効かなくなる．
    """
    db, ids = _fixture(tmp_path, monkeypatch)
    try:
        client, csrf = _signed_in(db, "S0001")
        _fail_until_blocked(client, csrf, ids)
        token = security.generate_token(ids["session"], ids["salt"])
        with_valid_token = _register(client, csrf, ids, token)
    finally:
        app.dependency_overrides.clear()
        db.close()
        _reset_engine()

    assert with_valid_token.status_code == 429
