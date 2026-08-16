"""ログインセッション（A-6）と監査ログ（A-8）のテスト．

B-1（models.py）が揃うまでは自動でスキップされる．
必要なモデルとカラムが揃うと有効になる．
"""

from datetime import datetime, timedelta, timezone

import pytest

from app import config, security

models = pytest.importorskip("app.models", reason="app/models.py が未実装")


def _missing_pieces():
    """B-1 側で足りていないものを列挙する."""
    missing = []
    for name in ("Base", "create_db_engine", "User", "LoginSession", "AuditLog"):
        if not hasattr(models, name):
            missing.append(name)

    if hasattr(models, "LoginSession"):
        for column in ("id_hash", "revoked_at", "expires_at", "last_used_at",
                       "created_at", "client_ip", "user_agent"):
            if not hasattr(models.LoginSession, column):
                missing.append(f"LoginSession.{column}")
    return missing


_MISSING = _missing_pieces()

pytestmark = pytest.mark.skipif(
    bool(_MISSING),
    reason="B-1（models.py）が未完成のためスキップ: " + ", ".join(_MISSING),
)


@pytest.fixture
def db():
    from sqlalchemy.orm import Session

    engine = models.create_db_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture
def user(db):
    u = models.User(
        login_id="S0001", role="student",
        display_name="学生A", password_hash="dummy-hash",
    )
    db.add(u)
    db.flush()
    return u


# ============================================ A-6. ログインセッション


def test_session_can_be_created_and_resolved(db, user):
    raw_id = security.create_login_session(db, user.id, client_ip="192.168.1.10",
                                           user_agent="pytest")

    resolved = security.get_session_user(db, raw_id)

    assert resolved is not None
    assert resolved.id == user.id


def test_raw_session_id_is_not_stored(db, user):
    """DBに生のセッションIDが残っていないこと.

    ここが破られると、DBが漏れた時点で全員のセッションを乗っ取られる。
    """
    raw_id = security.create_login_session(db, user.id)

    rows = db.query(models.LoginSession).all()
    assert len(rows) == 1
    assert rows[0].id_hash != raw_id
    assert len(rows[0].id_hash) == 64  # SHA-256のhex

    # 生の値でそのまま引けてしまわないこと
    assert db.get(models.LoginSession, raw_id) is None


def test_unknown_session_id_is_rejected(db, user):
    security.create_login_session(db, user.id)

    assert security.get_session_user(db, "totally-made-up-id") is None


@pytest.mark.parametrize("value", ["", None])
def test_empty_session_id_is_rejected(db, value):
    assert security.get_session_user(db, value) is None


def test_revoked_session_is_rejected(db, user):
    """ログアウト後に同じCookieを使っても通らないこと."""
    raw_id = security.create_login_session(db, user.id)
    assert security.get_session_user(db, raw_id) is not None

    security.revoke_login_session(db, raw_id)

    assert security.get_session_user(db, raw_id) is None


def test_expired_session_is_rejected(db, user):
    raw_id = security.create_login_session(db, user.id)

    # 期限を過去に書き換える
    row = db.query(models.LoginSession).one()
    past = datetime.now(timezone.utc) - timedelta(minutes=1)
    row.expires_at = past.strftime("%Y-%m-%dT%H:%M:%SZ")

    assert security.get_session_user(db, raw_id) is None


def test_revoke_all_sessions_for_user(db, user):
    """乗っ取り対応：そのユーザーの全セッションを一度に失効させられること.

    これができることが、JWTではなくサーバー側セッションを選んだ理由
    （decisions.md D-7）。
    """
    ids = [security.create_login_session(db, user.id) for _ in range(3)]
    for raw_id in ids:
        assert security.get_session_user(db, raw_id) is not None

    revoked = security.revoke_all_sessions_for_user(db, user.id)

    assert revoked == 3
    for raw_id in ids:
        assert security.get_session_user(db, raw_id) is None


def test_revoking_one_user_does_not_affect_others(db, user):
    """一括失効が他人のセッションまで巻き込まないこと（対照）."""
    other = models.User(login_id="S0002", role="student",
                        display_name="学生B", password_hash="dummy-hash")
    db.add(other)
    db.flush()

    mine = security.create_login_session(db, user.id)
    theirs = security.create_login_session(db, other.id)

    security.revoke_all_sessions_for_user(db, user.id)

    assert security.get_session_user(db, mine) is None
    assert security.get_session_user(db, theirs) is not None


def test_session_ids_are_unique(db, user):
    ids = {security.create_login_session(db, user.id) for _ in range(20)}

    assert len(ids) == 20


# ==================================================== A-8. 監査ログ


def test_audit_log_is_written(db, user):
    security.write_audit_log(
        db, action="login", result="success",
        actor_user_id=user.id, client_ip="192.168.1.10",
    )
    db.flush()

    rows = db.query(models.AuditLog).all()
    assert len(rows) == 1
    assert rows[0].action == "login"
    assert rows[0].result == "success"


def test_audit_log_records_failed_login_without_user(db):
    """存在しないIDへのログイン失敗も記録できること（actor_user_id は NULL）."""
    security.write_audit_log(
        db, action="login", result="failure",
        attempted_login_id="S9999", client_ip="203.0.113.5",
        detail="unknown_login_id",
    )
    db.flush()

    row = db.query(models.AuditLog).one()
    assert row.actor_user_id is None
    assert row.attempted_login_id == "S9999"


def test_audit_log_rejects_invalid_result(db):
    with pytest.raises(ValueError):
        security.write_audit_log(db, action="login", result="maybe")


def test_audit_log_rejects_secret_in_detail(db):
    """秘密鍵がdetailに紛れ込んだら弾くこと.

    「ログに秘密を書かない」は約束事だが、約束事だけだと事故が起きる。
    """
    secret = config.get_settings().token_secret

    with pytest.raises(ValueError):
        security.write_audit_log(
            db, action="attendance_register", result="failure",
            detail=f"debug: secret={secret}",
        )


def test_audit_log_now_survives_rollback(user):
    """失敗経路のログが、呼び出し側のロールバックで消えないこと.

    拒否された試行こそ後から追いたい情報なので、独立したトランザクションで
    書けることを確認する。
    """
    from sqlalchemy.orm import Session, sessionmaker

    engine = models.create_db_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)

    with factory() as work_db:
        work_db.add(models.User(login_id="S0003", role="student",
                                display_name="学生C", password_hash="dummy-hash"))
        security.write_audit_log_now(
            factory, action="attendance_register", result="failure",
            client_ip="203.0.113.5", detail="off_campus",
        )
        work_db.rollback()  # 本体の処理は失敗して巻き戻る

    with factory() as check_db:
        # ユーザーの追加は消えているが、監査ログは残っている
        assert check_db.query(models.User).count() == 0
        assert check_db.query(models.AuditLog).count() == 1
