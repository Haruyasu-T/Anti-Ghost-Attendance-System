"""端末の紐付け（A-9）・レート制限（A-10）・バースト検知（A-11）のテスト．

いずれも「検知はするがブロックはしない」もの（A-9/A-11）と、
「実際に拒否する」もの（A-10）が混ざっているので、そこを取り違えないよう
正常系の対照テストも置いている。
"""

from datetime import datetime, timedelta, timezone

import pytest

from app import config, security

models = pytest.importorskip("app.models", reason="app/models.py が未実装")

_MISSING = [
    name
    for name in ("Base", "create_db_engine", "User", "Course", "Enrollment",
                 "AttendanceSession", "AttendanceScan", "DeviceBinding", "AuditLog")
    if not hasattr(models, name)
]

pytestmark = pytest.mark.skipif(
    bool(_MISSING),
    reason="models.py が未完成のためスキップ: " + ", ".join(_MISSING),
)

NOW_ISO = "2026-07-27T01:00:00Z"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def db():
    from sqlalchemy.orm import Session

    engine = models.create_db_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture
def students(db):
    users = []
    for i in range(1, 5):
        u = models.User(
            login_id=f"S000{i}", role="student",
            display_name=f"学生{i}", password_hash="dummy-hash",
        )
        db.add(u)
        users.append(u)
    db.flush()
    return users


@pytest.fixture
def att_session(db, students):
    teacher = models.User(login_id="T0001", role="teacher",
                          display_name="教員A", password_hash="dummy-hash")
    db.add(teacher)
    db.flush()

    course = models.Course(name="情報セキュリティ", teacher_id=teacher.id)
    db.add(course)
    db.flush()

    s = models.AttendanceSession(
        course_id=course.id,
        scheduled_start_at=NOW_ISO,
        started_at=NOW_ISO,
        status="open",
        required_scan_count=1,
        token_salt="dummy-salt",
        created_by=teacher.id,
    )
    db.add(s)
    db.flush()
    return s


# ================================================ A-9. 端末の紐付け


def test_new_device_is_registered(db, students):
    result = security.check_device_binding(db, "device-A", students[0].id)
    db.flush()

    assert result is security.DeviceCheckResult.OK
    binding = db.get(models.DeviceBinding, "device-A")
    assert binding is not None
    assert binding.user_id == students[0].id


def test_same_user_reusing_device_is_ok(db, students):
    """同じ人が同じ端末を使い続けるのは当然OK（正常系の対照）."""
    security.check_device_binding(db, "device-A", students[0].id)
    db.flush()

    result = security.check_device_binding(db, "device-A", students[0].id)

    assert result is security.DeviceCheckResult.OK


def test_device_used_by_another_account_is_flagged(db, students):
    """別のアカウントが同じ端末を使ったら検知すること."""
    security.check_device_binding(db, "device-A", students[0].id)
    db.flush()

    result = security.check_device_binding(db, "device-A", students[1].id)

    assert result is security.DeviceCheckResult.CONFLICT


def test_conflicting_device_does_not_steal_the_binding(db, students):
    """衝突しても紐付けを書き換えないこと.

    書き換えを許すと、あとから来たアカウントが端末を「奪える」ことになり、
    記録として意味をなさなくなる。
    """
    security.check_device_binding(db, "device-A", students[0].id)
    db.flush()

    security.check_device_binding(db, "device-A", students[1].id)
    db.flush()

    binding = db.get(models.DeviceBinding, "device-A")
    assert binding.user_id == students[0].id


def test_missing_device_id_is_tolerated(db, students):
    """Cookieが無い端末でも例外にせず通すこと（ブロックはしない方針）."""
    assert security.check_device_binding(db, None, students[0].id) \
        is security.DeviceCheckResult.OK


def test_issue_device_id_is_unique():
    assert len({security.issue_device_id() for _ in range(50)}) == 50


# ================================================== A-10. レート制限


def _add_login_failure(db, login_id, client_ip, at):
    db.add(models.AuditLog(
        occurred_at=_iso(at), action="login", result="failure",
        attempted_login_id=login_id, client_ip=client_ip,
    ))


def test_not_limited_without_failures(db):
    assert security.is_login_rate_limited(db, "S0001", "192.168.1.10") is False


def test_not_limited_below_threshold(db):
    """閾値未満では止めないこと（正常系の対照）.

    打ち間違い程度で締め出すと、正当な利用者が使えなくなる。
    """
    now = datetime.now(timezone.utc)
    for i in range(config.get_settings().login_max_failures - 1):
        _add_login_failure(db, "S0001", "192.168.1.10", now - timedelta(seconds=i))
    db.flush()

    assert security.is_login_rate_limited(db, "S0001", "192.168.1.10") is False


def test_limited_after_threshold_by_login_id(db):
    now = datetime.now(timezone.utc)
    for i in range(config.get_settings().login_max_failures):
        _add_login_failure(db, "S0001", f"203.0.113.{i}", now - timedelta(seconds=i))
    db.flush()

    # IPはばらばらでも、同じIDを狙い続けていれば止まる
    assert security.is_login_rate_limited(db, "S0001", "203.0.113.99") is True


def test_limited_after_threshold_by_client_ip(db):
    now = datetime.now(timezone.utc)
    for i in range(config.get_settings().login_max_failures):
        _add_login_failure(db, f"S000{i}", "203.0.113.5", now - timedelta(seconds=i))
    db.flush()

    # IDを変えながら総当たりしても、同じIPからなら止まる
    assert security.is_login_rate_limited(db, "S9999", "203.0.113.5") is True


def test_other_user_is_not_affected(db):
    """巻き添えで別の利用者を止めないこと."""
    now = datetime.now(timezone.utc)
    for i in range(config.get_settings().login_max_failures):
        _add_login_failure(db, "S0001", "203.0.113.5", now - timedelta(seconds=i))
    db.flush()

    assert security.is_login_rate_limited(db, "S0002", "192.168.1.10") is False


def test_lock_expires_after_lockout_period(db):
    """最後の失敗から一定時間が経てば解除されること."""
    settings = config.get_settings()
    long_ago = datetime.now(timezone.utc) - timedelta(
        minutes=settings.login_lockout_minutes + 1
    )
    for i in range(settings.login_max_failures):
        _add_login_failure(db, "S0001", "203.0.113.5", long_ago - timedelta(seconds=i))
    db.flush()

    assert security.is_login_rate_limited(db, "S0001", "203.0.113.5") is False


def test_successful_logins_are_not_counted(db):
    """成功したログインを失敗として数えないこと."""
    now = datetime.now(timezone.utc)
    for i in range(config.get_settings().login_max_failures + 3):
        db.add(models.AuditLog(
            occurred_at=_iso(now - timedelta(seconds=i)),
            action="login", result="success",
            attempted_login_id="S0001", client_ip="192.168.1.10",
        ))
    db.flush()

    assert security.is_login_rate_limited(db, "S0001", "192.168.1.10") is False


# ================================================== A-11. バースト検知


def _add_scan(db, att_session, user, device_id, client_ip, at):
    db.add(models.AttendanceScan(
        attendance_session_id=att_session.id,
        user_id=user.id,
        scan_seq=1,
        scanned_at=_iso(at),
        client_ip=client_ip,
        device_id=device_id,
    ))


def test_burst_detected_when_one_device_registers_many_people(db, students, att_session):
    """1台の端末で複数人分の登録があったら検知すること（アカウント貸与の兆候）."""
    now = datetime.now(timezone.utc)
    threshold = config.get_settings().burst_threshold_count
    for i in range(threshold):
        _add_scan(db, att_session, students[i], "device-A", "192.168.1.10",
                  now - timedelta(seconds=i))
    db.flush()

    assert security.detect_burst(db, att_session.id, device_id="device-A") is True


def test_same_person_scanning_many_times_is_not_a_burst(db, students, att_session):
    """同じ人が何度読んでも検知しないこと.

    1回目と2回目以降（在室確認）は正常な動作。**件数ではなく人数**で
    数えていることの確認なので、閾値を超える回数を1人で読ませる。
    """
    now = datetime.now(timezone.utc)
    # 閾値より多い回数を「1人で」読む
    for seq in range(1, config.get_settings().burst_threshold_count + 2):
        db.add(models.AttendanceScan(
            attendance_session_id=att_session.id,
            user_id=students[0].id,
            scan_seq=seq,
            scanned_at=_iso(now),
            client_ip="192.168.1.10",
            device_id="device-A",
        ))
    db.flush()

    assert security.detect_burst(db, att_session.id, device_id="device-A") is False


def test_burst_ignores_old_scans(db, students, att_session):
    """集計期間より古い読み取りは数えないこと."""
    settings = config.get_settings()
    long_ago = datetime.now(timezone.utc) - timedelta(
        seconds=settings.burst_window_seconds + 60
    )
    for i in range(settings.burst_threshold_count):
        _add_scan(db, att_session, students[i], "device-A", "192.168.1.10",
                  long_ago - timedelta(seconds=i))
    db.flush()

    assert security.detect_burst(db, att_session.id, device_id="device-A") is False


def test_burst_is_scoped_to_the_session(db, students, att_session):
    """別のセッションの読み取りを巻き込まないこと."""
    now = datetime.now(timezone.utc)
    threshold = config.get_settings().burst_threshold_count
    for i in range(threshold):
        _add_scan(db, att_session, students[i], "device-A", "192.168.1.10",
                  now - timedelta(seconds=i))
    db.flush()

    other_session_id = att_session.id + 999
    assert security.detect_burst(db, other_session_id, device_id="device-A") is False


def test_burst_by_ip(db, students, att_session):
    """IPでも検知できること.

    ただし外部にデプロイすると学内の学生は全員が同じ出口IPになるため、
    実運用ではほぼ機能しない。判定の主役は device_id 側。
    """
    now = datetime.now(timezone.utc)
    threshold = config.get_settings().burst_threshold_count
    for i in range(threshold):
        _add_scan(db, att_session, students[i], f"device-{i}", "192.168.1.10",
                  now - timedelta(seconds=i))
    db.flush()

    assert security.detect_burst(db, att_session.id, client_ip="192.168.1.10") is True


def test_no_burst_without_identifiers(db, att_session):
    assert security.detect_burst(db, att_session.id) is False
