# SPDX-FileCopyrightText: 2026 田中晴康
# SPDX-License-Identifier: Apache-2.0

"""授業開始時刻の変更（PUT /attendance-sessions/{id}/scheduled-start）のテスト．

確認すること：

- 認可：担当外の教員は404，学生は403（どちらも値を変えず，ログも残さない）
- 状態：終了済みセッションは409
- CSRF：トークンが無い／違うと403
- 理由：必須（空・空白だけ・欠落・長すぎるものは拒否）．手動修正と同じ扱い
- 監査：変更前後の時刻・理由・実施者が `audit_logs` に残る
- 効果：開始時刻を動かすと，それまで受付時間外で弾かれていた読み取りが通る
- 方針：登録済みの出席区分は再計算しない（以後の初回登録から効く）

画面を経由せずAPIに対して書いている．画面にボタンが無いことは認可ではない
（screen-design.md）ので，認可の検証は直接APIを叩いて行う．
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app import config, models, security
from app import db as db_module
from app.main import app

CAMPUS_IP = "192.168.1.10"  # conftest の CAMPUS_IP_RANGES（192.168.0.0/16）に含まれる
ACTION = "session_start_time_update"
REASON = "開始時刻の入力ミスを訂正"


# ------------------------------------------------------------ 道具立て


@pytest.fixture
def world(monkeypatch):
    """教員2名・学生1名・授業1つ・履修関係・開催中のセッション1つを用意する.

    セッションの授業開始予定は「60分前」．受付は開始20分後までなので，
    初期状態では出席登録は受付時間外で弾かれる．
    """
    # 出席登録のテストでIPを「学内」にするために，プロキシ1段の構成にして
    # X-Forwarded-For の右端を使わせる（本番と同じ get_client_ip の経路を通す）．
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "1")
    config.get_settings.cache_clear()

    now = datetime.now(timezone.utc)
    factory = db_module.get_session_factory()
    with factory() as db:
        users = {
            "owner": models.User(login_id="T0001", role="teacher",
                                 display_name="教員A", password_hash="dummy-hash"),
            "other": models.User(login_id="T0002", role="teacher",
                                 display_name="教員B", password_hash="dummy-hash"),
            "student": models.User(login_id="S0001", role="student",
                                   display_name="学生A", password_hash="dummy-hash"),
        }
        db.add_all(users.values())
        db.flush()

        course = models.Course(name="情報セキュリティ", teacher_id=users["owner"].id)
        db.add(course)
        db.flush()
        db.add(models.Enrollment(
            course_id=course.id, user_id=users["student"].id))

        original_start = security.to_iso(now - timedelta(minutes=60))
        sess = models.AttendanceSession(
            course_id=course.id,
            scheduled_start_at=original_start,
            started_at=security.to_iso(now),
            status="open",
            required_scan_count=1,
            token_salt=security.new_token_salt(),
            created_by=users["owner"].id,
        )
        db.add(sess)
        db.flush()

        # ログインはAPI経由にしない（bcryptが遅いのと，ここの関心事ではないため）．
        raw_sessions = {
            name: security.create_login_session(db, user.id)
            for name, user in users.items()
        }
        db.commit()

        return SimpleNamespace(
            session_id=sess.id,
            salt=sess.token_salt,
            original_start=original_start,
            owner_id=users["owner"].id,
            student_id=users["student"].id,
            raw=raw_sessions,
        )


def _client(raw_session_id: str) -> TestClient:
    """指定したログインセッションのCookieを持つクライアント."""
    client = TestClient(app, headers={"X-Forwarded-For": CAMPUS_IP})
    client.cookies.set("session", raw_session_id)
    return client


def _csrf(raw_session_id: str) -> dict:
    return {"X-CSRF-Token": security.csrf_token_for_session(raw_session_id)}


def _new_start(minutes_from_now: int = 0) -> datetime:
    """送信する開始時刻．現在時刻の前後3時間以内に収まる値."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return now + timedelta(minutes=minutes_from_now)


def _put_json(client, world, body: dict, headers: dict):
    return client.put(
        f"/attendance-sessions/{world.session_id}/scheduled-start",
        json=body,
        headers=headers,
    )


def _put_start(client, world, new_start: datetime, headers: dict, reason: str = REASON):
    return _put_json(
        client, world,
        {"scheduled_start_at": new_start.isoformat(), "reason": reason},
        headers,
    )


def _stored_start(world) -> str:
    with db_module.get_session_factory()() as db:
        return db.get(models.AttendanceSession, world.session_id).scheduled_start_at


def _audit_rows(action: str = ACTION) -> list:
    with db_module.get_session_factory()() as db:
        return db.query(models.AuditLog).filter(models.AuditLog.action == action).all()


def _register(world, user: str = "student"):
    """学生として出席登録を試みる（学内IP・有効なトークン・CSRFトークン付き）."""
    raw = world.raw[user]
    token = security.generate_token(world.session_id, world.salt)
    return _client(raw).post(
        "/attendances",
        json={"attendance_session_id": world.session_id, "token": token},
        headers=_csrf(raw),
    )


def _assert_untouched(world):
    """拒否された操作が，値もログも変えていないこと."""
    assert _stored_start(world) == world.original_start
    assert _audit_rows() == []


# ------------------------------------------------------------ 認可


def test_teacher_of_another_course_gets_404(world):
    """担当外の教員は404．403にすると「そのセッションは存在する」と分かってしまう."""
    raw = world.raw["other"]

    response = _put_start(_client(raw), world, _new_start(), _csrf(raw))

    assert response.status_code == 404
    _assert_untouched(world)


def test_student_gets_403(world):
    """学生は変更できない．CSRFトークンは正しく付けて，認可で落ちることを確かめる."""
    raw = world.raw["student"]

    response = _put_start(_client(raw), world, _new_start(), _csrf(raw))

    assert response.status_code == 403
    _assert_untouched(world)


# ------------------------------------------------------------ 状態


def test_closed_session_gets_409(world):
    with db_module.get_session_factory()() as db:
        sess = db.get(models.AttendanceSession, world.session_id)
        sess.status = "closed"
        sess.closed_at = security.to_iso(datetime.now(timezone.utc))
        db.commit()
    raw = world.raw["owner"]

    response = _put_start(_client(raw), world, _new_start(), _csrf(raw))

    assert response.status_code == 409
    _assert_untouched(world)


# ------------------------------------------------------------ CSRF


@pytest.mark.parametrize("header_value", [None, "not-the-right-token"])
def test_missing_or_wrong_csrf_token_gets_403(world, header_value):
    """担当教員本人のCookieでも，CSRFトークンが無い／違うなら通らない."""
    raw = world.raw["owner"]
    headers = {} if header_value is None else {"X-CSRF-Token": header_value}

    response = _put_start(_client(raw), world, _new_start(), headers)

    assert response.status_code == 403
    _assert_untouched(world)


# ------------------------------------------------------------ 監査ログ


def test_audit_log_records_before_after_reason_and_actor(world):
    raw = world.raw["owner"]
    new_start = _new_start(minutes_from_now=-10)

    response = _put_start(_client(raw), world, new_start, _csrf(raw))

    assert response.status_code == 200
    expected_after = security.to_iso(new_start)
    assert response.json()["scheduled_start_at"] == expected_after
    assert _stored_start(world) == expected_after

    rows = _audit_rows()
    assert len(rows) == 1
    row = rows[0]
    assert row.result == "success"
    assert row.actor_user_id == world.owner_id
    assert row.target_type == "attendance_session"
    assert row.target_id == world.session_id
    assert row.detail == (
        f"before={world.original_start} after={expected_after} reason={REASON}"
    )


def test_unchanged_value_writes_no_audit_log(world):
    """同じ値での送信は何も変えず，意味のない監査ログも増やさない."""
    raw = world.raw["owner"]
    same = security.from_iso(world.original_start)

    response = _put_start(_client(raw), world, same, _csrf(raw))

    assert response.status_code == 200
    assert _stored_start(world) == world.original_start
    assert _audit_rows() == []


# ------------------------------------------------------------ 理由（必須）


@pytest.mark.parametrize("reason", ["", "   ", "\n\t \u3000"])
def test_blank_reason_gets_400(world, reason):
    """空文字・スペースだけ（全角空白・改行含む）の理由は拒否する.

    画面の required はスペースだけの入力を通すので，サーバー側が本体．
    """
    raw = world.raw["owner"]

    response = _put_start(_client(raw), world,
                          _new_start(), _csrf(raw), reason=reason)

    assert response.status_code == 400
    _assert_untouched(world)


def test_missing_reason_is_rejected(world):
    """reason を送らない（フィールドごと無い）リクエストも通らない."""
    raw = world.raw["owner"]

    response = _put_json(
        _client(raw), world,
        {"scheduled_start_at": _new_start().isoformat()},
        _csrf(raw),
    )

    assert response.status_code == 422
    _assert_untouched(world)


def test_reason_length_limit(world):
    """理由は500文字まで．監査ログの detail に入る値なので上限を置いている."""
    raw = world.raw["owner"]

    too_long = _put_start(_client(raw), world, _new_start(),
                          _csrf(raw), reason="あ" * 501)
    assert too_long.status_code == 400
    _assert_untouched(world)

    just_fits = _put_start(_client(raw), world,
                           _new_start(), _csrf(raw), reason="あ" * 500)
    assert just_fits.status_code == 200
    assert _audit_rows()[0].detail.endswith("reason=" + "あ" * 500)


def test_reason_is_stripped_before_logging(world):
    raw = world.raw["owner"]

    response = _put_start(
        _client(raw), world, _new_start(), _csrf(raw), reason="  \n" + REASON + " \u3000 "
    )

    assert response.status_code == 200
    assert _audit_rows()[0].detail.endswith(f"reason={REASON}")


# ------------------------------------------------------------ 効果


def test_moving_start_time_lets_an_out_of_window_scan_through(world):
    """開始時刻を訂正すると，受付時間外で弾かれていた読み取りが通る."""
    # 変更前：開始から60分経過．受付は20分後までなので弾かれる．
    before = _register(world)
    assert before.status_code == 403
    assert before.json()["detail"] == "受付時間外です"  # 別の理由で落ちていないこと

    raw = world.raw["owner"]
    response = _put_start(_client(raw), world, _new_start(), _csrf(raw))
    assert response.status_code == 200

    # 変更後：開始時刻が「今」．受付時間帯の中なので通る．
    after = _register(world)
    assert after.status_code == 200
    assert after.json()["status"] == "present"
    assert after.json()["scan_seq"] == 1


def test_already_registered_status_is_not_recalculated(world):
    """登録済みの出席区分は，開始時刻を動かしても変わらない（D-19と同じ方針）.

    変更は以後の初回登録から効く．過去の区分を直すなら手動修正を使う．
    """
    raw_owner = world.raw["owner"]

    # 開始を「今から10分前」にして登録する → 開始5分後を過ぎているので遅刻．
    response = _put_start(_client(raw_owner), world,
                          _new_start(-10), _csrf(raw_owner))
    assert response.status_code == 200
    registered = _register(world)
    assert registered.status_code == 200
    assert registered.json()["status"] == "late"

    # 開始を「今」に動かす．やり直せば出席になる時刻だが，保存済みの区分は変えない．
    response = _put_start(_client(raw_owner), world,
                          _new_start(), _csrf(raw_owner))
    assert response.status_code == 200

    with db_module.get_session_factory()() as db:
        attendance = (
            db.query(models.Attendance)
            .filter_by(attendance_session_id=world.session_id,
                       user_id=world.student_id)
            .one()
        )
        assert attendance.status == "late"
        assert attendance.record_source == "auto"
