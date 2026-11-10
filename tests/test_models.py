# SPDX-FileCopyrightText: 2026 田中晴康
# SPDX-License-Identifier: Apache-2.0

"""models.py（B-1）の契約テスト．

実装より先に「**DBが何を拒否しなければならないか**」を定義する．
アプリのロジックが漏れても最後の防壁が残る状態（⑤安全なデフォルト）を，
DBレベルで検証することが目的．

----------------------------------------------------------------------
B-1 に期待する契約
----------------------------------------------------------------------
`app/models.py` が以下を公開すること．

    Base                      … SQLAlchemy の declarative base
    create_db_engine(url)     … Engine を返す．**接続時に PRAGMA foreign_keys = ON**
                                `wal=True` のときは journal_mode = WAL も発行する
    User, Course, Enrollment, AttendanceSession,
    Attendance, AttendanceScan, LoginSession

各モデルの属性名は [docs/db-design.md](../docs/db-design.md) のカラム名と一致させる．

このファイルは B-1 が未実装の間は自動的にスキップされる（CIは緑のまま）．
実装が進むと自動的に有効になり，満たせていない制約があれば失敗する．

契約を変えたい場合は，**先にこのテストと db-design.md を更新してから**実装する
（[CONTRIBUTING.md](../CONTRIBUTING.md) の取り決め）．
"""

import pytest
from sqlalchemy.exc import IntegrityError, OperationalError

models = pytest.importorskip("app.models", reason="app/models.py が未実装")

_REQUIRED = (
    "Base",
    "create_db_engine",
    "User",
    "Course",
    "Enrollment",
    "AttendanceSession",
    "Attendance",
    "AttendanceScan",
    "LoginSession",
)
_missing = [name for name in _REQUIRED if not hasattr(models, name)]

pytestmark = pytest.mark.skipif(
    bool(_missing),
    reason="B-1（models.py）未実装のためスキップ: " + ", ".join(_missing),
)


def _require_columns(model, *columns):
    """モデルに必要なカラムが揃っているか確認する."""
    missing = [c for c in columns if not hasattr(model, c)]
    assert not missing, (
        f"{model.__name__} に必要なカラムがありません: {', '.join(missing)}"
    )


# 時刻カラムは db-design.md の通り「UTCのISO 8601文字列」を前提にしている．
# B が SQLAlchemy の DateTime 型でモデリングした場合は，ここを datetime に変える．
NOW = "2026-07-27T01:00:00.000Z"


# ---------------------------------------------------------------- fixtures

@pytest.fixture
def session():
    """テストごとに独立したインメモリDBのセッションを返す."""
    from sqlalchemy.orm import Session

    engine = models.create_db_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def fixture_data(session):
    """教員1名・学生2名・授業1つ・履修・出席セッション1つを作る."""
    teacher = models.User(
        login_id="T0001", role="teacher",
        display_name="教員A", password_hash="dummy-hash",
    )
    student = models.User(
        login_id="S0001", role="student",
        display_name="学生A", password_hash="dummy-hash",
    )
    other_student = models.User(
        login_id="S0002", role="student",
        display_name="学生B", password_hash="dummy-hash",
    )
    session.add_all([teacher, student, other_student])
    session.flush()

    course = models.Course(name="情報セキュリティ", teacher_id=teacher.id)
    session.add(course)
    session.flush()

    session.add(models.Enrollment(course_id=course.id, user_id=student.id))

    att_session = models.AttendanceSession(
        course_id=course.id,
        scheduled_start_at=NOW,
        started_at=NOW,
        status="open",
        required_scan_count=1,
        token_salt="dummy-salt",
        created_by=teacher.id,
    )
    session.add(att_session)
    session.flush()

    return {
        "teacher": teacher,
        "student": student,
        "other_student": other_student,
        "course": course,
        "att_session": att_session,
    }


# ------------------------------------------------- 外部キーが効いているか

def test_foreign_keys_are_enforced(session):
    """SQLiteは外部キーがデフォルト無効．PRAGMAを有効にし忘れていないか確認する.

    これを忘れると REFERENCES が飾りになり，存在しないユーザーの出席記録などが
    作れてしまう．B-1で最も見落とされやすい箇所．
    """
    session.add(models.Course(name="存在しない教員の授業", teacher_id=99999))

    with pytest.raises((IntegrityError, OperationalError)):
        session.flush()


# ------------------------------------------------- WALモードの切り替え

def _journal_mode(engine) -> str:
    with engine.connect() as conn:
        return conn.exec_driver_sql("PRAGMA journal_mode").scalar().lower()


def test_journal_mode_is_not_wal_by_default(tmp_path):
    """既定ではWALにしないこと.

    WALは同時アクセスが詰まったときの手当てで，実地テストで素の挙動を
    測る前に入れてしまうと測定の意味がなくなる（`app/config.py` 参照）．
    """
    engine = models.create_db_engine(f"sqlite:///{tmp_path / 'default.db'}")
    assert _journal_mode(engine) == "delete"


def test_journal_mode_is_wal_when_requested(tmp_path):
    """`wal=True` でWALになること（当日これだけで切り替えられる必要がある）."""
    engine = models.create_db_engine(f"sqlite:///{tmp_path / 'wal.db'}", wal=True)
    assert _journal_mode(engine) == "wal"


def test_foreign_keys_still_on_in_wal_mode(tmp_path):
    """WALにしても外部キーの有効化が消えないこと.

    PRAGMAを2つ並べたので，片方を書き足したときにもう片方を壊していないかを見る．
    """
    engine = models.create_db_engine(f"sqlite:///{tmp_path / 'wal_fk.db'}", wal=True)
    models.Base.metadata.create_all(engine)

    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1


# ------------------------------------------------------- 二重出席の防止

def test_duplicate_attendance_is_rejected(session, fixture_data):
    """同一セッション×同一学生で2行目を作れないこと（二重出席防止の最終防壁）."""
    for _ in range(2):
        session.add(models.Attendance(
            attendance_session_id=fixture_data["att_session"].id,
            user_id=fixture_data["student"].id,
            status="present",
            record_source="auto",
            first_recorded_at=NOW,
        ))

    with pytest.raises(IntegrityError):
        session.flush()


def test_different_students_can_attend_the_same_session(session, fixture_data):
    """一意制約が強すぎないことの確認（別の学生は当然登録できる）."""
    for user in (fixture_data["student"], fixture_data["other_student"]):
        session.add(models.Attendance(
            attendance_session_id=fixture_data["att_session"].id,
            user_id=user.id,
            status="present",
            record_source="auto",
            first_recorded_at=NOW,
        ))

    session.flush()  # 例外が出なければ成功


# --------------------------------------------- 読み取り回数の一意性

def test_duplicate_scan_seq_is_rejected(session, fixture_data):
    """同じ回（scan_seq）の読み取りを二重に登録できないこと."""
    for _ in range(2):
        session.add(models.AttendanceScan(
            attendance_session_id=fixture_data["att_session"].id,
            user_id=fixture_data["student"].id,
            scan_seq=1,
            scanned_at=NOW,
            client_ip="192.168.1.10",
        ))

    with pytest.raises(IntegrityError):
        session.flush()


def test_multiple_scans_with_different_seq_are_allowed(session, fixture_data):
    """1回目と2回目の読み取りは両方記録できること.

    attendances に一意制約を張りつつ複数回の読み取りを記録できることが，
    テーブルを2つに分けた理由（db-design.md 設計判断2）．
    """
    for seq in (1, 2):
        session.add(models.AttendanceScan(
            attendance_session_id=fixture_data["att_session"].id,
            user_id=fixture_data["student"].id,
            scan_seq=seq,
            scanned_at=NOW,
            client_ip="192.168.1.10",
        ))

    session.flush()  # 例外が出なければ成功


# ------------------------------------------------------- CHECK 制約

def test_invalid_role_is_rejected(session):
    """role は student / teacher / admin のみ．アプリ側の検証を抜けても入らないこと.

    以前はこのテストで `admin` を「不正な値」の例に使っていたが，管理者を
    足したので正当な値になった（decisions.md D-17）．ロールを増やしたときは
    このテストの例も更新すること．
    """
    session.add(models.User(
        login_id="X0001", role="superuser",
        display_name="不正なロール", password_hash="dummy-hash",
    ))

    with pytest.raises(IntegrityError):
        session.flush()


def test_admin_role_is_allowed(session):
    """admin は正当なロールとして入ること."""
    session.add(models.User(
        login_id="A9999", role="admin",
        display_name="管理者", password_hash="dummy-hash",
    ))
    session.flush()

    assert session.query(models.User).filter_by(login_id="A9999").count() == 1


def test_invalid_attendance_status_is_rejected(session, fixture_data):
    """出席区分は present / late / absent のみ."""
    session.add(models.Attendance(
        attendance_session_id=fixture_data["att_session"].id,
        user_id=fixture_data["student"].id,
        status="maybe",
        record_source="auto",
        first_recorded_at=NOW,
    ))

    with pytest.raises(IntegrityError):
        session.flush()


def test_invalid_record_source_is_rejected(session, fixture_data):
    """記録の出所は auto / manual のみ（自動判定と手動修正の区別を守る）."""
    session.add(models.Attendance(
        attendance_session_id=fixture_data["att_session"].id,
        user_id=fixture_data["student"].id,
        status="present",
        record_source="somehow",
        first_recorded_at=NOW,
    ))

    with pytest.raises(IntegrityError):
        session.flush()


# --------------------------------------------------------- NOT NULL

def test_token_salt_is_required(session, fixture_data):
    """token_salt が NOT NULL であること.

    塩が無いセッションを作れてしまうと，トークン導出が秘密鍵だけに依存する
    状態に戻ってしまう（decisions.md D-3）．
    """
    session.add(models.AttendanceSession(
        course_id=fixture_data["course"].id,
        scheduled_start_at=NOW,
        started_at=NOW,
        status="open",
        required_scan_count=1,
        created_by=fixture_data["teacher"].id,
        # token_salt を渡さない
    ))

    with pytest.raises(IntegrityError):
        session.flush()


# ------------------------------------------------------------ 履修

def test_duplicate_enrollment_is_rejected(session, fixture_data):
    """同じ授業に同じ学生を二重に履修登録できないこと（複合主キー）."""
    session.add(models.Enrollment(
        course_id=fixture_data["course"].id,
        user_id=fixture_data["student"].id,   # fixtureで登録済み
    ))

    with pytest.raises(IntegrityError):
        session.flush()


# -------------------------------------------- ログインセッション

def test_all_designed_tables_exist():
    """設計にあるテーブルが揃っていること.

    これらが無いと以下が実装できない：
      audit_logs         … 監査ログ・レート制限・バースト検知（A-8/A-10/A-11）
      device_bindings    … 端末の紐付け検知（A-9，アカウント貸与への対策）
      manual_corrections … 手動修正の監査（B-7．要件上の必須項目）
    """
    for name in ("AuditLog", "DeviceBinding", "ManualCorrection"):
        assert hasattr(models, name), (
            f"{name} が定義されていません（docs/db-design.md 参照）"
        )


def test_attendance_scan_records_the_device(session, fixture_data):
    """読み取りに device_id を残せること.

    これが無いと「同じ端末で複数アカウント」を検知できず、
    アカウント貸与への対策が成立しない。
    """
    _require_columns(models.AttendanceScan, "device_id")

    session.add(models.AttendanceScan(
        attendance_session_id=fixture_data["att_session"].id,
        user_id=fixture_data["student"].id,
        scan_seq=1,
        scanned_at=NOW,
        client_ip="192.168.1.10",
        device_id="device-abc",
    ))

    session.flush()


def test_attendance_scan_requires_client_ip(session, fixture_data):
    """client_ip が NOT NULL であること.

    IPが空のレコードができると、バースト検知も事後追跡もできなくなる。
    """
    session.add(models.AttendanceScan(
        attendance_session_id=fixture_data["att_session"].id,
        user_id=fixture_data["student"].id,
        scan_seq=1,
        scanned_at=NOW,
        # client_ip を渡さない
    ))

    with pytest.raises(IntegrityError):
        session.flush()


def test_login_session_can_be_revoked(session, fixture_data):
    """login_sessions に revoked_at があること.

    これが無いとセッションを失効させられず、サーバー側セッションを選んだ
    理由（教員アカウント乗っ取りへの対応）が失われる（decisions.md D-7）。
    """
    _require_columns(models.LoginSession,
                     "revoked_at", "created_at", "client_ip", "user_agent")


def test_attendance_session_records_close_time(session, fixture_data):
    """attendance_sessions に closed_at があること."""
    _require_columns(models.AttendanceSession, "closed_at")


def test_timestamp_default_matches_the_application_format(session):
    """DBが自動で入れる時刻と、アプリが入れる時刻の書式が一致すること.

    時刻の範囲検索は文字列の大小比較で行っている（固定長のUTC文字列なら
    文字列比較＝時系列比較になるため）。桁数が揺れるとこれが壊れる。

    同じ瞬間を "…:00Z" と "…:00.000Z" で表すと、'.'(0x2E) は 'Z'(0x5A) より
    小さいので後者が常に「古い」と判定される。レート制限は audit_logs を
    この比較で絞っているので、失敗が数え落とされて総当たりがすり抜ける。

    そのため「両方がISO 8601であること」では不十分で、**桁数まで一致**して
    いる必要がある。
    """
    import re

    from app import security

    session.add(models.AuditLog(action="login", result="failure"))
    session.flush()

    from_db = session.query(models.AuditLog).one().occurred_at
    from_app = security._to_iso(security._utcnow())

    pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z"
    assert re.fullmatch(pattern, from_db), f"DB側の書式が想定外: {from_db!r}"
    assert re.fullmatch(pattern, from_app), f"アプリ側の書式が想定外: {from_app!r}"
    assert len(from_db) == len(from_app)


def test_timestamp_check_constraint_rejects_wrong_format(session, fixture_data):
    """書式の違う時刻をDBが拒否すること（最後の防壁）.

    アプリ側で書式を揃えるのが本筋だが、誰かが別の書式で書き込もうとしたら
    静かに壊れるのではなく、その場で失敗してほしい。
    """
    session.add(models.AttendanceScan(
        attendance_session_id=fixture_data["att_session"].id,
        user_id=fixture_data["student"].id,
        scan_seq=1,
        scanned_at="2026-07-27 01:00:00",   # 'T' も 'Z' もミリ秒もない
        client_ip="192.168.1.10",
    ))

    with pytest.raises(IntegrityError):
        session.flush()


def test_login_session_is_keyed_by_hash(session, fixture_data):
    """login_sessions の主キーが id_hash であること.

    セッションIDそのものではなくハッシュを保存する設計（decisions.md D-7）が
    モデルに反映されているかの確認．生の値を入れるカラムがあってはいけない．
    """
    assert not hasattr(models.LoginSession, "id"), (
        "login_sessions に生のセッションIDを保存するカラムがある．"
        "id_hash（SHA-256）のみを保存すること"
    )

    session.add(models.LoginSession(
        id_hash="a" * 64,
        user_id=fixture_data["student"].id,
        last_used_at=NOW,
        expires_at="2026-07-28T01:00:00.000Z",
    ))

    session.flush()  # 例外が出なければ成功
