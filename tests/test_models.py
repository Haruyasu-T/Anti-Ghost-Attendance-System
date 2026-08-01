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


# 時刻カラムは db-design.md の通り「UTCのISO 8601文字列」を前提にしている．
# B が SQLAlchemy の DateTime 型でモデリングした場合は，ここを datetime に変える．
NOW = "2026-07-27T01:00:00Z"


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
    """role は student / teacher のみ．アプリ側の検証を抜けても入らないこと."""
    session.add(models.User(
        login_id="X0001", role="admin",
        display_name="不正なロール", password_hash="dummy-hash",
    ))

    with pytest.raises(IntegrityError):
        session.flush()


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
        expires_at="2026-07-28T01:00:00Z",
    ))

    session.flush()  # 例外が出なければ成功
