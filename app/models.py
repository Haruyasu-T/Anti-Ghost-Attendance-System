"""app/models.py（B-1）

出席管理システムのデータモデル定義．

設計方針
----------------------------------------------------------------------
- アプリ側のバリデーションが漏れても最後の防壁として機能するよう，
  可能な制約はすべて DB レベル（NOT NULL / CHECK / UNIQUE / FOREIGN KEY）
  で表現する（⑤安全なデフォルト）．
- SQLite は接続ごとに `PRAGMA foreign_keys = ON` を発行しないと外部キー制約が
  無効化されたままになるため，`create_db_engine()` で接続時に必ず有効化する．
- 時刻カラムは UTC の ISO 8601 文字列（例: "2026-07-27T01:00:00Z"）として
  保存する．タイムゾーン変換や比較演算はアプリ層の責務とし，DB 層では文字列
  として素直に保持する．
- ログインセッションは生のセッションIDを保存せず，SHA-256 等でハッシュ化した
  `id_hash` のみを主キーとして保存する（漏洩時の被害を限定するため）．
"""

from __future__ import annotations

from sqlalchemy import (
    CheckConstraint,
    Column,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    event,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def create_db_engine(url: str, **kwargs) -> Engine:
    """Engine を作成する．

    SQLite の場合，接続の都度 `PRAGMA foreign_keys = ON` を発行し，
    外部キー制約を有効化する（SQLite はデフォルトで無効なため）．
    """
    engine = create_engine(url, **kwargs)

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, connection_record):  # noqa: ANN001
        # SQLite 以外のドライバでは PRAGMA が存在しないため，
        # sqlite3 コネクションの場合のみ実行する．
        if type(dbapi_connection).__module__.startswith("sqlite3"):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys = ON")
            cursor.close()

    return engine


# ---------------------------------------------------------------- User

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    login_id = Column(String, nullable=False, unique=True)
    role = Column(String, nullable=False)
    display_name = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)

    __table_args__ = (
        CheckConstraint("role IN ('student', 'teacher')",
                        name="ck_users_role"),
    )


# -------------------------------------------------------------- Course

class Course(Base):
    __tablename__ = "courses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    teacher_id = Column(Integer, ForeignKey("users.id"), nullable=False)


# ---------------------------------------------------------- Enrollment

class Enrollment(Base):
    __tablename__ = "enrollments"

    course_id = Column(Integer, ForeignKey("courses.id"), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)


# ------------------------------------------------------ AttendanceSession

class AttendanceSession(Base):
    __tablename__ = "attendance_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    course_id = Column(Integer, ForeignKey("courses.id"), nullable=False)
    scheduled_start_at = Column(String, nullable=False)
    started_at = Column(String, nullable=True)
    status = Column(String, nullable=False)
    required_scan_count = Column(Integer, nullable=False)
    # トークン導出を秘密鍵だけに依存させないための塩．NOT NULL 必須（decisions.md D-3）．
    token_salt = Column(String, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "status IN ('scheduled', 'open', 'closed')",
            name="ck_attendance_sessions_status",
        ),
    )


# ------------------------------------------------------------ Attendance

class Attendance(Base):
    """確定した出席記録．1セッション×1学生につき1行のみ（最終的な出席状況）．"""

    __tablename__ = "attendances"

    id = Column(Integer, primary_key=True, autoincrement=True)
    attendance_session_id = Column(
        Integer, ForeignKey("attendance_sessions.id"), nullable=False
    )
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(String, nullable=False)
    record_source = Column(String, nullable=False)
    first_recorded_at = Column(String, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "attendance_session_id", "user_id", name="uq_attendances_session_user"
        ),
        CheckConstraint(
            "status IN ('present', 'late', 'absent')",
            name="ck_attendances_status",
        ),
        CheckConstraint(
            "record_source IN ('auto', 'manual')",
            name="ck_attendances_record_source",
        ),
    )


# -------------------------------------------------------- AttendanceScan

class AttendanceScan(Base):
    """個々の読み取り（スキャン）ログ．1セッション×1学生につき複数回記録できる．

    attendances に一意制約を張りつつ複数回の読み取りを記録できるようにするため，
    読み取りログを別テーブルに分離している（db-design.md 設計判断2）．
    """

    __tablename__ = "attendance_scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    attendance_session_id = Column(
        Integer, ForeignKey("attendance_sessions.id"), nullable=False
    )
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scan_seq = Column(Integer, nullable=False)
    scanned_at = Column(String, nullable=False)
    client_ip = Column(String, nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "attendance_session_id",
            "user_id",
            "scan_seq",
            name="uq_attendance_scans_session_user_seq",
        ),
    )


# ----------------------------------------------------------- LoginSession

class LoginSession(Base):
    """ログインセッション．

    生のセッションIDは保存せず，ハッシュ値（例: SHA-256, 64文字hex）のみを
    主キーとして保存する（decisions.md D-7）．`id` カラムは意図的に持たない．
    """

    __tablename__ = "login_sessions"

    id_hash = Column(String, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    last_used_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False)
