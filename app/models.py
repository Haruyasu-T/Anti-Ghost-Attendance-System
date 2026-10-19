"""

出席管理システムのデータモデル定義．

設計方針
----------------------------------------------------------------------
- アプリ側のバリデーションが漏れても最後の防壁として機能するよう，
    可能な制約はすべて DB レベル（NOT NULL / CHECK / UNIQUE / FOREIGN KEY）
    で表現する（⑤安全なデフォルト）．
- SQLite は接続ごとに `PRAGMA foreign_keys = ON` を発行しないと外部キー制約が
    無効化されたままになるため，`create_db_engine()` で接続時に必ず有効化する．
- 時刻カラムは UTC の ISO 8601 文字列（例: "2026-07-27T01:00:00.000Z"）として
    保存する．タイムゾーン変換や比較演算はアプリ層の責務とし，DB 層では文字列
    として素直に保持する．
    - DB 側で自動付与するタイムスタンプ（created_at 等）も同じ書式に揃えるため，
      `server_default` には SQLite の `datetime('now')` ではなく
      `strftime('%Y-%m-%dT%H:%M:%fZ', 'now')` を用いる
      （`datetime('now')` は "YYYY-MM-DD HH:MM:SS" 形式で ISO 8601 の `T`/`Z` を
      含まないため）．
    - アプリ層でも時刻文字列を生成する際は `Z` サフィックス付きの UTC 表現
      （例: `datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")` や
      `isoformat()` を "+00:00" → "Z" に置換したもの）に統一すること．
    - 最後の防壁として，DB レベルでも大まかな書式チェック（先頭が
      `YYYY-MM-DDTHH:MM` で末尾が `Z`）を CHECK 制約で強制する．完全な
      ISO 8601 バリデーションではないが，明らかに書式が異なる値の混入は防げる．
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
    Index
)
from sqlalchemy.engine import Engine
from sqlalchemy.sql import text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class AttendanceWindowSettings(Base):
    """全授業共通の受付時間。未保存の場合は環境変数を使う。"""
    __tablename__ = "attendance_window_settings"
    id = Column(Integer, primary_key=True)
    present_before_minutes = Column(Integer, nullable=False)
    present_after_minutes = Column(Integer, nullable=False)
    late_until_minutes = Column(Integer, nullable=False)
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_attendance_window_singleton"),
        # 受付終了が0になると全授業で誰も登録できなくなるので下限を置く（D-19）．
        # app/main.py の _LATE_UNTIL_MIN_MINUTES と同じ値にしておくこと．
        CheckConstraint("present_before_minutes >= 0 AND present_after_minutes >= 0 "
                        "AND late_until_minutes >= 5 "
                        "AND late_until_minutes >= present_after_minutes",
                        name="ck_attendance_window_minutes"),
    )


# UTC ISO 8601（"YYYY-MM-DDTHH:MM:SS.mmmZ"）の書式チェック用 SQL 断片．
#
# **桁数まで固定する**のが重要．時刻の範囲検索は文字列の大小比較で行うため
# （固定長のUTC文字列なら文字列比較＝時系列比較になる），桁数が揺れると比較が
# 壊れる．たとえば同じ瞬間を "…:00Z" と "…:00.000Z" で表すと，'.'(0x2E) は
# 'Z'(0x5A) より小さいので後者が常に「古い」と判定される．その結果，
# レート制限が失敗を数え落とし，総当たりがすり抜ける．
#
# ミリ秒3桁に統一する理由：授業開始直後は多数の登録が同じ秒に集中するため，
# 秒までだと監査ログの順序が潰れる．SQLite の strftime('%f') と揃えられる．
_ISO8601_UTC_GLOB = (
    "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]"
    "T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z"
)


def _iso8601_utc_check(column_name: str, constraint_name: str,
                       nullable: bool = False) -> CheckConstraint:
    """指定カラムに UTC ISO 8601（ミリ秒・固定長）の書式チェックを付与する．"""
    condition = f"{column_name} GLOB '{_ISO8601_UTC_GLOB}'"
    if nullable:
        condition = f"({column_name} IS NULL OR {condition})"
    return CheckConstraint(condition, name=constraint_name)


# SQLite の datetime('now') は "YYYY-MM-DD HH:MM:SS" 形式で UTC の 'T'/'Z' 表記を
# 持たないため，ISO 8601 UTC 表現（ミリ秒 + 'Z'）を生成する式に置き換える．
_UTC_NOW_ISO8601 = text("(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))")


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
    created_at = Column(String, nullable=False,
                        server_default=_UTC_NOW_ISO8601)

    __table_args__ = (
        # admin は授業と履修の管理だけを行う役割．出席記録には触れない
        # （decisions.md D-17）．ロールを増やすので，既存のDBファイルは
        # 作り直しが要る（SQLiteはCHECK制約を後から変更できない）．
        CheckConstraint("role IN ('student', 'teacher', 'admin')",
                        name="ck_users_role"),
        _iso8601_utc_check("created_at", "ck_users_created_at_iso8601"),
    )


# -------------------------------------------------------------- Course

class Course(Base):
    __tablename__ = "courses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    teacher_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(String, nullable=False,
                        server_default=_UTC_NOW_ISO8601)

    __table_args__ = (
        _iso8601_utc_check("created_at", "ck_courses_created_at_iso8601"),
    )


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
    started_at = Column(String, nullable=False)
    closed_at = Column(String)
    status = Column(String, nullable=False, default="open")
    required_scan_count = Column(Integer, nullable=False, default=1)
    # トークン導出を秘密鍵だけに依存させないための塩．NOT NULL 必須（decisions.md D-3）．
    token_salt = Column(String, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "status IN ('open', 'closed')",
            name="ck_attendance_sessions_status",
        ),
        _iso8601_utc_check(
            "scheduled_start_at", "ck_attendance_sessions_scheduled_start_at_iso8601"
        ),
        _iso8601_utc_check(
            "started_at", "ck_attendance_sessions_started_at_iso8601"
        ),
        _iso8601_utc_check(
            "closed_at", "ck_attendance_sessions_closed_at_iso8601", nullable=True
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
    record_source = Column(String, nullable=False, default="auto")
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
        _iso8601_utc_check(
            "first_recorded_at", "ck_attendances_first_recorded_at_iso8601"
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
    client_ip = Column(String, nullable=False)
    device_id = Column(String)

    __table_args__ = (
        UniqueConstraint(
            "attendance_session_id",
            "user_id",
            "scan_seq",
            name="uq_attendance_scans_session_user_seq",
        ),
        _iso8601_utc_check(
            "scanned_at", "ck_attendance_scans_scanned_at_iso8601"),
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
    created_at = Column(String, nullable=False,
                        server_default=_UTC_NOW_ISO8601)
    revoked_at = Column(String)
    client_ip = Column(String)
    user_agent = Column(String)

    __table_args__ = (
        Index("idx_login_sessions_user", "user_id"),
        _iso8601_utc_check(
            "last_used_at", "ck_login_sessions_last_used_at_iso8601"),
        _iso8601_utc_check(
            "expires_at", "ck_login_sessions_expires_at_iso8601"),
        _iso8601_utc_check(
            "created_at", "ck_login_sessions_created_at_iso8601"),
        _iso8601_utc_check(
            "revoked_at", "ck_login_sessions_revoked_at_iso8601", nullable=True
        ),
    )


class ManualCorrection(Base):
    """手動修正の監査ログ"""

    __tablename__ = "manual_corrections"

    id = Column(Integer, primary_key=True, autoincrement=True)
    attendance_session_id = Column(Integer, ForeignKey(
        "attendance_sessions.id"), nullable=False)
    target_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    teacher_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    before_status = Column(String)
    after_status = Column(String, nullable=False)
    reason = Column(String, nullable=False)
    client_ip = Column(String)
    corrected_at = Column(String, nullable=False,
                          server_default=_UTC_NOW_ISO8601)

    __table_args__ = (
        _iso8601_utc_check(
            "corrected_at", "ck_manual_corrections_corrected_at_iso8601"
        ),
    )


class DeviceBinding(Base):
    """アカウントの端末を記録する"""

    __tablename__ = "device_bindings"

    device_id = Column(String, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    first_seen_at = Column(String, nullable=False)
    last_seen_at = Column(String, nullable=False)

    __table_args__ = (
        _iso8601_utc_check(
            "first_seen_at", "ck_device_bindings_first_seen_at_iso8601"
        ),
        _iso8601_utc_check(
            "last_seen_at", "ck_device_bindings_last_seen_at_iso8601"
        ),
    )


class AuditLog(Base):
    """行動を記録する"""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    occurred_at = Column(String, nullable=False,
                         server_default=_UTC_NOW_ISO8601)
    action = Column(String, nullable=False)
    result = Column(String, nullable=False)
    actor_user_id = Column(Integer, ForeignKey("users.id"))
    attempted_login_id = Column(String)
    target_type = Column(String)
    target_id = Column(Integer)
    client_ip = Column(String)
    device_id = Column(String)
    detail = Column(String)

    __table_args__ = (
        CheckConstraint(
            "result IN ('success', 'failure')",
            name="ck_audit_logs_result",
        ),
        Index("idx_audit_logs_action_time", "action", "occurred_at"),
        Index("idx_audit_logs_ip_time", "client_ip", "occurred_at"),
        Index("idx_audit_logs_login_time", "attempted_login_id", "occurred_at"),
        _iso8601_utc_check("occurred_at", "ck_audit_logs_occurred_at_iso8601"),
    )
