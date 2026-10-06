"""

出席管理システムのデータモデル定義（MySQL 8.0.17 以上）．

設計方針
----------------------------------------------------------------------
- アプリ側のバリデーションが漏れても最後の防壁として機能するよう，
    可能な制約はすべて DB レベル（NOT NULL / CHECK / UNIQUE / FOREIGN KEY）
    で表現する（⑤安全なデフォルト）．
- **MySQL 8.0.16 未満では CHECK 制約が構文だけ通って黙って無視される**ので，
  「最後の防壁」が無効になる．式のデフォルト値は 8.0.13 以上，照合順序
  `utf8mb4_0900_bin` は 8.0.17 以上が要る．したがって 8.0.17 以上を前提にする．
- 外部キー制約は InnoDB なら常に有効なので，SQLite のような接続ごとの
  `PRAGMA foreign_keys` は要らない．代わりに，MyISAM だと `REFERENCES` が
  黙って無視されるため，全テーブルに `ENGINE=InnoDB` を明示している．
- 文字列の照合順序は，大文字小文字と末尾空白を区別する `utf8mb4_0900_bin` に
  揃える．MySQL の既定（`*_ci`）のままだと，SQLite では別物だった値が
  同一視されてしまう．
    - `s0001` で `S0001` のアカウントにログインできてしまう
    - `token_urlsafe` で作る `device_id` が，大小違いだけで主キー衝突する
- MySQL の VARCHAR は長さが必須．厳格モード（`create_db_engine` が接続ごとに
  強制する）では，長さを超える値は黙って切り詰められずエラーになる
  （例外：あふれた分が末尾の空白・改行だけなら，その分は黙って切り捨てられる）．
  **外部から入る値（login_id・device_id など）は API の入口で先に長さを
  検証すること**．モデル側は最後の防壁であり，超過すると 500 になる．
- 時刻カラムは UTC の ISO 8601 文字列（例: "2026-07-27T01:00:00.000Z"）として
    保存する．タイムゾーン変換や比較演算はアプリ層の責務とし，DB 層では文字列
    として素直に保持する．
    - DB 側で自動付与するタイムスタンプ（created_at 等）も同じ書式に揃えるため，
      `server_default` には `NOW()` ではなく，`UTC_TIMESTAMP(3)` を
      `YYYY-MM-DDTHH:MM:SS.mmmZ` に整形する式を用いる．`UTC_TIMESTAMP` は
      サーバーのタイムゾーン設定に依存しない（`NOW()` は依存する）．
    - アプリ層でも時刻文字列を生成する際は `Z` サフィックス付きの UTC 表現
      （例: `security.to_iso()`）に統一すること．
    - 最後の防壁として，DB レベルでも書式チェック（`YYYY-MM-DDTHH:MM:SS.mmmZ`）を
      CHECK 制約で強制する．カラム長 VARCHAR(24) と併せて，桁数まで固定される．
- ログインセッションは生のセッションIDを保存せず，SHA-256 等でハッシュ化した
    `id_hash` のみを主キーとして保存する（漏洩時の被害を限定するため）．
"""

from __future__ import annotations

from sqlalchemy import (
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import text

Base = declarative_base()


# ------------------------------------------------------------ テーブル共通の設定
#
# 照合順序をカラムごとではなくテーブルの既定にしているのは，カラムの付け忘れで
# 大文字小文字を区別しない列が混ざる事故を避けるため（新しいカラムは自動で bin になる）．
_MYSQL_TABLE_OPTIONS = {
    "mysql_engine": "InnoDB",
    "mysql_charset": "utf8mb4",
    "mysql_collate": "utf8mb4_0900_bin",
}


# ------------------------------------------------------------ カラム長
#
# InnoDB のインデックスキー長の上限は 3072 バイト．utf8mb4 は 1 文字 4 バイトなので
# 768 文字まで．主キー・UNIQUE・INDEX に入るカラムは，以下のとおりすべて短く
# 抑えているので，複合インデックスでも上限に当たらない．
_LEN_LOGIN_ID = 64         # 学籍番号・職員番号．ログイン失敗時の入力値も入る（外部入力）
_LEN_NAME = 100            # 氏名・授業名．main.py の授業名の上限（100）と揃える
_LEN_ENUM = 16             # role / status / record_source / result
_LEN_TIMESTAMP = 24        # "YYYY-MM-DDTHH:MM:SS.mmmZ" は必ず24文字
_LEN_HASH_OR_TOKEN = 64    # id_hash（SHA-256 hex 64文字）/ device_id / token_salt
_LEN_IP = 64               # IPv6 は最大45文字．余裕を見ている
_LEN_PASSWORD_HASH = 255   # bcrypt は60文字だが，方式を変えても収まるように
_LEN_LABEL = 64            # action / target_type
_LEN_DETAIL = 255          # 監査ログの補足．アプリが組み立てる短い文字列だけを入れる


# UTC ISO 8601（"YYYY-MM-DDTHH:MM:SS.mmmZ"）の書式チェック用の正規表現．
#
# **桁数まで固定する**のが重要．時刻の範囲検索は文字列の大小比較で行うため
# （固定長のUTC文字列なら文字列比較＝時系列比較になる），桁数が揺れると比較が
# 壊れる．たとえば同じ瞬間を "…:00Z" と "…:00.000Z" で表すと，'.'(0x2E) は
# 'Z'(0x5A) より小さいので後者が常に「古い」と判定される．その結果，
# レート制限が失敗を数え落とし，総当たりがすり抜ける．
#
# ミリ秒3桁に統一する理由：授業開始直後は多数の登録が同じ秒に集中するため，
# 秒までだと監査ログの順序が潰れる．
#
# 書き方の注意：
#   - `\.` ではなく `[.]` を使う．SQL の文字列リテラルではバックスラッシュが
#     エスケープとして解釈されるので，`\.` は意図せず `.`（任意の1文字）になりうる．
#   - 末尾の `$` は ICU の正規表現では「入力の末尾，または末尾の改行の直前」に
#     マッチするので，この正規表現だけだと末尾に改行が付いた文字列も通る．
#     ただし実際には問題にならない．カラムが VARCHAR(24) なので，あふれた分が
#     空白・改行だけのときは，MySQL が厳格モードでも黙って切り捨てて24文字だけを
#     保存する（MySQL 8.0.46 で確認）．CHECK が評価するのはこの切り捨て後の値で，
#     改行が付いたままの値は保存されない．カラム長を変えるときは，この前提が
#     崩れないか確認すること．
_ISO8601_UTC_REGEX = (
    "^[0-9]{4}-[0-9]{2}-[0-9]{2}"
    "T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$"
)


def _iso8601_utc_check(column_name: str, constraint_name: str,
                       nullable: bool = False) -> CheckConstraint:
    """指定カラムに UTC ISO 8601（ミリ秒・固定長）の書式チェックを付与する．

    MySQL では CHECK 制約の名前がテーブルではなくスキーマ全体で一意になる必要がある．
    呼び出し側で `ck_<テーブル名>_<カラム名>_iso8601` の形にして衝突を避けること．
    """
    condition = f"{column_name} REGEXP '{_ISO8601_UTC_REGEX}'"
    if nullable:
        condition = f"({column_name} IS NULL OR {condition})"
    return CheckConstraint(condition, name=constraint_name)


# DB 側で自動付与する現在時刻（UTC・ミリ秒3桁・末尾 Z）．
#
# DATE_FORMAT の %f はマイクロ秒6桁を返すので，LEFT(…, 23) でミリ秒3桁に切る
# （"YYYY-MM-DDTHH:MM:SS.mmm" は23文字）．
# 式をそのままデフォルト値にするには，MySQL では全体を括弧で囲む必要がある．
_UTC_NOW_ISO8601 = text(
    "(CONCAT(LEFT(DATE_FORMAT(UTC_TIMESTAMP(3), '%Y-%m-%dT%H:%i:%s.%f'), 23), 'Z'))"
)


def create_db_engine(url: str, **kwargs) -> Engine:
    """Engine を作成する．

    このアプリは MySQL 専用（CHECK 制約の `REGEXP` や，デフォルト値の
    `DATE_FORMAT` などが MySQL 固有のため）．ほかの DB を渡されたら，
    後で分かりにくいSQLエラーになる前に，ここで止める．

    接続の都度，セッションを**厳格モード**にする．MySQL は構成によっては
    長すぎる文字列を黙って切り詰めて保存する．切り詰められたログインIDや
    端末IDが監査ログに残ると，追跡も照合も不正確になる（⑥追跡可能性）．
    サーバー側の設定に頼らず，クライアント側からも強制する．
    """
    engine = create_engine(url, **kwargs)

    if engine.dialect.name != "mysql":
        engine.dispose()
        raise ValueError(
            "このアプリは MySQL 専用です"
            f"（渡されたDBの種類: {engine.dialect.name}）．"
            "DATABASE_URL を mysql+pymysql://… の形で指定してください．"
        )

    @event.listens_for(engine, "connect")
    def _configure_mysql_session(dbapi_connection, connection_record):  # noqa: ANN001
        cursor = dbapi_connection.cursor()
        try:
            # 既存の sql_mode を残したまま STRICT_ALL_TABLES を足す．
            # NULLIF は，sql_mode が空文字のときに先頭に "," が付いて
            # 構文エラーになるのを避けるため．
            cursor.execute(
                "SET SESSION sql_mode = "
                "CONCAT_WS(',', NULLIF(@@SESSION.sql_mode, ''), 'STRICT_ALL_TABLES')"
            )
        finally:
            cursor.close()

    return engine


# ---------------------------------------------------------------- User

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    login_id = Column(String(_LEN_LOGIN_ID), nullable=False, unique=True)
    role = Column(String(_LEN_ENUM), nullable=False)
    display_name = Column(String(_LEN_NAME), nullable=False)
    password_hash = Column(String(_LEN_PASSWORD_HASH), nullable=False)
    created_at = Column(String(_LEN_TIMESTAMP), nullable=False,
                        server_default=_UTC_NOW_ISO8601)

    __table_args__ = (
        # admin は授業と履修の管理だけを行う役割．出席記録には触れない
        # （decisions.md D-17）．ロールを増やすので，既存のDBは
        # 作り直しが要る（CHECK制約を後から変更するには ALTER が要る）．
        CheckConstraint("role IN ('student', 'teacher', 'admin')",
                        name="ck_users_role"),
        _iso8601_utc_check("created_at", "ck_users_created_at_iso8601"),
        _MYSQL_TABLE_OPTIONS,
    )


# -------------------------------------------------------------- Course

class Course(Base):
    __tablename__ = "courses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(_LEN_NAME), nullable=False)
    teacher_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(String(_LEN_TIMESTAMP), nullable=False,
                        server_default=_UTC_NOW_ISO8601)

    __table_args__ = (
        _iso8601_utc_check("created_at", "ck_courses_created_at_iso8601"),
        _MYSQL_TABLE_OPTIONS,
    )


# ---------------------------------------------------------- Enrollment

class Enrollment(Base):
    __tablename__ = "enrollments"

    course_id = Column(Integer, ForeignKey("courses.id"), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)

    __table_args__ = (_MYSQL_TABLE_OPTIONS,)


# ------------------------------------------------------ AttendanceSession

class AttendanceSession(Base):
    __tablename__ = "attendance_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    course_id = Column(Integer, ForeignKey("courses.id"), nullable=False)
    scheduled_start_at = Column(String(_LEN_TIMESTAMP), nullable=False)
    started_at = Column(String(_LEN_TIMESTAMP), nullable=False)
    closed_at = Column(String(_LEN_TIMESTAMP))
    status = Column(String(_LEN_ENUM), nullable=False, default="open")
    required_scan_count = Column(Integer, nullable=False, default=1)
    # トークン導出を秘密鍵だけに依存させないための塩．NOT NULL 必須（decisions.md D-3）．
    token_salt = Column(String(_LEN_HASH_OR_TOKEN), nullable=False)
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
        _MYSQL_TABLE_OPTIONS,
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
    status = Column(String(_LEN_ENUM), nullable=False)
    record_source = Column(String(_LEN_ENUM), nullable=False, default="auto")
    first_recorded_at = Column(String(_LEN_TIMESTAMP), nullable=False)

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
        _MYSQL_TABLE_OPTIONS,
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
    scanned_at = Column(String(_LEN_TIMESTAMP), nullable=False)
    client_ip = Column(String(_LEN_IP), nullable=False)
    # Cookie の値がそのまま入る（外部入力）．API の入口で形式と長さを検証すること．
    device_id = Column(String(_LEN_HASH_OR_TOKEN))

    __table_args__ = (
        UniqueConstraint(
            "attendance_session_id",
            "user_id",
            "scan_seq",
            name="uq_attendance_scans_session_user_seq",
        ),
        _iso8601_utc_check(
            "scanned_at", "ck_attendance_scans_scanned_at_iso8601"),
        _MYSQL_TABLE_OPTIONS,
    )


# ----------------------------------------------------------- LoginSession

class LoginSession(Base):
    """ログインセッション．

    生のセッションIDは保存せず，ハッシュ値（例: SHA-256, 64文字hex）のみを
    主キーとして保存する（decisions.md D-7）．`id` カラムは意図的に持たない．
    """

    __tablename__ = "login_sessions"

    id_hash = Column(String(_LEN_HASH_OR_TOKEN), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    last_used_at = Column(String(_LEN_TIMESTAMP), nullable=False)
    expires_at = Column(String(_LEN_TIMESTAMP), nullable=False)
    created_at = Column(String(_LEN_TIMESTAMP), nullable=False,
                        server_default=_UTC_NOW_ISO8601)
    revoked_at = Column(String(_LEN_TIMESTAMP))
    client_ip = Column(String(_LEN_IP))
    # リクエストヘッダの値がそのまま入る（外部入力）．長さの上限が読めないので
    # TEXT にして，長すぎて 500 になる経路を作らない．インデックスは張らない．
    user_agent = Column(Text)

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
        _MYSQL_TABLE_OPTIONS,
    )


class ManualCorrection(Base):
    """手動修正の監査ログ"""

    __tablename__ = "manual_corrections"

    id = Column(Integer, primary_key=True, autoincrement=True)
    attendance_session_id = Column(Integer, ForeignKey(
        "attendance_sessions.id"), nullable=False)
    target_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    teacher_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    before_status = Column(String(_LEN_ENUM))
    after_status = Column(String(_LEN_ENUM), nullable=False)
    # 教員が自由に書く文章．長さの上限を決めていないので TEXT にする．
    reason = Column(Text, nullable=False)
    client_ip = Column(String(_LEN_IP))
    corrected_at = Column(String(_LEN_TIMESTAMP), nullable=False,
                          server_default=_UTC_NOW_ISO8601)

    __table_args__ = (
        _iso8601_utc_check(
            "corrected_at", "ck_manual_corrections_corrected_at_iso8601"
        ),
        _MYSQL_TABLE_OPTIONS,
    )


class DeviceBinding(Base):
    """アカウントの端末を記録する"""

    __tablename__ = "device_bindings"

    # Cookie の値がそのまま主キーになる（外部入力）．API の入口で形式と長さを検証すること．
    device_id = Column(String(_LEN_HASH_OR_TOKEN), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    first_seen_at = Column(String(_LEN_TIMESTAMP), nullable=False)
    last_seen_at = Column(String(_LEN_TIMESTAMP), nullable=False)

    __table_args__ = (
        _iso8601_utc_check(
            "first_seen_at", "ck_device_bindings_first_seen_at_iso8601"
        ),
        _iso8601_utc_check(
            "last_seen_at", "ck_device_bindings_last_seen_at_iso8601"
        ),
        _MYSQL_TABLE_OPTIONS,
    )


class AuditLog(Base):
    """行動を記録する"""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    occurred_at = Column(String(_LEN_TIMESTAMP), nullable=False,
                         server_default=_UTC_NOW_ISO8601)
    action = Column(String(_LEN_LABEL), nullable=False)
    result = Column(String(_LEN_ENUM), nullable=False)
    actor_user_id = Column(Integer, ForeignKey("users.id"))
    # ログイン失敗時の入力値がそのまま入る（外部入力）．インデックスに入るので
    # TEXT にはできない．API の入口で長さを検証すること（LoginRequest）．
    attempted_login_id = Column(String(_LEN_LOGIN_ID))
    target_type = Column(String(_LEN_LABEL))
    target_id = Column(Integer)
    client_ip = Column(String(_LEN_IP))
    device_id = Column(String(_LEN_HASH_OR_TOKEN))
    detail = Column(String(_LEN_DETAIL))

    __table_args__ = (
        CheckConstraint(
            "result IN ('success', 'failure')",
            name="ck_audit_logs_result",
        ),
        Index("idx_audit_logs_action_time", "action", "occurred_at"),
        Index("idx_audit_logs_ip_time", "client_ip", "occurred_at"),
        Index("idx_audit_logs_login_time", "attempted_login_id", "occurred_at"),
        _iso8601_utc_check("occurred_at", "ck_audit_logs_occurred_at_iso8601"),
        _MYSQL_TABLE_OPTIONS,
    )
