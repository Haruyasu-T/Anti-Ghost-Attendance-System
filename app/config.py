"""設定値の読み込み（A-1）．

セキュリティに関わる値をコードに直書きしないための入り口．
すべての設定はここで環境変数から読み，他のモジュールはこのモジュールを参照する．

設計上の要点：
- **既定値を持たせない値がある**．`TOKEN_SECRET`・`CAMPUS_IP_RANGES`・`DATABASE_URL`は
  未設定なら例外を投げて止まる．開発用の既定値をコードに埋めると，設定を忘れたまま
  本番で動いてしまい，しかもその事実に誰も気付けない（⑤安全なデフォルト）．
  `DATABASE_URL` はMySQLの認証情報を含むので，なおさら既定値を持たせない．
- 値の検証もここで行う．不正なCIDRや整数でない値は，使う瞬間ではなく
  **起動時に**弾く．`DATABASE_URL` がMySQL向けでない場合や，文字コードが
  utf8mb4 でない場合も同様．
- **`DATABASE_URL` の値をエラーメッセージやログに出さない**．パスワードを含むため．
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from functools import lru_cache

from dotenv import load_dotenv
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

# .env があれば読み込む（既に設定済みの環境変数は上書きしない）．
# 本番では .env を置かず，ホスティング側の環境変数で渡す想定．
load_dotenv()


class ConfigError(RuntimeError):
    """設定が不足・不正なときに起動を止めるための例外."""


def _require_str(name: str) -> str:
    """必須の文字列設定を読む．未設定なら起動を止める."""
    value = os.getenv(name, "").strip()
    if not value:
        raise ConfigError(
            f"{name} が設定されていません。"
            ".env.example をコピーして .env を作り、値を設定してください。"
        )
    return value


def _int_or_default(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} は整数で指定してください（現在の値: {raw!r}）") from exc


def _parse_cidrs(raw: str) -> tuple:
    """カンマ区切りのCIDRを解析する．1つでも不正なら起動を止める."""
    networks = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            # strict=False: 192.168.1.5/24 のようなホスト部つきの指定も許容する
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError as exc:
            raise ConfigError(
                f"CAMPUS_IP_RANGES に不正なCIDRがあります: {part!r}"
            ) from exc

    if not networks:
        raise ConfigError("CAMPUS_IP_RANGES に有効なCIDRが1つもありません。")
    return tuple(networks)


_DATABASE_URL_EXAMPLE = "mysql+pymysql://user:pass@host:3306/dbname?charset=utf8mb4"


def _validate_database_url(raw: str) -> str:
    """DATABASE_URL がMySQL向けで，文字コードが utf8mb4 であることを確認する.

    確認する理由：
      - `models.py` はMySQL固有のSQL（CHECK制約の `REGEXP` など）を使っている．
        `.env` に古い `sqlite:///…` が残っていると，テーブル作成か最初のINSERTで
        分かりにくいエラーになる．起動時に原因が分かる形で止める
      - 文字コードが `utf8`（実体は `utf8mb3`，3バイトまで）だと，4バイト文字
        （一部の漢字や絵文字）を含む氏名を保存できない．`charset` を省略した場合の
        既定値はドライバ依存なので，明示を必須にして曖昧さを残さない

    エラーメッセージにURLそのものを入れない．パスワードを含むため，起動失敗の
    ログ経由で漏れるのを避ける．`from None` で，元の例外（URLを含みうる）が
    トレースバックに連鎖して表示されるのも防ぐ．
    """
    try:
        url = make_url(raw)
    except ArgumentError:
        raise ConfigError(
            "DATABASE_URL の形式が不正です（認証情報を含むため値は表示しません）。"
            f"例: {_DATABASE_URL_EXAMPLE}"
        ) from None

    if url.get_backend_name() != "mysql":
        raise ConfigError(
            "DATABASE_URL はMySQL（mysql+pymysql://…）で指定してください。"
            f"現在の種類: {url.get_backend_name()}。例: {_DATABASE_URL_EXAMPLE}"
        )
    if not url.database:
        raise ConfigError(
            "DATABASE_URL にデータベース名がありません。"
            f"例: {_DATABASE_URL_EXAMPLE}"
        )

    charset = url.query.get("charset")
    if isinstance(charset, (tuple, list)):
        charset = charset[-1] if charset else None
    if (charset or "").lower() != "utf8mb4":
        raise ConfigError(
            "DATABASE_URL の末尾に ?charset=utf8mb4 を付けてください。"
            f"例: {_DATABASE_URL_EXAMPLE}"
        )

    return raw


@dataclass(frozen=True)
class Settings:
    # --- 秘密・環境依存（必須） ---
    # repr=False：Settings をログやデバッグ出力に渡しても，秘密が出ないようにする．
    token_secret: str = field(repr=False)
    campus_ip_ranges: tuple

    # --- DB ---
    # パスワードを含むので repr=False．
    database_url: str = field(repr=False)
    # 接続プール．1プロセスあたりの最大接続数は pool_size + max_overflow．
    # workerを増やすときは，その積がMySQLの max_connections を超えないようにする．
    db_pool_size: int
    db_max_overflow: int
    # この秒数を超えて使われた接続は作り直す．MySQLの wait_timeout（既定8時間）や
    # 間に挟まるプロキシ・ファイアウォールの切断より短くしておくこと．
    db_pool_recycle_seconds: int

    # --- ログインセッション ---
    session_lifetime_hours: int

    # --- 動的QR ---
    qr_rotate_seconds: int
    token_accept_previous_windows: int

    # --- 受付時間帯（分） ---
    present_before_minutes: int
    present_after_minutes: int
    late_until_minutes: int

    # --- ログインのレート制限 ---
    login_max_failures: int
    login_window_minutes: int
    login_lockout_minutes: int

    # --- バースト検知 ---
    burst_threshold_count: int
    burst_window_seconds: int

    # --- リバースプロキシ ---
    # 自分の前段にいる「信頼できるプロキシ」の数．
    # 0 なら X-Forwarded-For を一切見ない（ローカル開発時）．
    # 詳しくは security.get_client_ip のコメントを参照．
    trusted_proxy_count: int


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """設定を読み込む（初回のみ．以降はキャッシュを返す）.

    アプリの起動時に一度呼んで，設定不備なら起動を止めること．
    使う瞬間まで検証を遅らせると，授業中に初めて設定ミスが発覚しかねない．
    """
    settings = Settings(
        token_secret=_require_str("TOKEN_SECRET"),
        campus_ip_ranges=_parse_cidrs(_require_str("CAMPUS_IP_RANGES")),
        database_url=_validate_database_url(_require_str("DATABASE_URL")),
        db_pool_size=_int_or_default("DB_POOL_SIZE", 5),
        db_max_overflow=_int_or_default("DB_MAX_OVERFLOW", 10),
        db_pool_recycle_seconds=_int_or_default(
            "DB_POOL_RECYCLE_SECONDS", 1800),
        session_lifetime_hours=_int_or_default("SESSION_LIFETIME_HOURS", 12),
        qr_rotate_seconds=_int_or_default("QR_ROTATE_SECONDS", 5),
        token_accept_previous_windows=_int_or_default(
            "TOKEN_ACCEPT_PREVIOUS_WINDOWS", 1),
        present_before_minutes=_int_or_default("PRESENT_BEFORE_MINUTES", 5),
        present_after_minutes=_int_or_default("PRESENT_AFTER_MINUTES", 5),
        late_until_minutes=_int_or_default("LATE_UNTIL_MINUTES", 20),
        login_max_failures=_int_or_default("LOGIN_MAX_FAILURES", 5),
        login_window_minutes=_int_or_default("LOGIN_WINDOW_MINUTES", 10),
        login_lockout_minutes=_int_or_default("LOGIN_LOCKOUT_MINUTES", 15),
        burst_threshold_count=_int_or_default("BURST_THRESHOLD_COUNT", 3),
        burst_window_seconds=_int_or_default("BURST_WINDOW_SECONDS", 60),
        trusted_proxy_count=_int_or_default("TRUSTED_PROXY_COUNT", 0),
    )

    if settings.qr_rotate_seconds <= 0:
        raise ConfigError("QR_ROTATE_SECONDS は1以上にしてください。")
    if settings.token_accept_previous_windows < 0:
        raise ConfigError("TOKEN_ACCEPT_PREVIOUS_WINDOWS は0以上にしてください。")
    if settings.trusted_proxy_count < 0:
        raise ConfigError("TRUSTED_PROXY_COUNT は0以上にしてください。")
    if settings.session_lifetime_hours <= 0:
        raise ConfigError("SESSION_LIFETIME_HOURS は1以上にしてください。")
    if settings.db_pool_size < 1:
        raise ConfigError("DB_POOL_SIZE は1以上にしてください。")
    if settings.db_max_overflow < 0:
        raise ConfigError("DB_MAX_OVERFLOW は0以上にしてください。")
    if settings.db_pool_recycle_seconds < 1:
        # -1（無効）や0を許すと，切断済みの接続を掴んで授業中に500になる．
        raise ConfigError("DB_POOL_RECYCLE_SECONDS は1以上にしてください。")
    if not (settings.present_after_minutes <= settings.late_until_minutes):
        raise ConfigError(
            "LATE_UNTIL_MINUTES は PRESENT_AFTER_MINUTES 以上にしてください。"
        )

    return settings
