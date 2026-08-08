"""設定値の読み込み（A-1）．

セキュリティに関わる値をコードに直書きしないための入り口．
すべての設定はここで環境変数から読み，他のモジュールはこのモジュールを参照する．

設計上の要点：
- **既定値を持たせない値がある**．`TOKEN_SECRET`と`CAMPUS_IP_RANGES`は未設定なら
  例外を投げて止まる．開発用の既定値をコードに埋めると，設定を忘れたまま本番で
  動いてしまい，しかもその事実に誰も気付けない（⑤安全なデフォルト）．
- 値の検証もここで行う．不正なCIDRや整数でない値は，使う瞬間ではなく
  **起動時に**弾く．
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv

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


@dataclass(frozen=True)
class Settings:
    # --- 秘密・環境依存（必須） ---
    token_secret: str
    campus_ip_ranges: tuple

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
        qr_rotate_seconds=_int_or_default("QR_ROTATE_SECONDS", 5),
        token_accept_previous_windows=_int_or_default("TOKEN_ACCEPT_PREVIOUS_WINDOWS", 1),
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
    if not (settings.present_after_minutes <= settings.late_until_minutes):
        raise ConfigError(
            "LATE_UNTIL_MINUTES は PRESENT_AFTER_MINUTES 以上にしてください。"
        )

    return settings
