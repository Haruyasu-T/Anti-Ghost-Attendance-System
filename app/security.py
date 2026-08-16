"""セキュリティの中核（担当A / A-2〜A-5）．

契約は [docs/security-interface.md](../docs/security-interface.md) を参照．

このモジュールの原則：
- **HTTPのことを知らない**．`Request`を受け取るのは`get_client_ip`だけ．
- **DBを引かない**．必要な値（`token_salt`など）は引数で受け取る．
  純粋関数のままにしておくと，テストが速く確実になる．
- 判定できないときは**拒否**する．「たぶん大丈夫」で通す分岐を作らない（⑤安全なデフォルト）．

未実装：A-6以降（ログインセッション・監査ログ・端末紐付け・レート制限）は
`models.py`（B-1）の完成後に着手する．
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
from datetime import datetime, timezone
from enum import Enum

import bcrypt

from app.config import get_settings

# トークンの長さ（16進16文字＝64ビット）．
# 総当たりで当てるには 2^63 回程度の試行が必要で，5〜10秒の有効期間では現実的でない．
# QRに載せる都合上，短いほど読み取りが速く確実になるため，安全性を保てる最小限にしている．
TOKEN_LENGTH = 16


# ============================================================ A-2. パスワード

def _prehash(plain: str) -> bytes:
    """bcryptに渡す前に SHA-256 で固定長に畳む.

    **bcryptは72バイトを超える入力を切り捨てる**．そのまま渡すと，長いパスワードは
    先頭72バイトしか使われず，「先頭72バイトが同じ別のパスワード」でも認証が
    通ってしまう．新しいbcryptでは切り捨てずに例外になるが，いずれにせよ
    長いパスワードを正しく扱えない．

    先にSHA-256で32バイトに畳み，base64で44文字にしてから渡すことで，
    入力の長さに関係なく全体がハッシュに反映される．
    （Django等が採用している bcrypt_sha256 と同じ考え方）
    """
    digest = hashlib.sha256(plain.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(plain: str) -> str:
    """パスワードをハッシュ化する（SHA-256で畳んでからbcrypt）.

    bcryptはソルトを自動で付けるため，同じ平文でも毎回異なるハッシュになる．
    ハッシュ自体に計算コストがあり，総当たりを遅くする．
    """
    return bcrypt.hashpw(_prehash(plain), bcrypt.gensalt()).decode("ascii")


# 存在しないユーザーへのログイン試行でも，実在ユーザーと同じだけ時間をかけるための
# ダミーハッシュ．これが無いと「即座に失敗＝そのIDは存在しない」と分かってしまう
# （タイミング攻撃によるアカウント列挙）．
_DUMMY_HASH = hash_password("dummy-password-for-timing-equalization")


def verify_password(plain: str, password_hash: str | None) -> bool:
    """平文とハッシュを照合する.

    `password_hash`が`None`（＝そのログインIDのユーザーが存在しない）の場合でも，
    **ダミーハッシュに対して照合を実行してから**Falseを返す．
    早期リターンすると応答時間の差でアカウントの存在が分かってしまうため．
    """
    target = password_hash if password_hash is not None else _DUMMY_HASH

    try:
        matched = bcrypt.checkpw(_prehash(plain), target.encode("ascii"))
    except (ValueError, TypeError):
        # 保存されているハッシュが壊れている等．通してはいけないのでFalse．
        return False

    # ユーザーが存在しない場合は，照合が偶然通っても必ずFalseにする
    return matched and password_hash is not None


# ============================================================ A-3. 動的トークン


def new_token_salt() -> str:
    """出席セッションごとの塩を生成する（セッション開始時・作り直し時に呼ぶ）.

    この塩を混ぜることで，`TOKEN_SECRET`が漏れただけでは有効なトークンを
    作れなくなる．また塩を作り直すと，出回っているQRが即座に全て無効になる．
    """
    return secrets.token_urlsafe(16)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _window_index(at: datetime, rotate_seconds: int) -> int:
    """時刻を「何番目の時間窓か」に落とす."""
    return int(at.timestamp()) // rotate_seconds


def _derive(session_id: int, token_salt: str, window: int, secret: str) -> str:
    """1つの時間窓に対応するトークンを計算する."""
    message = f"{session_id}:{token_salt}:{window}".encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return digest[:TOKEN_LENGTH]


def generate_token(session_id: int, token_salt: str, at: datetime | None = None) -> str:
    """指定時刻の世代に対応するトークンを返す（at=Noneなら現在時刻）.

    `session_id`を入力に含めているので，同時刻に別の授業が開講されていても，
    そちらのQRを流用することはできない．
    """
    settings = get_settings()
    at = at or _utcnow()
    window = _window_index(at, settings.qr_rotate_seconds)
    return _derive(session_id, token_salt, window, settings.token_secret)


def verify_token(
    session_id: int,
    token_salt: str,
    token: str,
    at: datetime | None = None,
) -> bool:
    """トークンが現在世代または直前世代として妥当かを判定する.

    直前の世代も受け付けるのは，表示が切り替わる直前に読み取りを始めた学生が，
    カメラの合焦・デコード・通信の遅延で期限切れになるのを防ぐため．
    その代償として，転送に使える猶予が更新間隔の約2倍になる（脅威モデルに記載済み）．
    """
    if not token:
        return False

    settings = get_settings()
    at = at or _utcnow()
    window = _window_index(at, settings.qr_rotate_seconds)

    # 一致しても途中で抜けない．抜けると「何世代前で一致したか」が
    # 処理時間の差として観測できてしまうため，常に同じ回数だけ計算する．
    matched = False
    for back in range(settings.token_accept_previous_windows + 1):
        expected = _derive(session_id, token_salt, window - back, settings.token_secret)
        # `==` ではなく compare_digest を使う．`==`は不一致の位置で処理時間が変わり，
        # 先頭から1文字ずつ正解を絞り込まれる余地がある．
        if hmac.compare_digest(expected, token):
            matched = True

    return matched


# ============================================================ A-4. アクセス元IP


def is_campus_ip(client_ip: str) -> bool:
    """アクセス元IPが学内レンジに含まれるかを判定する.

    解析できない値は**Falseを返す**（判定不能なら拒否する）．
    """
    try:
        address = ipaddress.ip_address(client_ip.strip())
    except (ValueError, AttributeError):
        return False

    return any(address in network for network in get_settings().campus_ip_ranges)


def get_client_ip(request) -> str:
    """信頼できる経路からアクセス元IPを取得する.

    **このプロジェクトで最も間違えやすい箇所**なので，`main.py`側でヘッダを
    直接読まず，必ずこの関数を通すこと．

    `X-Forwarded-For`はクライアントが自由に送れるヘッダである．素直に先頭の値を
    使うと，学外の攻撃者が `X-Forwarded-For: <学内IP>` を付けるだけで
    IP検証を突破できてしまう．つまり「クライアントの自己申告で学内判定する」
    ことになり，対策が完全に無効化される．

    そこで，前段にいる**信頼できるプロキシの数**（`TRUSTED_PROXY_COUNT`）を
    設定として持つ．
      - 0 のとき：ヘッダを一切見ず，TCP接続元のアドレスだけを使う（ローカル開発）
      - N のとき：`X-Forwarded-For` の**右からN番目**を使う

    右から数えるのは，各プロキシが「自分が見た接続元」を末尾に追記していくため．
    攻撃者が偽の値を送っても，それはリストの左側に押しやられる．末尾側の
    N個は信頼できるプロキシが書いた値なので，そこだけを信じる．
    """
    settings = get_settings()

    if settings.trusted_proxy_count == 0:
        client = getattr(request, "client", None)
        return getattr(client, "host", "") or ""

    forwarded = request.headers.get("x-forwarded-for", "")
    parts = [part.strip() for part in forwarded.split(",") if part.strip()]

    if len(parts) < settings.trusted_proxy_count:
        # 期待した数のプロキシを経由していない＝構成の想定と食い違う．
        # 推測で通すと判定を誤るため，空文字を返して呼び出し側で拒否させる．
        return ""

    return parts[-settings.trusted_proxy_count]


# ============================================================ A-5. 受付時間帯


class AttendanceStatus(str, Enum):
    PRESENT = "present"
    LATE = "late"


def classify_attendance(
    scheduled_start_at: datetime,
    now: datetime,
) -> AttendanceStatus | None:
    """出席区分を返す．受付時間外ならNone.

    境界値は**学生に有利な側**に含める（decisions.md D-10）．
    1秒の差で不利益が出ると異議申し立てが増え，教員の手動修正への依存が高まる．
    手動修正はそれ自体が攻撃面なので，運用の摩擦を減らすことがセキュリティ上も望ましい．

        t < -5分         → None（早すぎる）
        -5分 <= t <= +5分 → PRESENT
        +5分 <  t <= +20分 → LATE
        t > +20分        → None（受付終了）

    `now`には必ず**サーバー時刻**を渡す．クライアントから受け取った時刻を
    渡してはいけない（端末の時計は自由に変更できる）．
    """
    if scheduled_start_at.tzinfo is None or now.tzinfo is None:
        # naiveとawareを混ぜると比較を誤る（あるいは例外になる）．
        # 黙って進むと判定がずれるので，はっきり落とす．
        raise ValueError(
            "classify_attendance にはタイムゾーン付きの datetime を渡してください。"
        )

    settings = get_settings()
    elapsed_seconds = (now - scheduled_start_at).total_seconds()

    if elapsed_seconds < -settings.present_before_minutes * 60:
        return None  # 授業前に前もって読み取っておく行為を防ぐ
    if elapsed_seconds <= settings.present_after_minutes * 60:
        return AttendanceStatus.PRESENT
    if elapsed_seconds <= settings.late_until_minutes * 60:
        return AttendanceStatus.LATE
    return None
