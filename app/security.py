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
from datetime import datetime, timedelta, timezone
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


# ==================================================== ここから下はDBを使う
#
# `app.models`（B-1）に依存する．models.py が未完成の間も上の A-1〜A-5 を
# 壊さないよう，import は関数の中で行っている（models.py が揃ったら
# トップレベルの import に戻してよい）．
#
# DBセッションは呼び出し側から引数で受け取る．security.py 側でセッションを
# 作らないことで，テスト時に使い捨てのDBを渡せる状態を保つ．


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _to_iso(dt: datetime) -> str:
    """DBに入れる形式（UTCのISO 8601・ミリ秒3桁の固定長）に変換する.

    "2026-08-22T10:00:00.123Z" のように**必ず24文字**になる．

    桁数を固定するのは，時刻の範囲検索を文字列の大小比較で行っているため．
    固定長のUTC文字列なら文字列比較がそのまま時系列比較になるが，桁数が
    揺れると壊れる．同じ瞬間を "…:00Z" と "…:00.000Z" で表すと，'.'(0x2E)は
    'Z'(0x5A)より小さいので後者が常に「古い」と判定され，レート制限が
    失敗を数え落とす．

    `models.py` の CHECK 制約もこの書式を強制している．
    """
    dt = dt.astimezone(timezone.utc)
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.{dt.microsecond // 1000:03d}Z"


def _from_iso(value: str) -> datetime:
    """DBから読んだISO 8601文字列をawareなdatetimeにする."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


# ============================================== A-6. ログインセッション

# セッションIDの長さ（バイト）．推測は現実的でない．
SESSION_ID_BYTES = 32


def create_login_session(
    db,
    user_id: int,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> str:
    """新しいログインセッションを作り，Cookieに入れる生のIDを返す.

    **生のIDはこの戻り値でしか手に入らない**．DBにはSHA-256ハッシュしか
    保存しないので，後から取り出すことはできない（パスワードと同じ考え方）．
    こうしておくとDBが漏れてもセッションを乗っ取られない．
    """
    from app import models

    raw_id = secrets.token_urlsafe(SESSION_ID_BYTES)
    now = _utcnow()
    lifetime = timedelta(hours=get_settings().session_lifetime_hours)

    db.add(
        models.LoginSession(
            id_hash=_sha256_hex(raw_id),
            user_id=user_id,
            created_at=_to_iso(now),
            last_used_at=_to_iso(now),
            expires_at=_to_iso(now + lifetime),
            client_ip=client_ip,
            user_agent=user_agent,
        )
    )
    db.flush()
    return raw_id


def get_session_user(db, session_id: str | None):
    """セッションIDから利用者を引く．無効・期限切れ・失効済みならNone."""
    from app import models

    if not session_id:
        return None

    row = db.get(models.LoginSession, _sha256_hex(session_id))
    if row is None:
        return None
    if row.revoked_at is not None:
        return None
    if _from_iso(row.expires_at) <= _utcnow():
        return None

    row.last_used_at = _to_iso(_utcnow())
    return db.get(models.User, row.user_id)


def revoke_login_session(db, session_id: str | None) -> None:
    """セッションを1つ失効させる（ログアウト）."""
    from app import models

    if not session_id:
        return

    row = db.get(models.LoginSession, _sha256_hex(session_id))
    if row is not None and row.revoked_at is None:
        row.revoked_at = _to_iso(_utcnow())


def revoke_all_sessions_for_user(db, user_id: int) -> int:
    """そのユーザーの有効なセッションをすべて失効させる．失効させた件数を返す.

    教員アカウントの乗っ取りに気付いたときの緊急停止用．
    この操作ができることが，署名付きCookie（JWT等）ではなくサーバー側
    セッションを選んだ理由（decisions.md D-7）．
    """
    from app import models

    now = _to_iso(_utcnow())
    rows = (
        db.query(models.LoginSession)
        .filter(
            models.LoginSession.user_id == user_id,
            models.LoginSession.revoked_at.is_(None),
        )
        .all()
    )
    for row in rows:
        row.revoked_at = now
    return len(rows)


# ======================================================== CSRFトークン
#
# 方式：ログインセッションから HMAC で導出する（サーバー側に保存しない）．
#
#     csrf_token = HMAC-SHA256(TOKEN_SECRET, "csrf:" + セッションIDのハッシュ)
#
# セッションごとに違う値になり，秘密鍵が無ければ計算できない．DBにカラムを
# 足す必要がなく，毎リクエストで再計算して照合できる．
#
# なぜこれで防げるか：攻撃者が用意したページからは，
#   - 同一生成元ポリシーにより，こちらのHTMLに埋め込まれたトークンを読めない
#   - セッションCookieはHttpOnlyなのでJavaScriptから読めない
#   - 仮に読めたとしても TOKEN_SECRET が無いのでトークンを計算できない
# したがって正しい `X-CSRF-Token` を付けたリクエストを作れない．
#
# CookieのSameSite=Laxだけでもクロスサイトの POST は概ね止まるが，
# ブラウザの実装や設定に依存する部分なので，多層防御として併用する．

CSRF_TOKEN_LENGTH = 32
CSRF_HEADER = "X-CSRF-Token"


def csrf_token_for_session(raw_session_id: str | None) -> str:
    """セッションに対応するCSRFトークンを返す．未ログインなら空文字."""
    if not raw_session_id:
        return ""

    message = f"csrf:{_sha256_hex(raw_session_id)}".encode("utf-8")
    digest = hmac.new(
        get_settings().token_secret.encode("utf-8"), message, hashlib.sha256
    ).hexdigest()
    return digest[:CSRF_TOKEN_LENGTH]


def verify_csrf_token(raw_session_id: str | None, provided: str | None) -> bool:
    """送られてきたCSRFトークンが，そのセッションのものか判定する."""
    if not raw_session_id or not provided:
        return False
    # 比較は定数時間で行う（トークン検証と同じ理由）
    return hmac.compare_digest(csrf_token_for_session(raw_session_id), provided)


# ==================================================== A-8. 監査ログ


def _reject_secrets_in_detail(detail: str | None) -> None:
    """秘密鍵がログに紛れ込んでいないか確認する.

    「トークンやパスワードをログに入れない」は運用の約束事だが，
    約束事だけだと事故は起きる．最低限，秘密鍵の混入は機械的に弾く．
    """
    if not detail:
        return
    if get_settings().token_secret in detail:
        raise ValueError("監査ログのdetailに秘密鍵を含めてはいけません")


def write_audit_log(
    db,
    action: str,
    result: str,
    actor_user_id: int | None = None,
    attempted_login_id: str | None = None,
    target_type: str | None = None,
    target_id: int | None = None,
    client_ip: str | None = None,
    device_id: str | None = None,
    detail: str | None = None,
) -> None:
    """監査ログを1件，**呼び出し側のトランザクションに**書く.

    手動修正のように「記録と本体の変更が必ずセットで残る／両方消える」必要が
    ある場面ではこちらを使う．

    逆に，このあと例外を投げてロールバックする経路（ログイン失敗，出席登録の
    拒否など）でこれを使うと，**ログごと消える**．その場合は
    `write_audit_log_now` を使うこと．
    """
    from app import models

    if result not in ("success", "failure"):
        raise ValueError("result は 'success' か 'failure' にしてください")
    _reject_secrets_in_detail(detail)

    db.add(
        models.AuditLog(
            occurred_at=_to_iso(_utcnow()),
            action=action,
            result=result,
            actor_user_id=actor_user_id,
            attempted_login_id=attempted_login_id,
            target_type=target_type,
            target_id=target_id,
            client_ip=client_ip,
            device_id=device_id,
            detail=detail,
        )
    )


def write_audit_log_now(session_factory, **kwargs) -> None:
    """監査ログを**独立したトランザクションで**書いて即コミットする.

    失敗を記録してから例外を投げる経路で使う．呼び出し側のトランザクションが
    ロールバックされても，この記録は残る．

    拒否された試行こそ後から追いたい情報なので，ここを取りこぼさないように
    経路を分けている（⑥追跡可能性）．
    """
    with session_factory() as audit_db:
        write_audit_log(audit_db, **kwargs)
        audit_db.commit()


# ================================================== A-9. 端末の紐付け


class DeviceCheckResult(str, Enum):
    OK = "ok"              # 未登録，または同じ利用者
    CONFLICT = "conflict"  # 別の利用者に紐付いている


def issue_device_id() -> str:
    """新しい端末識別子を発行する.

    HttpOnlyのCookieで配る前提．JavaScriptから読めない形にしておく．
    推測されても他人になりすませるわけではないが，乱数にしておく．
    """
    return secrets.token_urlsafe(16)


def check_device_binding(db, device_id: str | None, user_id: int) -> DeviceCheckResult:
    """端末が別のアカウントに紐付いていないか調べる.

    **見つけてもブロックしない**（decisions.md D-11）．`device_id` はCookieなので
    削除やシークレットモードで簡単に回避できる．回避可能な仕組みをブロックの
    根拠にすると，端末を買い替えた正当な利用者を弾く一方で，本気の攻撃者は
    素通りする．検知して記録するところまでが用途．

    衝突を見つけても**紐付けを書き換えない**．書き換えを許すと，あとから来た
    アカウントが端末を「奪える」ことになり，記録として意味をなさなくなる．
    """
    from app import models

    if not device_id:
        return DeviceCheckResult.OK

    now = _to_iso(_utcnow())
    binding = db.get(models.DeviceBinding, device_id)

    if binding is None:
        db.add(models.DeviceBinding(
            device_id=device_id,
            user_id=user_id,
            first_seen_at=now,
            last_seen_at=now,
        ))
        return DeviceCheckResult.OK

    if binding.user_id != user_id:
        return DeviceCheckResult.CONFLICT

    binding.last_seen_at = now
    return DeviceCheckResult.OK


# ==================================================== A-10. レート制限


def is_login_rate_limited(db, login_id: str | None, client_ip: str | None) -> bool:
    """ログイン試行を拒否すべきかを判定する.

    判定のしかた：
      直近の失敗を `LOGIN_WINDOW_MINUTES` 分の幅で数え，`LOGIN_MAX_FAILURES`
      件以上あれば，**最後の失敗から `LOGIN_LOCKOUT_MINUTES` の間**は拒否する．

    失敗するたびにロックが延びるので，総当たりを続けている限り解除されない．

    `login_id` 別と `client_ip` 別の両方を見る．片方だけだと，
      - `login_id` だけ … 1つのIPから多数のIDを総当たりされて素通り
      - `client_ip` だけ … 分散したIPから1つのIDを狙われて素通り
    のどちらかを取り逃す．
    """
    from app import models

    settings = get_settings()
    now = _utcnow()

    # ロック解除の判定に必要な分だけ遡れば足りる
    lookback = timedelta(
        minutes=settings.login_window_minutes + settings.login_lockout_minutes
    )
    since = _to_iso(now - lookback)

    def _locked_by(column, value) -> bool:
        if not value:
            return False

        # 時刻はUTCの固定長ISO文字列なので，文字列の大小比較で時系列比較になる
        times = [
            row[0]
            for row in db.query(models.AuditLog.occurred_at)
            .filter(
                models.AuditLog.action == "login",
                models.AuditLog.result == "failure",
                column == value,
                models.AuditLog.occurred_at >= since,
            )
            .all()
        ]
        if not times:
            return False

        last_failure = max(_from_iso(t) for t in times)
        if now - last_failure >= timedelta(minutes=settings.login_lockout_minutes):
            return False  # ロック期間を過ぎている

        # 最後の失敗から遡って window 分の失敗を数える
        window_start = last_failure - timedelta(minutes=settings.login_window_minutes)
        recent = [t for t in times if _from_iso(t) >= window_start]
        return len(recent) >= settings.login_max_failures

    return (
        _locked_by(models.AuditLog.attempted_login_id, login_id)
        or _locked_by(models.AuditLog.client_ip, client_ip)
    )


# ==================================================== A-11. バースト検知


def detect_burst(
    db,
    attendance_session_id: int,
    device_id: str | None = None,
    client_ip: str | None = None,
) -> bool:
    """短時間に同じ端末（またはIP）から複数人の登録があったかを判定する.

    数えるのは**登録件数ではなく，登録した人数（重複しない `user_id`）**．
    1人が1回目と2回目を読むのは正常なので，件数で数えると誤検知になる．

    `device_id` での判定が主で，`client_ip` は補助．
    **外部にデプロイすると，学内Wi-Fiの学生は全員が大学のNATの出口IPで
    届くため，IPでの判定はほぼ機能しない**（全員が同じIPになる）．
    IPを見るのは，学内が複数の出口に分かれている場合や，ローカルでの
    検証時に意味を持つ程度と考えておく．
    """
    from app import models

    settings = get_settings()
    since = _to_iso(_utcnow() - timedelta(seconds=settings.burst_window_seconds))

    def _distinct_users(column, value) -> int:
        if not value:
            return 0
        return (
            db.query(models.AttendanceScan.user_id)
            .filter(
                models.AttendanceScan.attendance_session_id == attendance_session_id,
                column == value,
                models.AttendanceScan.scanned_at >= since,
            )
            .distinct()
            .count()
        )

    threshold = settings.burst_threshold_count
    return (
        _distinct_users(models.AttendanceScan.device_id, device_id) >= threshold
        or _distinct_users(models.AttendanceScan.client_ip, client_ip) >= threshold
    )
