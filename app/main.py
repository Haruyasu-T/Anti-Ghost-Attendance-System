"""
FastAPI エントリポイント（フェーズ3 担当B）．

api-design.md の「認証」セクションに対応する3エンドポイントを実装する．

    POST /auth/login   ... ログイン．レート制限あり
    POST /auth/logout  ... ログアウト
    GET  /auth/me      ... 自分のロールと表示名

方針
----------------------------------------------------------------------
- 検証に失敗したら常に拒否する（api-design.md「前提」）．
- ログインID存在有無とパスワード誤りは区別しない（401で統一）．
- Cookieにはセッションの乱数IDのみを入れる．ユーザーIDやロールは入れない．
- セッションの発行・検証・失効，レート制限，監査ログの記録はすべて
  `security.py`（担当A）の責務．このファイルはそれらを呼び出すだけにし，
  ハッシュ化や時刻フォーマットのロジックをここに複製しない
  （security-interface.md「境界を守るための取り決め」）．
- DB接続も `app/db.py`（担当A暫定実装）に一本化する．このファイルで
  独自の Engine / SessionLocal を作らない．
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import models, security
from app.auth import (
    SESSION_COOKIE,
    require_course_owner,
    require_login,
    require_session_owner,
)
from app.config import get_settings
from app.db import get_db, get_session_factory

# 授業開始時刻の入力許容幅．現在時刻からこれ以上離れた scheduled_start_at は
# 誤入力とみなして拒否する（api-design.md「現在時刻の前後数時間以内くらい」）．
# 値の根拠が薄いのでいったんここに置くが，config.py の Settings に寄せて
# 運用しながら調整できるようにしてもよい（未決定事項として decisions.md に
# 記載する候補）．
SCHEDULED_START_TOLERANCE = timedelta(hours=3)

app = FastAPI(title="学内Wi-Fi連動 QR出席管理システム")


@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------- スキーマ

class LoginRequest(BaseModel):
    login_id: str
    password: str


class MeResponse(BaseModel):
    login_id: str
    role: str
    display_name: str


class StartSessionRequest(BaseModel):
    # 例: "2026-07-27T01:00:00Z"．タイムゾーンは必須（省略時はUTCと決め打ちしない）．
    scheduled_start_at: str


class AttendanceSessionResponse(BaseModel):
    id: int
    course_id: int
    scheduled_start_at: str
    started_at: str
    closed_at: str | None
    status: str
    required_scan_count: int


class TokenResponse(BaseModel):
    token: str
    rotate_seconds: int
    next_rotate_at: str


def _to_session_response(sess: models.AttendanceSession) -> AttendanceSessionResponse:
    return AttendanceSessionResponse(
        id=sess.id,
        course_id=sess.course_id,
        scheduled_start_at=sess.scheduled_start_at,
        started_at=sess.started_at,
        closed_at=sess.closed_at,
        status=sess.status,
        required_scan_count=sess.required_scan_count,
    )


def _parse_scheduled_start_at(raw: str) -> datetime:
    """教員が入力した授業開始時刻を検証してUTCのdatetimeにする.

    `security.from_iso` を使わないのは意図的．あちらはDBから読んだ値
    （タイムゾーン欠落なら黙ってUTCとみなす）用で，クライアント入力に
    同じ緩さを適用すると，フロントがJST→UTC変換を忘れて送ってきた場合に
    9時間ズレたセッションが黙って作られてしまう（④クライアントを信用しない）．
    ここでは形式不備・タイムゾーン欠落をどちらも明示的に拒否する．
    """
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scheduled_start_at の形式が不正です",
        )

    if parsed.tzinfo is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scheduled_start_at にはタイムゾーンを含めてください",
        )

    scheduled = parsed.astimezone(timezone.utc)
    now = datetime.now(timezone.utc)
    if abs((scheduled - now).total_seconds()) > SCHEDULED_START_TOLERANCE.total_seconds():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scheduled_start_at が現在時刻から離れすぎています",
        )

    return scheduled


# -------------------------------------------------------------- エンドポイント

@app.post("/auth/login")
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    # `request.client.host` を直接使わない．プロキシ経由の構成では偽装され得るため，
    # 必ず security.get_client_ip を通す（TRUSTED_PROXY_COUNT を踏まえて判定する）．
    client_ip = security.get_client_ip(request)

    if security.is_login_rate_limited(db, payload.login_id, client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="しばらく待ってから再度お試しください",
        )

    user = db.query(models.User).filter(
        models.User.login_id == payload.login_id).one_or_none()

    # 「IDが存在しない」と「パスワードが違う」を区別しない．
    # verify_password はハッシュがNoneでもダミーハッシュと照合するため，
    # タイミングでアカウントの存在有無が漏れない．
    password_hash = user.password_hash if user is not None else None
    if not security.verify_password(payload.password, password_hash) or user is None:
        # このあと例外でロールバックする経路なので，`db`（呼び出し側のトランザクション）
        # に監査ログを書いても一緒に消える．write_audit_log_now で独立したトランザクション
        # に書く（security-interface.md）．
        security.write_audit_log_now(
            get_session_factory(),
            action="login",
            result="failure",
            attempted_login_id=payload.login_id,
            client_ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="IDまたはパスワードが違います")

    # セッション固定攻撃対策として，ログイン成功のたびに新しいセッションIDを発行する．
    # ハッシュ化・有効期限・時刻フォーマットはすべて security.create_login_session の
    # 内部に閉じている．ここでは生のIDを受け取ってCookieに入れるだけ．
    raw_session_id = security.create_login_session(
        db,
        user.id,
        client_ip=client_ip,
        user_agent=request.headers.get("user-agent"),
    )
    security.write_audit_log(
        db,
        action="login",
        result="success",
        actor_user_id=user.id,
        client_ip=client_ip,
    )

    response.set_cookie(
        key=SESSION_COOKIE,
        value=raw_session_id,
        httponly=True,
        secure=True,
        samesite="lax",  # SameSite=Strict にしない理由は api-design.md 参照
    )

    # todo: CSRFトークンの発行方法（Cookie+ヘッダ方式か，レスポンスボディで
    # 返すか）が security-interface.md 側で未確定のため，ここでは発行しない．

    return {"status": "ok"}


@app.post("/auth/logout")
def logout(
    request: Request,
    response: Response,
    user: models.User = Depends(require_login),
    db: Session = Depends(get_db),
):
    security.revoke_login_session(db, request.cookies.get(SESSION_COOKIE))
    security.write_audit_log(
        db,
        action="logout",
        result="success",
        actor_user_id=user.id,
        client_ip=security.get_client_ip(request),
    )
    response.delete_cookie(key=SESSION_COOKIE)
    return {"status": "ok"}


@app.get("/auth/me", response_model=MeResponse)
def me(user: models.User = Depends(require_login)):
    return MeResponse(
        login_id=user.login_id,
        role=user.role,
        display_name=user.display_name,
    )


# -------------------------------------------------- 出席セッション系（B-4）
#
# 認可は require_course_owner / require_session_owner に任せ，ここには
# 「担当授業か」の if を書かない（api-design.md「認可チェックの書き方」）．
# course.teacher_id / sess.created_by は依存関数の時点で「ログイン中の教員
# 本人」であることが保証済みなので，監査ログの actor_user_id にもそのまま使う．

@app.post(
    "/courses/{course_id}/attendance-sessions",
    response_model=AttendanceSessionResponse,
)
def start_attendance_session(
    payload: StartSessionRequest,
    request: Request,
    course: models.Course = Depends(require_course_owner),
    db: Session = Depends(get_db),
):
    scheduled_start_at = _parse_scheduled_start_at(payload.scheduled_start_at)

    # 同じ授業で open のセッションが既にあれば409（api-design.md）．
    existing_open = (
        db.query(models.AttendanceSession)
        .filter(
            models.AttendanceSession.course_id == course.id,
            models.AttendanceSession.status == "open",
        )
        .first()
    )
    if existing_open is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="この授業には開催中のセッションが既にあります",
        )

    now = datetime.now(timezone.utc)
    session_row = models.AttendanceSession(
        course_id=course.id,
        # scheduled_start_at: 授業の開始"予定"時刻（判定基準）．
        # started_at: 教員がこのセッションを開始した実時刻．
        # 両者を分ける理由は db-design.md 参照（教員の開始操作が遅れても
        # 遅刻判定がずれないようにするため）．
        scheduled_start_at=security.to_iso(scheduled_start_at),
        started_at=security.to_iso(now),
        status="open",
        required_scan_count=1,
        token_salt=security.new_token_salt(),
        created_by=course.teacher_id,
    )
    db.add(session_row)
    db.flush()  # id を確定させる（コミットは get_db に任せる）

    security.write_audit_log(
        db,
        action="session_start",
        result="success",
        actor_user_id=course.teacher_id,
        client_ip=security.get_client_ip(request),
        target_type="attendance_session",
        target_id=session_row.id,
    )

    return _to_session_response(session_row)


@app.get(
    "/attendance-sessions/{attendance_session_id}/token",
    response_model=TokenResponse,
)
def get_attendance_session_token(
    sess: models.AttendanceSession = Depends(require_session_owner),
):
    """現在有効なトークンを返す．

    **このシステムで最も認可を間違えてはいけないエンドポイント**（api-design.md）．
    学生が呼べてしまうと，教室のQRを見ずにトークンが手に入り，動的QRという
    対策が丸ごと無意味になる．認可は Depends(require_session_owner) のみに
    委ね，ここに追加の if を書かない．
    """
    if sess.status != "open":
        # 仕様書に明記はないが，終了済みセッションのQRを投影し続けたまま
        # トークンだけ配り続けるのは事故のもとなので閉じている．
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="セッションは終了しています"
        )

    settings = get_settings()
    token = security.generate_token(sess.id, sess.token_salt)

    # window の計算式は db-design.md / security-interface.md に明記された
    # 公開の契約（floor(unix時刻 / QR_ROTATE_SECONDS)）．generate_token 内部の
    # 非公開ヘルパーを複製しているわけではなく，この式自体が契約になっている．
    now = datetime.now(timezone.utc)
    window_index = int(now.timestamp()) // settings.qr_rotate_seconds
    next_rotate_at = datetime.fromtimestamp(
        (window_index + 1) * settings.qr_rotate_seconds, tz=timezone.utc
    )

    return TokenResponse(
        token=token,
        rotate_seconds=settings.qr_rotate_seconds,
        next_rotate_at=next_rotate_at.isoformat().replace("+00:00", "Z"),
    )


@app.post(
    "/attendance-sessions/{attendance_session_id}/rescan",
    response_model=AttendanceSessionResponse,
)
def rescan_attendance_session(
    request: Request,
    sess: models.AttendanceSession = Depends(require_session_owner),
    db: Session = Depends(get_db),
):
    if sess.status != "open":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="セッションは終了しています"
        )

    sess.required_scan_count += 1

    security.write_audit_log(
        db,
        action="rescan_start",
        result="success",
        actor_user_id=sess.created_by,
        client_ip=security.get_client_ip(request),
        target_type="attendance_session",
        target_id=sess.id,
        detail=f"required_scan_count={sess.required_scan_count}",
    )

    return _to_session_response(sess)


@app.post(
    "/attendance-sessions/{attendance_session_id}/rotate-token",
    response_model=AttendanceSessionResponse,
)
def rotate_attendance_session_token(
    request: Request,
    sess: models.AttendanceSession = Depends(require_session_owner),
    db: Session = Depends(get_db),
):
    if sess.status != "open":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="セッションは終了しています"
        )

    # 塩を作り直すだけで，出回っている全QRが即座に無効になる（decisions.md D-3）．
    sess.token_salt = security.new_token_salt()

    security.write_audit_log(
        db,
        action="token_rotate",
        result="success",
        actor_user_id=sess.created_by,
        client_ip=security.get_client_ip(request),
        target_type="attendance_session",
        target_id=sess.id,
    )

    return _to_session_response(sess)


@app.post(
    "/attendance-sessions/{attendance_session_id}/close",
    response_model=AttendanceSessionResponse,
)
def close_attendance_session(
    request: Request,
    sess: models.AttendanceSession = Depends(require_session_owner),
    db: Session = Depends(get_db),
):
    if sess.status != "open":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="セッションはすでに終了しています"
        )

    sess.status = "closed"
    sess.closed_at = security.to_iso(datetime.now(timezone.utc))

    security.write_audit_log(
        db,
        action="session_close",
        result="success",
        actor_user_id=sess.created_by,
        client_ip=security.get_client_ip(request),
        target_type="attendance_session",
        target_id=sess.id,
    )

    return _to_session_response(sess)
