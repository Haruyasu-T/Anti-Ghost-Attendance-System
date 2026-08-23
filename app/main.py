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

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import security
from app.auth import SESSION_COOKIE, require_login
from app.db import get_db, get_session_factory
from app.models import User
from app.auth import CsrfMiddleware


app = FastAPI(title="学内Wi-Fi連動 QR出席管理システム")
app.add_middleware(CsrfMiddleware)


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

    user = db.query(User).filter(User.login_id ==
                                 payload.login_id).one_or_none()

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

    return {"status": "ok"}


@app.post("/auth/logout")
def logout(
    request: Request,
    response: Response,
    user: User = Depends(require_login),
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
def me(user: User = Depends(require_login)):
    return MeResponse(
        login_id=user.login_id,
        role=user.role,
        display_name=user.display_name,
    )
