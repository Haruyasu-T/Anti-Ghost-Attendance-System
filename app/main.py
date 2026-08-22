from __future__ import annotations
from fastapi import FastAPI
from app.security import verify_password
# from app.security import require_login, record_login_attempt, check_login_rate_limit
from app.models import LoginSession, User, create_db_engine
from sqlalchemy.orm import Session, sessionmaker
from pydantic import BaseModel
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response, status
from datetime import datetime, timedelta, timezone
import secrets
import hashlib

app = FastAPI(title="学内Wi-Fi連動 QR出席管理システム")


@app.get("/health")
def health():
    return {"status": "ok"}


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
- セッションの発行（login_sessions への INSERT／Cookie設定）と失効
  （revoked_at の更新）は担当Bの責務としてこのファイルに実装している．
- 一方，セッションの「検証」（require_login: 存在・失効・有効期限の確認），
  レート制限，監査ログの記録は security.py（担当A）の責務であり，このファ
  イルの担当範囲外．該当する呼び出しは import ごとコメントアウトしている．
  担当Aの実装が完了し次第，コメントを外して有効化する．
  - `require_login` 未実装のため，現状 `/auth/logout` はCookieの有無のみで
    判定する暫定ガードで代替しており，`/auth/me` は501を返す．
"""


# ---------------------------------------------------------------- DB

# 接続文字列は仮でここに直書きする．
DATABASE_URL = "sqlite:///./app.db"

engine = create_db_engine(DATABASE_URL, connect_args={
                          "check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------- セッション設定

# ログインセッションの有効期間．要件に明示がないため仮値．
# 本来は設定ファイル（app.config.get_settings()）に寄せるべき値だが，
# get_settings() 側にこの項目があるか未確認のため，ここでは定数にしている．
SESSION_TTL = timedelta(hours=8)
SESSION_COOKIE_NAME = "session"


def _hash_session_id(raw_session_id: str) -> str:
    """Cookieに入れる生のセッションIDをDB保存用にハッシュ化する（db-design.md）．"""
    return hashlib.sha256(raw_session_id.encode("utf-8")).hexdigest()


def _utcnow_iso() -> str:
    """models.py が要求する UTC ISO 8601（'...Z'）形式の現在時刻文字列を返す．"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---------------------------------------------------------------- スキーマ

class LoginRequest(BaseModel):
    login_id: str
    password: str


class MeResponse(BaseModel):
    login_id: str
    role: str
    display_name: str


# -------------------------------------------------------- 認可の依存関数
#
# require_login() は security.py（担当A）の責務．
# セッションの検証・失効判定・有効期限判定のロジックはすべてそちら側に
# 実装される想定のため，ここには置かない．
#
# 担当Aの実装がまだ完了していない可能性があるため，呼び出し部分は
# コメントアウトしている．import が解決でき次第，下記のコメントを外す．

# def get_current_user(
#     request: Request,
#     db: Session = Depends(get_db),
#     session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
# ) -> User:
#     """require_login() を呼び出すだけの薄いラッパー．
#
#     api-design.md の「認可チェックの書き方」に合わせ，エンドポイント本体には
#     認可ロジックを書かず，この関数を Depends として宣言的に付ける．
#     検証本体（セッション存在確認・失効確認・有効期限確認）は security.py 側。
#     """
#     return require_login(request=request, db=db, session=session)


# -------------------------------------------------------------- エンドポイント

@app.post("/auth/login")
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    # todo: レート制限は security.py 側の責務．
    # check_login_rate_limit(db, login_id=payload.login_id, client_ip=request.client.host)
    # が429を投げる想定．未実装のためコメントアウト．
    # check_login_rate_limit(
    #     db,
    #     login_id=payload.login_id,
    #     client_ip=request.client.host if request.client else None,
    # )

    user = db.query(User).filter(User.login_id ==
                                 payload.login_id).one_or_none()

    # 「IDが存在しない」と「パスワードが違う」を区別しない．
    # verify_password はハッシュがNoneでもダミーハッシュと照合するため，
    # タイミングでアカウントの存在有無が漏れない．
    password_hash = user.password_hash if user is not None else None
    if not verify_password(payload.password, password_hash) or user is None:
        # todo: 監査ログは security.py 側の責務．
        # record_login_attempt(
        #     db,
        #     login_id=payload.login_id,
        #     client_ip=request.client.host if request.client else None,
        #     result="failure",
        # )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="IDまたはパスワードが違います")

    # セッション固定攻撃対策として，ログイン成功のたびに新しいセッションIDを発行する．
    raw_session_id = secrets.token_urlsafe(32)
    id_hash = _hash_session_id(raw_session_id)

    now = datetime.now(timezone.utc)
    expires_at = now + SESSION_TTL

    login_session = LoginSession(
        id_hash=id_hash,
        user_id=user.id,
        last_used_at=_utcnow_iso(),
        expires_at=expires_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        client_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    db.add(login_session)
    db.commit()

    # todo: 監査ログは security.py 側の責務．
    # record_login_attempt(
    #     db,
    #     login_id=payload.login_id,
    #     client_ip=request.client.host if request.client else None,
    #     result="success",
    # )

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
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
    response: Response,
    db: Session = Depends(get_db),
    session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    # todo: require_login が実装され次第，以下を有効化する．
    # current_user: User = Depends(get_current_user),
):
    # todo: 本来は require_login が401を返す箇所．暫定ガード．
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="ログインが必要です")

    id_hash = _hash_session_id(session)
    login_session = db.get(LoginSession, id_hash)
    if login_session is not None:
        login_session.revoked_at = _utcnow_iso()
        db.commit()

    # todo: 監査ログは security.py 側の責務．
    # record_logout(db, user_id=current_user.id)

    response.delete_cookie(key=SESSION_COOKIE_NAME)
    return {"status": "ok"}


@app.get("/auth/me", response_model=MeResponse)
def me(
    # todo: require_login が実装され次第，以下を有効化する．
    # current_user: User = Depends(get_current_user),
):
    # todo: 上記が有効化されるまで /auth/me は動作しない（暫定的に501）．
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="require_login 未実装のため /auth/me は未提供です",
    )
    # return MeResponse(
    #     login_id=current_user.login_id,
    #     role=current_user.role,
    #     display_name=current_user.display_name,
    # )
