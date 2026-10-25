"""管理者による学生・教員アカウントの一覧取得と作成。

main.py に依存せず、認可・DB・ハッシュ化は既存の共通モジュールを使う。
コミットとロールバックは get_db がリクエスト単位で行う。
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import models, security
from app.auth import require_role
from app.db import get_db

router = APIRouter(tags=["admin-users"])
require_admin = require_role("admin")


class AdminUserRow(BaseModel):
    id: int
    login_id: str
    display_name: str
    role: str


class UserCreateRequest(BaseModel):
    login_id: str = Field(min_length=1, max_length=100)
    display_name: str = Field(min_length=1, max_length=100)
    role: str
    password: str = Field(min_length=8, max_length=128, repr=False)


def to_admin_user_row(user: models.User) -> AdminUserRow:
    return AdminUserRow(
        id=user.id,
        login_id=user.login_id,
        display_name=user.display_name,
        role=user.role,
    )


@router.get("/admin/users", response_model=list[AdminUserRow])
def admin_list_users(
    _: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """割り当ての候補にする利用者の一覧.

    `password_hash` は返さない．レスポンスの形を固定しているので，モデルに
    列を足しても勝手に露出しない．他の管理者アカウントも一覧に出さない
    （割り当ての候補にならないため）．
    """
    users = (
        db.query(models.User)
        .filter(models.User.role.in_(["teacher", "student"]))
        .order_by(models.User.role, models.User.login_id)
        .all()
    )
    return [to_admin_user_row(u) for u in users]


@router.post("/admin/users", response_model=AdminUserRow, status_code=201)
def admin_create_user(
    payload: UserCreateRequest,
    request: Request,
    user: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    login_id = payload.login_id.strip()
    display_name = payload.display_name.strip()
    if not login_id or not display_name:
        raise HTTPException(status_code=400, detail="ログインIDと氏名を入力してください")
    if any(char.isspace() for char in login_id):
        raise HTTPException(status_code=400, detail="ログインIDに空白は使用できません")
    if payload.role not in ("student", "teacher"):
        raise HTTPException(status_code=400, detail="権限には学生または教員を指定してください")
    if not payload.password.strip():
        raise HTTPException(status_code=400, detail="空白だけのパスワードは使用できません")
    if db.query(models.User.id).filter(models.User.login_id == login_id).first():
        raise HTTPException(status_code=409, detail="このログインIDは既に使用されています")

    created = models.User(
        login_id=login_id, display_name=display_name, role=payload.role,
        password_hash=security.hash_password(payload.password),
    )
    # 同時に同じIDが登録された場合も、トランザクションを壊さず重複として返す。
    try:
        with db.begin_nested():
            db.add(created)
            db.flush()
    except IntegrityError:
        raise HTTPException(status_code=409, detail="このログインIDは既に使用されています")

    security.write_audit_log(
        db, action="user_create", result="success", actor_user_id=user.id,
        client_ip=security.get_client_ip(request), target_type="user",
        target_id=created.id, detail=f"role={created.role}",
    )
    return to_admin_user_row(created)


