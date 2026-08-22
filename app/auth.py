"""認可の依存関数（A-7）．

`security.py` はHTTPを知らない純粋なロジックに保ちたいので，
FastAPIの `Request` や `HTTPException` を扱う部分はこちらに分けている．

**各エンドポイントに `if` で認可を書かないこと．** 1箇所の書き忘れが
そのまま脆弱性になる．ここで定義した依存関数を `Depends` で宣言的に付け，
レビューでは「宣言が付いているか」を見るだけで漏れが分かる状態にする．

使い方：

    @app.get("/attendance-sessions/{attendance_session_id}/token")
    def get_token(sess = Depends(require_session_owner)):
        ...
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app import security
from app.db import get_db

# Cookie名．JavaScriptから触らせないため，どちらもHttpOnlyで発行する．
SESSION_COOKIE = "session"
DEVICE_COOKIE = "device_id"


def get_current_user(request: Request, db: Session = Depends(get_db)):
    """ログイン中の利用者を返す．未ログインなら401.

    誰であるかは**Cookieのセッションからだけ**決める．リクエストに含まれる
    ユーザーIDや学籍番号は一切見ない（他人になりすます経路を作らないため）．
    """
    raw_session_id = request.cookies.get(SESSION_COOKIE)
    user = security.get_session_user(db, raw_session_id)
    if user is None:
        raise HTTPException(status_code=401, detail="ログインが必要です")
    return user


def require_role(*allowed_roles: str):
    """指定したロールだけを通す依存関数を作る.

        user = Depends(require_role("teacher"))
    """
    if not allowed_roles:
        raise ValueError("ロールを1つ以上指定してください")

    def dependency(user=Depends(get_current_user)):
        if user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="権限がありません")
        return user

    return dependency


def require_course_owner(
    course_id: int,
    user=Depends(require_role("teacher")),
    db: Session = Depends(get_db),
):
    """パスの `course_id` が，ログイン中の教員の担当授業かを確認する.

    ロールが teacher であることだけ確認して `course_id` をそのまま信じると，
    他の教員の授業を操作できてしまう（水平権限昇格）．

    見つからない場合と他人の授業の場合で応答を分けない．403を返すと
    「そのIDの授業は存在する」と分かってしまうので，どちらも404にする．
    """
    from app import models

    course = db.get(models.Course, course_id)
    if course is None or course.teacher_id != user.id:
        raise HTTPException(status_code=404, detail="見つかりません")
    return course


def require_session_owner(
    attendance_session_id: int,
    user=Depends(require_role("teacher")),
    db: Session = Depends(get_db),
):
    """パスの `attendance_session_id` が，ログイン中の教員の担当授業かを確認する.

    `GET /attendance-sessions/{id}/token` は**必ずこれを通すこと**．
    学生がトークンを取得できてしまうと，教室のQRを見ずに出席できることになり，
    動的QRという対策が丸ごと無意味になる（threat-model.md）．
    """
    from app import models

    attendance_session = db.get(models.AttendanceSession, attendance_session_id)
    if attendance_session is None:
        raise HTTPException(status_code=404, detail="見つかりません")

    course = db.get(models.Course, attendance_session.course_id)
    if course is None or course.teacher_id != user.id:
        raise HTTPException(status_code=404, detail="見つかりません")

    return attendance_session
