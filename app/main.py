"""
FastAPI エントリポイント．

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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import models, security
from app.auth import (
    DEVICE_COOKIE,
    SESSION_COOKIE,
    require_course_owner,
    require_login,
    require_role,
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
        #
        # 先に db.rollback() しておく．本来ここまでの db は読み取りだけなので今は
        # 問題にならないが，別コネクションで書き込む write_audit_log_now と
        # db 側の未コミット状態が重なると "database is locked"（書き込みロックの
        # 循環待ち）になり得る（register_attendance の _reject_now で実際に踏んだ）．
        # 呼び出し順を安全側に倒しておく．
        db.rollback()
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

    # device_id は「端末を跨いで・ログインを跨いで」同じ値を保つことに意味がある
    # （device_bindings による端末の使い回し検知はこれが前提）．
    # 既に持っている端末には発行し直さない．毎回発行し直すと，ログインの度に
    # 別端末として扱われてしまい，検知の意味がなくなる．
    if request.cookies.get(DEVICE_COOKIE) is None:
        response.set_cookie(
            key=DEVICE_COOKIE,
            value=security.issue_device_id(),
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=400 * 24 * 60 * 60,  # ブラウザが許容する上限に寄せた長期Cookie
        )

    # todo: CSRFトークンの発行方法（Cookie+ヘッダ方式か，レスポンスボディで
    # 返すか）が security-interface.md 側で未確定のため，ここでは発行しない．
    # B-5（POST /attendances）の検証順序#3もこれに依存するため，現状は
    # スキップしている（実装時にコメントを入れて明示）．

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


# ------------------------------------------------------- 出席登録（B-5・核心）
#
# api-design.md「POST /attendances（出席登録）」の検証順序をそのままの順で
# 実装する．IP検証をトークン検証より前に置くのは意図的（D-5：学外からの
# 試行にトークンの有効性を漏らさないため）．
#
# 実装時点で次の3点が未確定・未実装のまま残っている（担当Aと要確認）：
#   #3  CSRF検証 … 発行方法が security-interface.md 側で未確定のため todo
#   #7  「期限切れ」と「不正」の区別 … security.verify_token の公開契約は
#       bool のみなので区別できない．今は「無効なQRです」に統一している
#   #10 device_id の発行元 … login 時に（未発行なら）発行するようにした
#       （このファイル内 /auth/login 参照）

class AttendanceRegisterRequest(BaseModel):
    attendance_session_id: int
    token: str


class AttendanceRegisterResponse(BaseModel):
    status: str  # "present" | "late"
    scan_seq: int
    recorded_at: str


@app.post("/attendances", response_model=AttendanceRegisterResponse)
def register_attendance(
    payload: AttendanceRegisterRequest,
    request: Request,
    user: models.User = Depends(require_role("student")),
    db: Session = Depends(get_db),
):
    # todo: #3 CSRFトークンの検証．login側の発行が未確定のため未実装．
    # 発行方式が決まり次第，ここに require_csrf 相当のチェックを先頭で入れる．

    client_ip = security.get_client_ip(request)
    device_id = request.cookies.get(DEVICE_COOKIE)

    def _reject_now(status_code: int, detail: str, log_detail: str, **log_extra) -> HTTPException:
        # require_login が触った last_used_at の更新など，db 側に未コミットの
        # 書き込みが残っていることがある（autoflushでSQLiteに書き込み済みだが
        # 未コミット＝書き込みロックを保持したまま）．write_audit_log_now は
        # 別コネクションで書き込むため，先に db 側のロックを手放しておかないと
        # 「write_audit_log_now が終わるまで db は解放されない／db が解放される
        # まで write_audit_log_now が書けない」という循環待ちで
        # "database is locked" になる．ここまでの経路では db.add() をまだ
        # 呼んでいないので，rollback で失うものはない．
        db.rollback()
        security.write_audit_log_now(
            get_session_factory(),
            action="attendance_register",
            result="failure",
            actor_user_id=user.id,
            client_ip=client_ip,
            device_id=device_id,
            detail=log_detail,
            **log_extra,
        )
        return HTTPException(status_code=status_code, detail=detail)

    # 4. IP検証．トークン検証より先に行う（D-5）．
    if not security.is_campus_ip(client_ip):
        raise _reject_now(
            status.HTTP_403_FORBIDDEN, "学内ネットワークからアクセスしてください", "off_campus"
        )

    # 5. セッションの存在・状態
    sess = db.get(models.AttendanceSession, payload.attendance_session_id)
    if sess is None:
        raise _reject_now(
            status.HTTP_404_NOT_FOUND, "見つかりません", "session_not_found",
            target_type="attendance_session", target_id=payload.attendance_session_id,
        )
    if sess.status != "open":
        raise _reject_now(
            status.HTTP_409_CONFLICT, "このセッションは終了しています", "session_closed",
            target_type="attendance_session", target_id=sess.id,
        )

    # 6. 履修確認
    enrolled = (
        db.query(models.Enrollment)
        .filter(
            models.Enrollment.course_id == sess.course_id,
            models.Enrollment.user_id == user.id,
        )
        .one_or_none()
    )
    if enrolled is None:
        raise _reject_now(
            status.HTTP_403_FORBIDDEN, "この授業の履修者ではありません", "not_enrolled",
            target_type="attendance_session", target_id=sess.id,
        )

    # 7. トークン検証．期限切れと不正の区別はしない（上記の理由により）．
    if not security.verify_token(sess.id, sess.token_salt, payload.token):
        raise _reject_now(
            status.HTTP_403_FORBIDDEN, "無効なQRです", "invalid_token",
            target_type="attendance_session", target_id=sess.id,
        )

    # 8. 何回目の読み取りか
    scan_seq = (
        db.query(models.AttendanceScan)
        .filter(
            models.AttendanceScan.attendance_session_id == sess.id,
            models.AttendanceScan.user_id == user.id,
        )
        .count()
        + 1
    )
    if scan_seq > sess.required_scan_count:
        raise _reject_now(
            status.HTTP_409_CONFLICT,
            "この回の出席は既に登録されています",
            "already_registered",
            target_type="attendance_session", target_id=sess.id,
        )

    now = datetime.now(timezone.utc)

    # 9. 受付時間帯の判定は1回目のみ．2回目以降は在室確認なので見ない．
    if scan_seq == 1:
        scheduled_start_at = security.from_iso(sess.scheduled_start_at)
        classified = security.classify_attendance(scheduled_start_at, now)
        if classified is None:
            raise _reject_now(
                status.HTTP_403_FORBIDDEN, "受付時間を過ぎています", "outside_window",
                target_type="attendance_session", target_id=sess.id,
            )
        attendance_status = classified.value
    else:
        existing = (
            db.query(models.Attendance)
            .filter(
                models.Attendance.attendance_session_id == sess.id,
                models.Attendance.user_id == user.id,
            )
            .one_or_none()
        )
        if existing is None:
            # scan_seq>1 に到達しているのに1回目の記録が無いのは整合性が
            # 崩れている状態．判定できないなら拒否する（⑤安全なデフォルト）．
            raise _reject_now(
                status.HTTP_409_CONFLICT,
                "出席記録の状態を確認できません",
                "inconsistent_state",
                target_type="attendance_session", target_id=sess.id,
            )
        attendance_status = existing.status

    # 10. 端末の紐付け確認．ブロックしない．検知して記録するだけ（D-11）．
    if device_id:
        conflict = security.check_device_binding(db, device_id, user.id)
        if conflict == security.DeviceCheckResult.CONFLICT:
            security.write_audit_log(
                db,
                action="device_conflict",
                result="success",
                actor_user_id=user.id,
                client_ip=client_ip,
                device_id=device_id,
                target_type="attendance_session",
                target_id=sess.id,
            )

    # 11. 記録．一意制約違反は409に変換する．
    scanned_at = security.to_iso(now)
    db.add(
        models.AttendanceScan(
            attendance_session_id=sess.id,
            user_id=user.id,
            scan_seq=scan_seq,
            scanned_at=scanned_at,
            client_ip=client_ip,
            device_id=device_id,
        )
    )
    if scan_seq == 1:
        db.add(
            models.Attendance(
                attendance_session_id=sess.id,
                user_id=user.id,
                status=attendance_status,
                record_source="auto",
                first_recorded_at=scanned_at,
            )
        )

    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise _reject_now(
            status.HTTP_409_CONFLICT,
            "この回の出席は既に登録されています",
            "duplicate_scan",
            target_type="attendance_session", target_id=sess.id,
        )

    # 12. 監査ログ（成功）．本体の記録と同じトランザクションに書く．
    security.write_audit_log(
        db,
        action="attendance_register",
        result="success",
        actor_user_id=user.id,
        client_ip=client_ip,
        device_id=device_id,
        target_type="attendance_session",
        target_id=sess.id,
        detail=f"scan_seq={scan_seq}",
    )

    return AttendanceRegisterResponse(
        status=attendance_status,
        scan_seq=scan_seq,
        recorded_at=scanned_at,
    )
