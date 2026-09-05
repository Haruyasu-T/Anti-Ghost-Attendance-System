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

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import models, security
from app.auth import (
    DEVICE_COOKIE,
    SESSION_COOKIE,
    CsrfMiddleware,
    csrf_token_for_request,
    require_course_owner,
    require_login,
    require_role,
    require_session_owner,
)
from app.config import get_settings
from app.db import get_db, get_session_factory
from scripts.init_db import create_tables

# 授業開始時刻の入力許容幅．現在時刻からこれ以上離れた scheduled_start_at は
# 誤入力とみなして拒否する（api-design.md「現在時刻の前後数時間以内くらい」）．
# 値の根拠が薄いのでいったんここに置くが，config.py の Settings に寄せて
# 運用しながら調整できるようにしてもよい（未決定事項として decisions.md に
# 記載する候補）．
SCHEDULED_START_TOLERANCE = timedelta(hours=3)

# --------------------------------------------------------- 起動時のテーブル作成
#
# 以前はここ（モジュールレベル）で `create_tables()` を直接呼んでいた．
# それだと `import app.main` した時点でDBファイルへの書き込みが走ってしまい，
# `pytest` を流しただけでもリポジトリ直下に `attendance.db` ができていた
# （`.gitignore` で除外されるので事故にはならないが，「アプリを読み込む＝
# ディスクに書き込む」状態になっていた）．本番でファイルシステムが読み取り
# 専用だと，import した時点で起動が落ちてしまう（次の編集内容 #2）．
#
# そこで FastAPI の lifespan に移し，アプリ起動時にだけ呼ぶようにする．
#
# テーブル作成のロジックは `scripts/init_db.py` の `create_tables()` に
# 一本化されている．`python -m scripts.init_db` で単体実行できるほか，
# アプリ起動のタイミングでもここから同じ関数を呼び，テーブルが無ければ作る
# （テーブルが無いまま `/auth/login` を叩くと500になるため，起動時の
# 呼び出しは残す）．
#
# `create_tables` の中身（`Base.metadata.create_all`）は既存テーブルには
# 触れない（checkfirst=Trueが既定）ので，二度目以降の起動やDBが既にある
# 場合に呼んでも安全．初期データ（教員・学生・授業）を入れるのは別の
# スクリプト（B-2）の役目とし，ここではスキーマの用意だけを行う．
#
# 副次効果として，`create_tables()` は内部で `get_engine()`→`get_settings()`
# を呼ぶため，`TOKEN_SECRET` や `CAMPUS_IP_RANGES` の設定不備もこの時点で
# 検出される（config.pyが本来意図している「起動時に検証する」動きに合わせ
# られる）．


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    yield


app = FastAPI(title="学内Wi-Fi連動 QR出席管理システム", lifespan=lifespan)

# 状態を変えるリクエストにCSRFトークンを要求する（decisions.md D-14）．
# エンドポイントごとに require_csrf 相当を付ける方式にしていないのは，
# 「1箇所の書き忘れがそのまま穴になる」ことを避けるため．新しいエンドポイントを
# 足しても自動的に守られる状態にしておく（security-interface.md 参照）．
app.add_middleware(CsrfMiddleware)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# 画面ルートでも使うので、依存関数をここで1つ作って共有する．
require_teacher = require_role("teacher")


@app.get("/health")
def health():
    return {"status": "ok"}


# ------------------------------------------------------------- 画面ルート
#
# ここから下は画面（HTML）を返すルート．担当Cがマージした `/teacher/courses`
# （このファイル末尾）と同じ書き方に揃える：認可は必ず `Depends` で宣言的に
# 付け，if では書かない（screen-design.md「画面の出し分けは認可ではない」．
# ボタンを隠しても直接URLを叩かれる前提で考える）．

@app.get("/login")
def login_page(request: Request):
    """ログイン画面．ログイン前の画面なので誰でも見られる．"""
    return templates.TemplateResponse(request=request, name="login.html", context={})


@app.get("/")
def index(request: Request, db: Session = Depends(get_db)):
    """ルート．ロールで教員／学生の入口へ振り分け，未ログインなら /login へ．

    `Depends(require_login)` を使わないのはここだけ意図的．require_login は
    未ログイン時に401（JSON）を返すが，ここはブラウザの画面遷移なので
    リダイレクトで応答したい．そのため `security.get_session_user` を直接呼ぶ．
    """
    user = security.get_session_user(db, request.cookies.get(SESSION_COOKIE))
    if user is None:
        return RedirectResponse(url="/login")
    if user.role == "teacher":
        return RedirectResponse(url="/teacher/courses")
    return RedirectResponse(url="/student")


@app.get("/student")
def student_home_view(
    request: Request,
    user: models.User = Depends(require_role("student")),
):
    """ログイン直後に学生が最初に見る画面."""
    return templates.TemplateResponse(
        request=request,
        name="home.html",
        context={"display_name": user.display_name},
    )


@app.get("/scan")
def scan_page(
    request: Request,
    db: Session = Depends(get_db),
):
    """QRから遷移してくる読み取り画面（カメラアプリからの直接着地も含む）.

    `index` と同じ理由で `Depends(require_role("student"))` を使わない．
    未ログイン時に日本語の案内画面（401）を返したいため，
    `security.get_session_user` を直接呼んで判定する．

    `require_login` が投げる401のJSON（`{"detail": "ログインが必要です"}`）を
    そのまま返すと，授業中に学生の画面へ生のJSONが出て何が起きたか伝わらない．
    `/login` へリダイレクトしないのは，QRの `s`/`t` がクエリ文字列にしか無く，
    リダイレクトすると失われて結局読み直しになるため．それなら最初から
    「もう一度読み取ってください」と伝える方が親切
    （screen-design.md の「授業開始前にログインしておいてください」と同じ考え方）．
    """
    user = security.get_session_user(db, request.cookies.get(SESSION_COOKIE))
    if user is None:
        return templates.TemplateResponse(
            request=request,
            name="scan_login_required.html",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    if user.role != "student":
        # 教員アカウント等でのアクセスは「未ログイン」とは別物の異常系なので，
        # 従来通りJSONの403のままにする（案内画面が要るのは未ログインの場合だけ）．
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="権限がありません")

    return templates.TemplateResponse(
        request=request,
        name="scan.html",
        context={"csrf_token": csrf_token_for_request(request)},
    )


@app.get("/history")
def history_page(
    request: Request,
    user: models.User = Depends(require_role("student")),
):
    """自分の出席履歴画面．表示データは GET /me/attendances から取得する."""
    return templates.TemplateResponse(request=request, name="history.html", context={})


# ---------------------------------------------------------------- スキーマ

class LoginRequest(BaseModel):
    login_id: str
    password: str


class MeResponse(BaseModel):
    login_id: str
    role: str
    display_name: str


class OpenSessionResponse(BaseModel):
    id: int
    status: str


class CourseResponse(BaseModel):
    id: int
    name: str
    open_session: OpenSessionResponse | None = None


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


class AttendanceSessionSummary(BaseModel):
    id: int
    course_name: str
    required_scan_count: int


class AttendanceRow(BaseModel):
    # 手動修正の宛先（PUT .../attendances/{user_id}）に使う．これが無いと
    # 画面の「修正」ボタンが宛先を持てず，手動修正API（B-7）を一度も呼べない．
    # この一覧は担当教員しか開けず，login_id（学籍番号）も既に返しているので，
    # 内部IDを足しても露出する情報は増えない．
    # 学生向けの /me/attendances には引き続きIDを一切載せない（D-13）．
    user_id: int
    login_id: str
    display_name: str
    # 未登録者は status / record_source が None になる（api-design.md の例の
    # S0004 に対応）．欠席者を「行が無い」のではなく「区分が空欄の行」として
    # 見せるため，履修者は必ず1行出す．
    status: str | None
    scan_count: int
    record_source: str | None
    alerts: list[str]


class AttendanceListResponse(BaseModel):
    session: AttendanceSessionSummary
    rows: list[AttendanceRow]


class ManualCorrectionRequest(BaseModel):
    status: str  # "present" | "late" | "absent"
    reason: str


class ManualCorrectionResponse(BaseModel):
    attendance_session_id: int
    user_id: int
    status: str
    record_source: str
    before_status: str | None
    corrected_at: str


# attendances.status の CHECK 制約と一致させる．ここで弾かずに models.py の
# CHECK 制約に頼ると IntegrityError（500 になりかねない）に流れてしまうため，
# アプリ側で先に検証する．
_VALID_ATTENDANCE_STATUSES = ("present", "late", "absent")


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

    # CSRFトークンをレスポンスボディで返す．
    # `auth.csrf_token_for_request` はテンプレート描画（TemplateResponse）を
    # 前提にした経路（担当C側）だが，このAPI自体はHTMLを描画しないJSON APIなので，
    # `security.csrf_token_for_session` を直接使い，ここで完結させる．
    # セキュリティ上の強さはHTML埋め込み方式と同等（同一オリジンのスクリプトしか
    # このレスポンスボディを読めないため）．JS側はこの値を保持し，以降の
    # 状態変更リクエストで `X-CSRF-Token` ヘッダに載せる．
    csrf_token = security.csrf_token_for_session(raw_session_id)

    return {"status": "ok", "csrf_token": csrf_token}


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
    "/courses/{course_id}/attendance-sessions",
    response_model=list[AttendanceSessionResponse],
)
def list_course_attendance_sessions(
    course: models.Course = Depends(require_course_owner),
    db: Session = Depends(get_db),
):
    """その授業の出席セッションを新しい順に返す（screen-design.md S5）．

    授業一覧の画面が「開催中の回があるか」を判断するために要る．
    開催中なら [QR表示] [状況] を，無ければ [開始] を出す．これが無いと
    どちらのボタンを出すべきか画面側で決められない．

    認可は `require_course_owner` のみに委ね，ここに if を書かない．
    他の教員の授業IDを指定された場合は依存関数が404を返す（403にすると
    「そのIDの授業は存在する」と分かってしまうため．api-design.md）．

    `token_salt` は返さない．レスポンスの形は `AttendanceSessionResponse` に
    固定されており，モデルに列を足しても勝手に露出しない．
    """
    sessions = (
        db.query(models.AttendanceSession)
        .filter(models.AttendanceSession.course_id == course.id)
        .order_by(
            # 開始予定時刻はミリ秒まで固定長のISO 8601で持っているので，
            # 文字列の降順がそのまま時刻の降順になる（decisions.md D-11）．
            models.AttendanceSession.scheduled_start_at.desc(),
            models.AttendanceSession.id.desc(),
        )
        .all()
    )
    return [_to_session_response(sess) for sess in sessions]


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


@app.get("/attendance-sessions/{attendance_session_id}/qr")
def teacher_qr_view(
    request: Request,
    sess: models.AttendanceSession = Depends(require_session_owner),
    db: Session = Depends(get_db),
):
    """教員のQR投影画面（プロジェクター表示用）.

    認可は `require_session_owner` のみに委ね，ここに追加の if は書かない
    （token取得APIと同じ方針．api-design.md「認可チェックの書き方」）．
    他の教員のセッションIDを指定された場合も `require_session_owner` が
    404を返す（403にすると「そのIDのセッションは存在する」と分かってしまう
    ため．api-design.mdのHTTPステータスの使い分け参照）．
    """
    course = db.get(models.Course, sess.course_id)
    return templates.TemplateResponse(
        request=request,
        name="teacher_qr.html",
        context={
            "session_id": sess.id,
            "csrf_token": csrf_token_for_request(request),
            "course_name": course.name if course is not None else None,
        },
    )


# --------------------------------------------------------- 出席状況一覧（B-6）
#
# api-design.md「GET /attendance-sessions/{id}/attendances」に対応する．
# 履修者全員を返し，出席登録が無い学生も「未登録」として含める
# （phase3-tasks.md B-6／screen-design.md S7．欠席者を見落とさないため）．
# 認可は require_session_owner のみに委ね，ここに course_id 等の if を書かない
# （token エンドポイントと同じ方針）．

@app.get(
    "/attendance-sessions/{attendance_session_id}/attendances",
    response_model=AttendanceListResponse,
)
def list_attendance_session_attendances(
    sess: models.AttendanceSession = Depends(require_session_owner),
    db: Session = Depends(get_db),
):
    course = db.get(models.Course, sess.course_id)

    # 履修者を login_id 順に取得する．Enrollment 単体には login_id が無いので
    # User と結合する．表示順を安定させるため login_id でソートしておく
    # （画面側でソートし直す前提を作らない）．
    enrolled_users = (
        db.query(models.User)
        .join(models.Enrollment, models.Enrollment.user_id == models.User.id)
        .filter(models.Enrollment.course_id == sess.course_id)
        .order_by(models.User.login_id)
        .all()
    )

    attendances_by_user = {
        a.user_id: a
        for a in db.query(models.Attendance)
        .filter(models.Attendance.attendance_session_id == sess.id)
        .all()
    }

    # scan_count は attendance_scans の件数．履修者の人数はこの規模のシステムでは
    # 高々数十人なので，SQLのGROUP BYを持ち込まずPython側で数える
    # （このファイルの他のクエリと同じ書き方に揃える）．
    scan_counts: dict[int, int] = {}
    for (user_id,) in (
        db.query(models.AttendanceScan.user_id)
        .filter(models.AttendanceScan.attendance_session_id == sess.id)
        .all()
    ):
        scan_counts[user_id] = scan_counts.get(user_id, 0) + 1

    rows: list[AttendanceRow] = []
    for user in enrolled_users:
        attendance = attendances_by_user.get(user.id)
        scan_count = scan_counts.get(user.id, 0)

        alerts: list[str] = []
        # 「1回目だけ読んで中抜けした」学生の警告（requirements.md「2回目以降の
        # QR再表示」／screen-design.md S7）．
        #
        # 注：文書に判定条件の厳密な定義が無いため，ここでの解釈を明記しておく．
        # 「再表示が行われている（required_scan_count > 1）のに，1回目のスキャン
        # から増えていない（scan_count == 1）」場合にのみ付ける．2回目までは
        # 来たが3回目以降を落とした（例：required=3, scan_count=2）ケースへの
        # warning文言は要件・画面設計のどちらにも定義が無いため，今回は対象外と
        # した．必要になったら security-interface.md 側の合意ではなく，この
        # ファイル内の解釈の話なのでB内で決めてよい．
        if sess.required_scan_count > 1 and scan_count == 1:
            alerts.append("1回目のみ")

        # 端末重複（device_conflict）やバースト検知のアラートはここに含めない．
        # あれは B-8（GET .../alerts）の責務で，audit_logs / device_bindings を
        # 見て初めて判定できる．画面側（担当C）で両エンドポイントの結果を
        # マージする前提（screen-design.md S7の「アラート」欄）．
        rows.append(
            AttendanceRow(
                user_id=user.id,
                login_id=user.login_id,
                display_name=user.display_name,
                status=attendance.status if attendance is not None else None,
                scan_count=scan_count,
                record_source=attendance.record_source if attendance is not None else None,
                alerts=alerts,
            )
        )

    return AttendanceListResponse(
        session=AttendanceSessionSummary(
            id=sess.id,
            course_name=course.name,
            required_scan_count=sess.required_scan_count,
        ),
        rows=rows,
    )


# ------------------------------------------------------------ アラート（B-8）
#
# 端末の重複とバーストを教員に見せる．出席状況一覧（上）とは別のエンドポイント
# にして，画面側で user_id をキーにマージする（screen-design.md S7 のアラート欄）．
# 分けている理由は，こちらが audit_logs / attendance_scans を横断して数える
# 重い処理で，一覧の表示を待たせたくないため．
#
# **検知するだけで，ブロックも自動欠席もしない（decisions.md D-11）．**
# device_id はCookieなので削除やシークレットモードで簡単に回避できる．
# 回避できる仕組みをブロックの根拠にすると，端末を買い替えた正当な利用者を
# 弾く一方で，本気の攻撃者は素通りする．判断は教員に委ねる．

ALERT_DEVICE_SHARED = "同じ端末で複数アカウント"
ALERT_DEVICE_BOUND_TO_OTHER = "別アカウントに紐付いた端末"
ALERT_BURST = "短時間に同じ端末から複数人"


class AlertRow(BaseModel):
    user_id: int
    login_id: str
    display_name: str
    alerts: list[str]


class AlertListResponse(BaseModel):
    rows: list[AlertRow]


def _device_label(index: int) -> str:
    """端末を画面上で見分けるためのラベル．

    **生の `device_id` は返さない．** 認証情報ではないが，HttpOnlyのCookieで
    配っている値をわざわざ画面に出す理由がない．教員に必要なのは「この2人が
    同じ端末だった」と分かることで，値そのものではない．このセッション内で
    通し番号を振れば足りる．
    """
    return f"端末{index}"


def _burst_device_ids(
    scans: list[models.AttendanceScan], threshold: int, window_seconds: int
) -> set[str]:
    """バーストが起きた端末を返す．

    数えるのは**登録件数ではなく人数**（重複しない `user_id`）．1人が1回目と
    2回目を読むのは正常なので，件数で数えると誤検知になる（security.py の
    detect_burst と同じ考え方）．

    detect_burst は登録の瞬間に「直近の窓」を見るが，こちらは授業が終わった
    後から見るので，窓を時間軸上で滑らせて一度でも閾値に達したかを調べる．
    """
    by_device: dict[str, list[tuple[datetime, int]]] = {}
    for scan in scans:
        if not scan.device_id:
            continue
        by_device.setdefault(scan.device_id, []).append(
            (security.from_iso(scan.scanned_at), scan.user_id)
        )

    burst: set[str] = set()
    for device_id, entries in by_device.items():
        entries.sort()
        left = 0
        for right in range(len(entries)):
            while (entries[right][0] - entries[left][0]).total_seconds() > window_seconds:
                left += 1
            if len({user_id for _, user_id in entries[left:right + 1]}) >= threshold:
                burst.add(device_id)
                break
    return burst


@app.get(
    "/attendance-sessions/{attendance_session_id}/alerts",
    response_model=AlertListResponse,
)
def list_attendance_session_alerts(
    sess: models.AttendanceSession = Depends(require_session_owner),
    db: Session = Depends(get_db),
):
    settings = get_settings()

    scans = (
        db.query(models.AttendanceScan)
        .filter(models.AttendanceScan.attendance_session_id == sess.id)
        .order_by(models.AttendanceScan.scanned_at, models.AttendanceScan.id)
        .all()
    )

    # 端末ごとに，その端末で登録した利用者を集める．登場順に通し番号を振るので，
    # 同じ一覧を二度開いてもラベルの並びが変わらない．
    users_by_device: dict[str, set[int]] = {}
    device_order: list[str] = []
    for scan in scans:
        if not scan.device_id:
            continue
        if scan.device_id not in users_by_device:
            users_by_device[scan.device_id] = set()
            device_order.append(scan.device_id)
        users_by_device[scan.device_id].add(scan.user_id)

    labels = {device_id: _device_label(i + 1) for i, device_id in enumerate(device_order)}
    burst_devices = _burst_device_ids(
        scans, settings.burst_threshold_count, settings.burst_window_seconds
    )

    alerts_by_user: dict[int, list[str]] = {}

    def _add(user_id: int, message: str) -> None:
        messages = alerts_by_user.setdefault(user_id, [])
        if message not in messages:
            messages.append(message)

    for device_id, user_ids in users_by_device.items():
        label = labels[device_id]
        if len(user_ids) > 1:
            for user_id in user_ids:
                _add(user_id, f"{ALERT_DEVICE_SHARED}（{label}）")
        if device_id in burst_devices:
            for user_id in user_ids:
                _add(user_id, f"{ALERT_BURST}（{label}）")

    # 登録時に検知した紐付けの衝突（A-9）．こちらは授業を跨いだ話なので，
    # このセッションの scans だけを見ても分からない．監査ログが唯一の記録．
    for row in (
        db.query(models.AuditLog)
        .filter(
            models.AuditLog.action == "device_conflict",
            models.AuditLog.target_type == "attendance_session",
            models.AuditLog.target_id == sess.id,
        )
        .all()
    ):
        if row.actor_user_id is not None:
            _add(row.actor_user_id, ALERT_DEVICE_BOUND_TO_OTHER)

    if not alerts_by_user:
        return AlertListResponse(rows=[])

    users = (
        db.query(models.User)
        .filter(models.User.id.in_(alerts_by_user.keys()))
        .order_by(models.User.login_id)
        .all()
    )
    return AlertListResponse(
        rows=[
            AlertRow(
                user_id=user.id,
                login_id=user.login_id,
                display_name=user.display_name,
                alerts=alerts_by_user[user.id],
            )
            for user in users
        ]
    )


@app.get("/attendance-sessions/{attendance_session_id}/attendances/view")
def attendance_list_view(
    request: Request,
    sess: models.AttendanceSession = Depends(require_session_owner),
    db: Session = Depends(get_db),
):
    """教員の出席状況一覧画面．表示データは GET .../attendances から取得する.

    QR画面（`teacher_qr_view`）と同じ理由で，認可は `require_session_owner`
    のみに委ねる．他の教員のセッションIDには404を返す．
    """
    course = db.get(models.Course, sess.course_id)
    return templates.TemplateResponse(
        request=request,
        name="attendance_list.html",
        context={
            "session_id": sess.id,
            "csrf_token": csrf_token_for_request(request),
            "course_name": course.name if course is not None else None,
        },
    )


# --------------------------------------------------------- 手動修正API（B-7）
#
# api-design.md「PUT /attendance-sessions/{attendance_session_id}/attendances/{user_id}」
# に対応する．decisions.md D-15の通り，記録があれば更新・無ければ作成を同じ
# 形で扱う（当初の PATCH /attendances/{id} 案は新規記録を作れず破綻していた）．
#
# パスに user_id を受け取るが，D-8（学生の記録を読むAPIにIDを受け取らせない）
# とは矛盾しない．D-8は学生が自分の記録を読む経路の話で，こちらは教員が対象を
# 指定する操作なのでIDの指定が機能そのものに必要．認可は require_session_owner
# （そのセッションの授業を担当しているか）で担保する．

@app.put(
    "/attendance-sessions/{attendance_session_id}/attendances/{user_id}",
    response_model=ManualCorrectionResponse,
)
def correct_attendance(
    user_id: int,
    payload: ManualCorrectionRequest,
    request: Request,
    sess: models.AttendanceSession = Depends(require_session_owner),
    db: Session = Depends(get_db),
):
    # reason は必須．空文字やスペースだけは400で拒否する（api-design.md）．
    # 手動修正は出席記録を書き換えられる特権操作なので，理由の入力自体を
    # 抑止として機能させる（requirements.md）．
    reason = payload.reason.strip()
    if not reason:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="理由を入力してください"
        )

    if payload.status not in _VALID_ATTENDANCE_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="status は present / late / absent のいずれかにしてください",
        )

    # 対象の学生がこの授業を履修しているか確認する（未履修なら400．api-design.md）．
    # Enrollment.user_id は users.id への外部キーなので，この行が取れれば
    # 対象ユーザーの実在も同時に保証される．
    enrolled = (
        db.query(models.Enrollment)
        .filter(
            models.Enrollment.course_id == sess.course_id,
            models.Enrollment.user_id == user_id,
        )
        .one_or_none()
    )
    if enrolled is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="この授業の履修者ではありません",
        )

    client_ip = security.get_client_ip(request)
    now = datetime.now(timezone.utc)

    existing = (
        db.query(models.Attendance)
        .filter(
            models.Attendance.attendance_session_id == sess.id,
            models.Attendance.user_id == user_id,
        )
        .one_or_none()
    )
    # before_status は，記録が無かった場合はNULL（api-design.md）．
    before_status = existing.status if existing is not None else None

    if existing is not None:
        existing.status = payload.status
        existing.record_source = "manual"
    else:
        # 新規追加のパス．一意制約 (attendance_session_id, user_id) は
        # 上のクエリで既存行が無いことを確認済みなので通常は衝突しないが，
        # 同時に2つの修正リクエストが来た場合の競合はここでは扱っていない
        # （単一の教員が操作する運用を前提にした割り切り．正直に限界として
        # 書いておく）．
        existing = models.Attendance(
            attendance_session_id=sess.id,
            user_id=user_id,
            status=payload.status,
            record_source="manual",
            first_recorded_at=security.to_iso(now),
        )
        db.add(existing)

    corrected_at = security.to_iso(now)

    # manual_corrections への記録と attendances の更新を同一トランザクションに
    # する（phase3-tasks.md B-7）．sess.created_by をteacher_idに使うのは
    # 他の教員向けエンドポイント（rescan等）と同じ考え方：require_session_owner
    # を通った時点でログイン中の教員がそのセッションの担当（＝作成者）だと
    # 確認済みなので，別途 Depends(require_login) で取り直す必要が無い．
    db.add(
        models.ManualCorrection(
            attendance_session_id=sess.id,
            target_user_id=user_id,
            teacher_id=sess.created_by,
            before_status=before_status,
            after_status=payload.status,
            reason=reason,
            client_ip=client_ip,
            corrected_at=corrected_at,
        )
    )

    # audit_logs にも action="manual_correction" として残す（db-design.md の
    # action一覧に明記されている）．manual_corrections が変更前後の値を持つ
    # 一次記録で，こちらは他のセキュリティイベントと横断的に検索するための
    # 二次記録という位置づけ．同じ db（トランザクション）に書くことで，
    # 書き込みが失敗したら修正自体がロールバックされる
    # （security-interface.md「呼び出す側の責任」）．
    security.write_audit_log(
        db,
        action="manual_correction",
        result="success",
        actor_user_id=sess.created_by,
        client_ip=client_ip,
        target_type="attendance_session",
        target_id=sess.id,
        detail=f"target_user_id={user_id} before={before_status} after={payload.status}",
    )

    return ManualCorrectionResponse(
        attendance_session_id=sess.id,
        user_id=user_id,
        status=payload.status,
        record_source="manual",
        before_status=before_status,
        corrected_at=corrected_at,
    )


# ------------------------------------------------------- 出席登録（B-5・核心）
#
# api-design.md「POST /attendances（出席登録）」の検証順序をそのままの順で
# 実装する．IP検証をトークン検証より前に置くのは意図的（D-5：学外からの
# 試行にトークンの有効性を漏らさないため）．
#
# 実装済み・解消済み：
#   #3  CSRF検証 … CsrfMiddleware を app に登録し，POST /attendances を含む
#       状態変更系リクエスト全体に適用済み（このファイル冒頭の
#       app.add_middleware(CsrfMiddleware) 参照）．エンドポイント個別の
#       チェックは書かない方針のまま
#   #7  「期限切れ」と「不正」の区別 … security.classify_token が
#       TokenCheck（VALID/EXPIRED/INVALID）を返すようになったため，
#       監査ログのdetailはこの2つを区別して記録している．
#       **ただし学生に見せるメッセージは区別しない**（decisions.md D-16／
#       TokenCheckのdocstring）．区別して見せると，偽造したトークンが
#       形式として正しかったかを攻撃者が探る手がかり（オラクル）になる
#       ため．どちらも「無効なQRです」のまま統一している
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
    # CSRF検証はミドルウェア（CsrfMiddleware）が担当し，ここには書かない．
    # このエンドポイントに個別のチェックを足すと，将来別のPOSTエンドポイントで
    # 付け忘れる余地を残すことになる．

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
    result = security.classify_token(sess.id, sess.token_salt, payload.token)
    if result is not security.TokenCheck.VALID:
        raise _reject_now(
            status.HTTP_403_FORBIDDEN,
            "QRを読み取れませんでした。もう一度読み取ってください",
            result.value,
            target_type="attendance_session",
            target_id=sess.id
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
                status.HTTP_403_FORBIDDEN, "受付時間外です", "outside_window",
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


# --------------------------------------------------------- 学生の出席履歴（D-8）
#
# api-design.md「学生の記録を読むAPIにIDを受け取らせない」（D-8）に対応する．
# パス・クエリ・ボディのどこにも学生IDを持たせず，対象はログインセッションから
# 決まる本人だけにする．`/students/{student_id}/attendances` のような形を
# 作らなければ，他人の記録を覗く攻撃はそもそも成立しない．
#
# api-design.mdの認可欄は「要ログイン」であって「student」限定ではないため，
# ここでは `require_role("student")` ではなく `require_login` を使う．

class MyAttendanceRow(BaseModel):
    course_name: str
    scheduled_start_at: str
    # 記録が無いセッション（未登録／欠席）は status / record_source が None
    # になる．list_attendance_session_attendances の AttendanceRow と同じ考え方．
    status: str | None
    scan_count: int
    record_source: str | None


@app.get("/me/attendances", response_model=list[MyAttendanceRow])
def list_my_attendances(
    user: models.User = Depends(require_login),
    db: Session = Depends(get_db),
):
    # 履修している授業の出席セッションだけを対象にする．
    enrolled_course_ids = [
        row[0]
        for row in db.query(models.Enrollment.course_id)
        .filter(models.Enrollment.user_id == user.id)
        .all()
    ]

    # 記録が無いセッション（欠席／未登録）も「記録なし」の行として出す
    # （screen-design.md S4の「第7回 記録なし」．欠席を「行が無いこと」で
    # 表す設計と同じで，履修者名簿ではなくセッション側を起点に取得する）．
    sessions = (
        db.query(models.AttendanceSession, models.Course)
        .join(models.Course, models.Course.id == models.AttendanceSession.course_id)
        .filter(models.AttendanceSession.course_id.in_(enrolled_course_ids))
        .order_by(models.AttendanceSession.scheduled_start_at.desc())
        .all()
    )

    attendances_by_session = {
        a.attendance_session_id: a
        for a in db.query(models.Attendance)
        .filter(models.Attendance.user_id == user.id)
        .all()
    }

    scan_counts: dict[int, int] = {}
    for (session_id,) in (
        db.query(models.AttendanceScan.attendance_session_id)
        .filter(models.AttendanceScan.user_id == user.id)
        .all()
    ):
        scan_counts[session_id] = scan_counts.get(session_id, 0) + 1

    rows: list[MyAttendanceRow] = []
    for sess, course in sessions:
        attendance = attendances_by_session.get(sess.id)
        rows.append(
            MyAttendanceRow(
                course_name=course.name,
                scheduled_start_at=sess.scheduled_start_at,
                status=attendance.status if attendance is not None else None,
                scan_count=scan_counts.get(sess.id, 0),
                record_source=attendance.record_source if attendance is not None else None,
            )
        )

    return rows


# ------------------------------------------------------------ 教員の授業一覧
#
# 一覧は「ログイン中の教員が担当する授業」だけを返す．授業IDを受け取って
# 絞り込む形にすると，他人のIDを入れられたときの防御が呼び出し側頼みになる．

@app.get(
    "/courses",
    response_model=list[CourseResponse],
    response_model_exclude_none=True,
)
def list_courses(
    user: models.User = Depends(require_teacher),
    db: Session = Depends(get_db),
):
    courses = (
        db.query(models.Course)
        .filter(models.Course.teacher_id == user.id)
        .order_by(models.Course.name, models.Course.id)
        .all()
    )
    if not courses:
        return []

    # 担当授業の開催中セッションを一括取得し，画面から授業ごとにHTTP
    # リクエストを送らなくて済むようにする．
    open_sessions = (
        db.query(models.AttendanceSession)
        .filter(
            models.AttendanceSession.course_id.in_([course.id for course in courses]),
            models.AttendanceSession.status == "open",
        )
        .order_by(models.AttendanceSession.id.desc())
        .all()
    )
    # 開始APIが二重作成を409で拒否するため通常は1授業1件．既存データに
    # 複数件あっても最新の1件だけを採用し，授業カードを重複させない．
    open_session_by_course = {}
    for session_row in open_sessions:
        open_session_by_course.setdefault(session_row.course_id, session_row)

    return [
        {
            "id": course.id,
            "name": course.name,
            "open_session": open_session_by_course.get(course.id),
        }
        for course in courses
    ]


@app.get("/teacher/courses")
def teacher_courses_view(
    request: Request,
    user: models.User = Depends(require_teacher),
):
    """ログイン直後に教員が最初に見る画面.

    受付時間帯の分数をテンプレートに渡している．セッション開始ダイアログで
    「出席：09:55〜10:05／遅刻：10:05〜10:20」と表示し，入力した授業開始時刻が
    正しいかを教員自身に確認させるため（screen-design.md S5）．

    **JS側に数字を直書きさせないためにサーバーから渡す．** 直書きすると
    `.env` で値を変えたときに画面の表示だけが古いまま残り，教員が見ている
    受付時間帯と実際の判定がずれる．誤入力を防ぐための表示が逆に誤解を生む．
    """
    settings = get_settings()
    return templates.TemplateResponse(
        request=request,
        name="teacher_courses.html",
        context={
            "display_name": user.display_name,
            "csrf_token": csrf_token_for_request(request),
            "present_before_minutes": settings.present_before_minutes,
            "present_after_minutes": settings.present_after_minutes,
            "late_until_minutes": settings.late_until_minutes,
        },
    )
