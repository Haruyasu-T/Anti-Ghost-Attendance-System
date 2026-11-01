# security.py のインターフェース

`app/security.py`（担当A）が公開する関数と，`app/main.py`（担当B）からどう呼ぶかの取り決め．

担当Aが中身を書いている間も担当Bが「この関数を呼ぶ」前提でAPIを書けるように，先に形だけ決めておく．3人でいちばんコンフリクトしそうな境界なので，実装前に合意しておきたい．

## 設定値

セキュリティに関わる値はコードに直接書かない．

| 名前 | 既定値 | 意味 |
|---|---|---|
| `TOKEN_SECRET` | なし（必須） | トークン生成用の秘密鍵 |
| `QR_ROTATE_SECONDS` | 5 | QRとトークンの更新間隔（秒） |
| `TOKEN_ACCEPT_PREVIOUS_WINDOWS` | 1 | 何世代前まで受け付けるか |
| `PRESENT_BEFORE_MINUTES` | 5 | 開始何分前から出席として受け付けるか |
| `PRESENT_AFTER_MINUTES` | 5 | 開始何分後まで出席とするか |
| `LATE_UNTIL_MINUTES` | 20 | 開始何分後まで遅刻として受け付けるか |
| `CAMPUS_IP_RANGES` | なし（必須） | 学内とみなすIPレンジ（CIDR） |
| `LOGIN_MAX_FAILURES` | 5 | レート制限の閾値（失敗回数） |
| `LOGIN_WINDOW_MINUTES` | 10 | 失敗回数を数える期間 |
| `LOGIN_LOCKOUT_MINUTES` | 15 | 制限がかかる時間 |
| `BURST_THRESHOLD_COUNT` | 3 | バースト検知の閾値 |
| `BURST_WINDOW_SECONDS` | 60 | バースト検知の集計期間 |
| `TRUSTED_PROXY_COUNT` | 0 | 前段にいる信頼できるプロキシの数（後述） |

読み込みは `app/config.py` にまとめ，`get_settings()` で取る．`security.py` や `main.py` から `os.getenv` を直接呼ばない（検証を通らない値が紛れ込むので）．

値の検証（必須項目の有無・CIDRの妥当性・整数変換）は読み込み時にまとめてやり，不正なら使う瞬間ではなく起動時に落とす．

### TOKEN_SECRET の扱い

`.env` で管理して `.gitignore` に入れる．リポジトリには絶対にコミットしない．`.env.example` にはキー名だけ書いて値は空にしておく．

起動時に未設定ならエラーで停止させる．開発用の既定値をコードに埋めてはいけない．埋めると本番でそのまま動いてしまい，しかも誰も気付けない．

### CAMPUS_IP_RANGES の扱い

実際の学内IPレンジも `.env` 側で管理し，リポジトリにはコミットしない．秘密鍵ほどの機密性はないが，公開したときに学内ネットワークの構成を晒すことになる．隠せるものは隠しておく．

文書やコードの例には `192.168.0.0/16` のようなプライベートアドレスの汎用例だけを使う．

### リポジトリに書いていいもの・いけないもの

| 種類 | 扱い | 理由 |
|---|---|---|
| トークンの生成方式・長さ・更新間隔 | 書いていい | 安全性は鍵の秘密性だけに依存すべきで，方式を隠すことに依存する設計は誤り |
| トークンの例（架空の値） | 書いていい | HMACの出力から鍵は逆算できず，数秒で失効する |
| `TOKEN_SECRET` の値 | 禁止 | 漏れると有効なトークンを作れる |
| 実際の学内IPレンジ | 禁止 | 学内ネットワーク構成の露出 |
| 実在の学籍番号・氏名・メールアドレス | 禁止 | 個人情報．例には `S0001` のような架空の値を使う |
| 本物のパスワード（テスト用も含む） | 禁止 | テストコードへの直書きもだめ |

## 公開する関数

### パスワード

```python
def hash_password(plain: str) -> str: ...
def verify_password(plain: str, password_hash: str | None) -> bool: ...
```

`bcrypt` ライブラリを直接使う．自前でハッシュ処理を書かない．

最初は `passlib` を使うつもりだったが，`passlib` 1.7.4（2020年で更新停止）が新しい `bcrypt` と非互換で動かなかったので，`bcrypt` を直接使う形に変えた．層が1つ減り，メンテナンスされていない依存も外せる．

**bcryptに渡す前にSHA-256で畳む**．bcryptは72バイトを超える入力を切り捨てるので，そのまま渡すと「先頭72バイトが同じ別のパスワード」でも認証が通ってしまう．先にSHA-256（32バイト）→base64（44文字）にすれば，長さに関係なく全体が反映される．

`verify_password` は，ユーザーが存在しない（`password_hash` が `None`）場合でもダミーのハッシュに対して照合を実行する．早期リターンすると応答時間の差からアカウントの存在が分かってしまうため．

### ログインセッション

サーバー側で保持する（`login_sessions` テーブル）．理由は[DB設計](db-design.md)の設計メモを参照．

```python
def create_login_session(db, user_id: int,
                         client_ip: str | None = None,
                         user_agent: str | None = None) -> str: ...
def get_session_user(db, session_id: str | None) -> User | None: ...
def revoke_login_session(db, session_id: str | None) -> None: ...
def revoke_all_sessions_for_user(db, user_id: int) -> int: ...
```

DBセッションは第1引数で受け取る．`security.py` の中でセッションを作らないことで，テスト時に使い捨てのDBを渡せる状態を保つ（当初の案では引数に無かったが，実装時に変更した）．

守ること：

- セッションIDは `secrets.token_urlsafe(32)` などの暗号論的乱数で作る．連番・UUIDv1・時刻由来の値は使わない（推測されると乗っ取られる）
- DBに保存するのはSHA-256ハッシュだけ．`create_login_session` は生の値を返し（Cookieに入れる），DBには `id_hash` を書く．`get_session_user` は受け取った値をハッシュ化して照合する．これでDBが漏れてもセッションを乗っ取れない
- Cookieに入れるのはセッションIDだけ．ユーザーIDやロールは入れない
- `get_session_user` は `revoked_at` と `expires_at` を必ず見る．どちらかに該当したら `None`
- ログイン成功時にセッションIDを再発行する（セッション固定攻撃の対策）

### 動的トークン

```python
def new_token_salt() -> str: ...
def generate_token(session_id: int, token_salt: str,
                   at: datetime | None = None) -> str: ...

class TokenCheck(str, Enum):
    VALID   = "valid"      # 受け付ける
    EXPIRED = "expired"    # 少し前の世代．読み取りが遅れた
    INVALID = "invalid"    # どの世代とも一致しない．偽造・改ざん・別セッション

def classify_token(session_id: int, token_salt: str, token: str,
                   at: datetime | None = None) -> TokenCheck: ...
def verify_token(session_id: int, token_salt: str, token: str,
                 at: datetime | None = None) -> bool: ...   # classify_token の薄い包み
```

**`EXPIRED` と `INVALID` を学生に見せ分けないこと（D-16）。** この区別は監査ログ用．応答を変えると，攻撃者は偽造したトークンが「形式として正しかったか」を試せてしまう．学生の取るべき行動はどちらも「もう一度読む」で同じなので，見分けさせる価値もない．

B-5 での使い方：

```python
result = security.classify_token(sess.id, sess.token_salt, req.token)
if result is not security.TokenCheck.VALID:
    security.write_audit_log_now(
        get_session_factory(), action="attendance_register", result="failure",
        actor_user_id=user.id, client_ip=client_ip,
        detail=result.value,          # ← ここは区別する（expired_token / invalid_token）
    )
    raise HTTPException(403, "QRを読み取れませんでした。もう一度読み取ってください")
```

方式：

```
window = floor(unix_time / QR_ROTATE_SECONDS)
token  = HMAC-SHA256(TOKEN_SECRET, f"{session_id}:{token_salt}:{window}") の先頭16文字
```

検証は `window` と `window - 1`（`TOKEN_ACCEPT_PREVIOUS_WINDOWS` の数だけ遡る）を再計算して照合する．

守ること：

- 比較は `hmac.compare_digest` を使う．`==` は文字列の一致位置によって処理時間が変わるので，1文字ずつ推測される余地がある
- 一致しても途中でループを抜けない．抜けると何世代前で一致したかが処理時間に出る
- `session_id` を入力に含める．同時刻に2つの授業が開講されていても互いのQRを流用できない
- `token_salt` を混ぜる．`TOKEN_SECRET` の漏洩だけではトークンを作れなくなる
- `token_salt` は引数で受け取る．`security.py` からDBを引かない（純粋関数のままにしてテストしやすさを保つ）
- `new_token_salt` は `secrets.token_urlsafe(16)` などの暗号論的乱数
- `at` はテスト専用．本番の呼び出しでは省略してサーバー時刻を使う

QRが撮影されて出回ったと教員が気付いたら，`token_salt` を作り直すと出回っている全QRが即座に無効になる．秘密鍵だけから導出する方式にはできなかった操作．

限界は2つ．ワンタイム化はしない（同じ世代内なら複数人に通る．QRを多数の学生が同時に読む以上これは必須の性質で，二重登録は一意制約と `scan_seq` で防ぐ）．それと `TOKEN_SECRET` と `token_salt` の両方が漏れると，そのセッションのトークンは任意に作れる．

### アクセス元IP

```python
def is_campus_ip(client_ip: str) -> bool: ...
def get_client_ip(request) -> str: ...
```

`ipaddress` モジュールで `CAMPUS_IP_RANGES` と照合する．解析できない値は `False`（判定できないなら拒否する）．

**IPの取り方がいちばん間違えやすい**．ここを誤ると「クライアントが自己申告したIPで学内判定する」ことになり，対策が完全に無効化される．`main.py` 側でヘッダを直接読まず，必ず `get_client_ip` を通すこと．

#### X-Forwarded-For の扱い

`X-Forwarded-For` はクライアントが自由に送れるヘッダ．素直に先頭の値を使うと，学外の攻撃者が `X-Forwarded-For: <学内IP>` を付けるだけでIP検証を突破できる．

一方で外部にデプロイするとロードバランサの背後に入るので，`request.client.host` はプロキシのアドレスになり，そのままでは学生のIPが分からない．

そこで前段にいる信頼できるプロキシの数を設定として持つ．

| 設定値 | 動作 | 使う場面 |
|---|---|---|
| `0` | ヘッダを一切見ず，TCP接続元のアドレスだけを使う | ローカル開発 |
| `N` | `X-Forwarded-For` の右からN番目を使う | プロキシN台の背後にデプロイした場合 |

右から数えるのは，各プロキシが「自分が見た接続元」を末尾に追記していくため．攻撃者が偽の値を送っても，それはリストの左側に押しやられる．末尾側のN個は信頼できるプロキシが書いた値なので，そこだけを信じる．

想定より短い経路だったら空文字を返して呼び出し側で拒否させる．推測で通さない．

### 受付時間帯

```python
class AttendanceStatus(str, Enum):
    PRESENT = "present"
    LATE    = "late"

def classify_attendance(scheduled_start_at: datetime,
                        now: datetime) -> AttendanceStatus | None: ...
```

`scheduled_start_at` からの経過時間を `t`（分）とする．境界値はすべて学生に有利な側に含める．

| 条件 | 戻り値 |
|---|---|
| `t < -5` | `None`（早すぎる） |
| `-5 <= t <= +5` | `PRESENT` |
| `+5 < t <= +20` | `LATE` |
| `t > +20` | `None`（受付終了） |

つまり `t = -5` ちょうどは受け付ける，`t = +5` ちょうどは遅刻にしない，`t = +20` ちょうどは受付終了にしない．

有利な側に倒すのは，1秒の差で不利益が出ると異議申し立てが増え，教員の手動修正への依存が高まるから．手動修正はそれ自体が攻撃面なので，運用の摩擦を減らすことがセキュリティ上も望ましい．

`now` には必ずサーバー時刻を渡す．クライアントから受け取った時刻を渡してはいけない．

「早すぎる」場合（開始5分前より前）も `None` にする．授業前に前もって読み取っておく行為を防ぐため．

タイムゾーンなしの `datetime` を渡したら `ValueError` で落とす．naiveとawareを混ぜると判定がずれるので，曖昧なまま進むより落とした方がいい．

### 端末の紐付け

```python
def issue_device_id() -> str: ...

class DeviceCheckResult(str, Enum):
    OK       = "ok"        # 未登録，または同一ユーザー
    CONFLICT = "conflict"  # 別のユーザーに紐付いている

def check_device_binding(db, device_id: str | None,
                         user_id: int) -> DeviceCheckResult: ...
```

`CONFLICT` でも登録をブロックしない．`audit_logs` に `device_conflict` として記録し，教員のアラート画面に出す．

`device_id` はHttpOnlyのCookieで配る．JavaScriptから読めない形にして，ページ側で書き換えられないようにする．

衝突を見つけても**紐付けを書き換えない**．書き換えを許すと，あとから来たアカウントが端末を「奪える」ことになり，記録として意味をなさなくなる．

限界として，Cookieを削除すれば新しい端末として扱われるし，シークレットモードでも回避できる．だからブロックの根拠にはしない．

### レート制限

```python
def is_login_rate_limited(db, login_id: str | None,
                          client_ip: str | None) -> bool: ...
```

`audit_logs` の `action='login'` かつ `result='failure'` を，`login_id` 別と `client_ip` 別の両方で数える．

両方見るのは，`login_id` だけだと1つのIPから多数のIDを総当たりされ，`client_ip` だけだと分散したIPから1つのIDを狙われるため．

判定のしかた：直近の失敗を `LOGIN_WINDOW_MINUTES` 分の幅で数え，`LOGIN_MAX_FAILURES` 件以上あれば，**最後の失敗から `LOGIN_LOCKOUT_MINUTES` の間**は拒否する．失敗するたびにロックが延びるので，総当たりを続けている限り解除されない．

### 異常検知

```python
def detect_burst(db, attendance_session_id: int,
                 device_id: str | None = None,
                 client_ip: str | None = None) -> bool: ...
```

短時間に同じ端末（またはIP）から複数人の登録があったかを判定する．

数えるのは**登録件数ではなく，登録した人数（重複しない `user_id`）**．1人が1回目と2回目を読むのは正常なので，件数で数えると誤検知になる．

`device_id` での判定が主で，`client_ip` は補助．**外部にデプロイすると学内Wi-Fiの学生は全員が大学のNATの出口IPで届くため，IPでの判定はほぼ機能しない**（全員が同じIPになる）．学内が複数の出口に分かれている場合や，ローカルでの検証時に意味を持つ程度と考えておく．

### 監査ログ

```python
def write_audit_log(
    db,
    action: str,
    result: str,                      # "success" | "failure"
    actor_user_id: int | None = None,
    attempted_login_id: str | None = None,
    target_type: str | None = None,
    target_id: int | None = None,
    client_ip: str | None = None,
    device_id: str | None = None,
    detail: str | None = None,
) -> None: ...

def write_audit_log_now(session_factory, **kwargs) -> None: ...
```

**2つある理由**（実装時に気付いた点）．

`write_audit_log` は呼び出し側のトランザクションに書く．手動修正のように「記録と本体の変更が必ずセットで残る／両方消える」必要がある場面はこちら．

ところが，このあと例外を投げてロールバックする経路（ログイン失敗，出席登録の拒否など）で使うと，**ログごと消えてしまう**．拒否された試行こそ後から追いたい情報なので，そこを取りこぼさないよう `write_audit_log_now` を用意した．こちらは独立したトランザクションで書いて即コミットするので，呼び出し側がロールバックしても残る．

### ⚠️ 呼ぶ前にロールバックすること（`database is locked`）

`write_audit_log_now` は**別のコネクション**を使う．SQLiteは**ファイル単位で
書き手が1本だけ**なので，呼び出し側の `db` が未コミットの書き込みを抱えていると，
こちらは永久に書けない．

`require_login` が `login_sessions.last_used_at` を更新しており，その直後の
`db.get()` がautoflushを起こすので，**エンドポイント本体に入る前からロックは
握られている**．つまり本体で1回もクエリしていなくても発生する．

```python
db.rollback()                                      # ← 必ず先に
security.write_audit_log_now(get_session_factory(), ...)
raise HTTPException(...)
```

これを忘れると、同時アクセスがゼロでも**毎回**止まる（1リクエストの中で
自分自身と衝突するため）．実際に2026-08-29に2回踏んでいる．詳細は decisions.md の **D-21**．

`register_attendance` では `_reject_now` の中に閉じ込めてある．
**`_reject_now` を通さずに `write_audit_log_now` を直接呼ぶ実装は，レビューで止める．**

呼び出す側の責任：

- 出席登録は成功も失敗も記録する．失敗理由を `detail` に入れる
- **失敗して例外を投げる経路では `write_audit_log_now` を使う**
- **その際，呼ぶ前に `db.rollback()` する**（上記）
- 手動修正は `manual_corrections` への記録と同じトランザクションで行い，ログの書き込みが失敗したら修正をロールバックする
- `detail` にパスワードとトークンを入れない．秘密鍵の混入は実装側でも弾いているが，約束事として守ること

## app/auth.py — 認可の依存関数

`security.py` をHTTPから切り離しておきたいので，FastAPIの `Request` や `HTTPException` を扱う部分は `app/auth.py` に分けている．

```python
from app.auth import require_login, require_role, require_course_owner, require_session_owner

require_login          # ログイン必須．未ログインなら401
require_role(*roles)   # ロール確認．require_role("teacher") のように呼んで使う
require_course_owner   # パスの course_id が自分の担当授業か確認
require_session_owner  # パスの attendance_session_id が自分の担当授業か確認
```

`require_role` だけが「依存関数を作る関数」なので括弧付きで呼ぶ．残りはそのまま `Depends(...)` に渡す．`get_current_user` は `require_login` の別名（FastAPIでよく使われる名前なので用意してあるだけで，実体は同じ）．

他の教員のリソースを指定された場合は403ではなく**404**を返す．403だと「そのIDは存在する」と分かってしまうため．

## app/db.py — DBセッション

```python
from app.db import get_db          # FastAPIの依存関数．1リクエスト1トランザクション
from app.db import get_session_factory   # 独立したトランザクションが要るとき
```

`get_db` は正常終了でコミット，例外でロールバックする．

**失敗を記録してから例外を投げる経路では，このセッションに監査ログを書かないこと．** ロールバックで一緒に消える．`write_audit_log_now(get_session_factory(), ...)` を使う．

## B-3（認証API）での呼び出し例

自前でセッションを作らず，以下を呼ぶこと．ハッシュ化・有効期限・失効の扱いはすべて `security.py` 側に入っている．

```python
from app import security
from app.auth import SESSION_COOKIE, require_login
from app.db import get_db, get_session_factory

@app.post("/auth/login")
def login(payload: LoginRequest, request: Request, response: Response,
          db: Session = Depends(get_db)):
    client_ip = security.get_client_ip(request)   # request.client.host を直接使わない

    if security.is_login_rate_limited(db, payload.login_id, client_ip):
        raise HTTPException(429, "しばらく待ってから再度お試しください")

    user = db.query(models.User).filter_by(login_id=payload.login_id).one_or_none()
    if not security.verify_password(payload.password,
                                    user.password_hash if user else None):
        # 例外でロールバックするので _now の方を使う
        security.write_audit_log_now(
            get_session_factory(), action="login", result="failure",
            attempted_login_id=payload.login_id, client_ip=client_ip,
        )
        raise HTTPException(401, "IDまたはパスワードが違います")

    raw_session_id = security.create_login_session(
        db, user.id, client_ip=client_ip,
        user_agent=request.headers.get("user-agent"),
    )
    security.write_audit_log(db, action="login", result="success",
                             actor_user_id=user.id, client_ip=client_ip)

    response.set_cookie(SESSION_COOKIE, raw_session_id,
                        httponly=True, secure=True, samesite="lax")
    return {"status": "ok"}


@app.post("/auth/logout")
def logout(request: Request, response: Response,
           user = Depends(require_login), db: Session = Depends(get_db)):
    security.revoke_login_session(db, request.cookies.get(SESSION_COOKIE))
    security.write_audit_log(db, action="logout", result="success",
                             actor_user_id=user.id,
                             client_ip=security.get_client_ip(request))
    response.delete_cookie(SESSION_COOKIE)
    return {"status": "ok"}


@app.get("/auth/me")
def me(user = Depends(require_login)):
    return {"login_id": user.login_id, "role": user.role,
            "display_name": user.display_name}
```

## CSRF対策

```python
security.csrf_token_for_session(raw_session_id) -> str
security.verify_csrf_token(raw_session_id, provided) -> bool
auth.csrf_token_for_request(request) -> str        # 画面描画時に使う
auth.CsrfMiddleware                                # main.py に add_middleware する
```

**方式：ログインセッションからHMACで導出する（サーバー側に保存しない）．**

```
csrf_token = HMAC-SHA256(TOKEN_SECRET, "csrf:" + セッションIDのハッシュ)
```

セッションごとに違う値になり，秘密鍵が無ければ計算できない．DBにカラムを足す必要がなく，毎リクエストで再計算して照合できる．トークンの導出に既に使っている考え方と同じ．

**なぜこれで防げるか．** 攻撃者が用意したページからは，

- 同一生成元ポリシーにより，こちらのHTMLに埋め込まれたトークンを読めない
- セッションCookieはHttpOnlyなのでJavaScriptから読めない
- 仮に読めたとしても `TOKEN_SECRET` が無いのでトークンを計算できない

したがって正しい `X-CSRF-Token` を付けたリクエストを作れない．

**ミドルウェアで強制する．** エンドポイントごとに付ける方式にしていない．このプロジェクトで繰り返し問題になっているのは「1箇所の書き忘れがそのまま穴になる」ことなので，付け忘れが起こりえない形にした．新しいエンドポイントを足しても自動的に守られる．

```python
# main.py
from app.auth import CsrfMiddleware
app.add_middleware(CsrfMiddleware)
```

対象外にしているもの：

| 対象外 | 理由 |
|---|---|
| GET / HEAD / OPTIONS / TRACE | 状態を変えないため |
| `POST /auth/login` | まだセッションが無く検証できない．守るべき状態も無い |
| 未ログインのリクエスト | セッションが無いのでCSRFで守る対象が無い．認可側の401に任せる |

ログインCSRF（被害者を攻撃者のアカウントでログインさせる）は理論上あるが，`SameSite=Lax` である程度防げるため今回は許容する．

**画面側の使い方.** テンプレートに `csrf_token` を渡し，JavaScriptがヘッダに載せる．

```python
return templates.TemplateResponse(
    request=request, name="scan.html",
    context={"csrf_token": auth.csrf_token_for_request(request)},
)
```

```html
<section data-csrf-token="{{ csrf_token }}">
```

```javascript
fetch("/attendances", { method: "POST", credentials: "same-origin",
  headers: { "X-CSRF-Token": shell.dataset.csrfToken } })
```

### 時刻の変換

```python
def to_iso(dt: datetime) -> str: ...      # DBに入れる形式に変換
def from_iso(value: str) -> datetime: ... # DBから読んだ値をdatetimeに戻す
```

`main.py` 側でも時刻の変換が必要になるので公開している．自前で `strftime` を書かず，必ずこれを通すこと（書式が揃わないと範囲検索が壊れる．後述）．

**`from_iso` はDBから読んだ値の変換に使う関数であって，クライアント入力の検証には使わない．** タイムゾーンが無ければ黙ってUTCとみなすので，フロントがJST→UTCの変換を忘れて送ってきた場合に気付けない．クライアント入力はタイムゾーンの有無まで呼び出し側で明示的に弾くこと（④クライアントを信用しない）．

## 時刻の書式

DBに入れる時刻は **"YYYY-MM-DDTHH:MM:SS.mmmZ"（ミリ秒3桁・24文字固定）** に統一する．

範囲検索を文字列の大小比較で行っているため，**桁数が揺れると比較が壊れる**．同じ瞬間を `…:00Z` と `…:00.000Z` で表すと，`.`(0x2E) は `Z`(0x5A) より小さいので後者が常に「古い」と判定される．レート制限が失敗を数え落とし，総当たりがすり抜ける．

- Python側：`security._to_iso(dt)` を使う．自分で `strftime` しない
- DB側：`server_default` は `strftime('%Y-%m-%dT%H:%M:%fZ','now')`
- `models.py` の CHECK 制約が桁数まで強制しているので，違う書式は書き込み時に落ちる

## main.py 側から見た呼び出し（出席登録）

[API設計](api-design.md)の検証順序に対応する擬似コード．担当Bはこの形で実装する．

```python
@app.post("/attendances")
def register_attendance(req: RegisterRequest, request: Request,
                        user = Depends(require_role("student"))):
    client_ip = security.get_client_ip(request)
    device_id = request.cookies.get("device_id")

    # IP検証をトークン検証より前に置く
    # 学外からの試行にトークンの有効性を漏らさないため
    if not security.is_campus_ip(client_ip):
        security.write_audit_log("attendance_register", "failure",
                                 actor_user_id=user.id, client_ip=client_ip,
                                 detail="off_campus")
        raise HTTPException(403, "学内ネットワークからアクセスしてください")

    sess = get_open_session_or_404(req.attendance_session_id)
    require_enrolled(user.id, sess.course_id)

    if not security.verify_token(sess.id, sess.token_salt, req.token):
        security.write_audit_log("attendance_register", "failure",
                                 actor_user_id=user.id, client_ip=client_ip,
                                 target_type="attendance_session", target_id=sess.id,
                                 detail="invalid_token")
        raise HTTPException(403, "無効なQRです")

    scan_seq = count_scans(sess.id, user.id) + 1
    if scan_seq > sess.required_scan_count:
        raise HTTPException(409, "この回の出席は既に登録されています")

    # 受付時間帯の判定は1回目だけ．2回目以降は在室確認なので見ない
    if scan_seq == 1:
        status = security.classify_attendance(sess.scheduled_start_at, utcnow())
        if status is None:
            raise HTTPException(403, "受付時間を過ぎています")
    else:
        status = None

    # 端末の紐付けは検知だけ．ブロックしない
    if device_id and security.check_device_binding(device_id, user.id) == "conflict":
        security.write_audit_log("device_conflict", "success",
                                 actor_user_id=user.id, client_ip=client_ip,
                                 device_id=device_id, target_id=sess.id)

    with transaction():
        insert_scan(sess.id, user.id, scan_seq, client_ip, device_id)
        if scan_seq == 1:
            insert_attendance(sess.id, user.id, status)

    security.write_audit_log("attendance_register", "success",
                             actor_user_id=user.id, client_ip=client_ip,
                             device_id=device_id,
                             target_type="attendance_session", target_id=sess.id,
                             detail=f"scan_seq={scan_seq}")
```

## 境界を守るための取り決め

1. `main.py` から `security.py` の内部関数（アンダースコア始まり）を呼ばない
2. `main.py` にセキュリティ判定のロジックを書かない．「IPが `192.168.` で始まるか」のような判定を直接書き始めたら設計違反
3. `security.py` はHTTPのことを知らない．`Request` を受け取るのは `get_client_ip` だけ
4. 設定値を参照するのは `security.py` 側．`main.py` に閾値や分数をハードコードしない
5. ここに書いたシグネチャを変えたくなったら，先にこの文書を更新してから実装する（他の人の作業を壊さないため）
