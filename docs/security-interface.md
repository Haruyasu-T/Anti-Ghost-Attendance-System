# security.py インターフェース定義

`app/security.py`（担当A）が公開する関数と，`app/main.py`（担当B）がそれをどう呼ぶかの取り決め．

**この文書の目的**：担当Aが中身を実装している間も，担当Bが「この関数を呼ぶ」前提でAPIを書けるようにして並行作業を可能にすること．3人体制で最もコンフリクトが起きやすい境界なので，実装前に合意しておく．

---

## 設定値（環境変数・設定ファイル）

セキュリティに関わる値をコードに直書きしない．

| 名前 | 既定値 | 意味 |
|---|---|---|
| `TOKEN_SECRET` | （なし・**環境変数必須**） | トークン生成用の秘密鍵 |
| `QR_ROTATE_SECONDS` | 5 | QRとトークンの更新間隔（秒） |
| `TOKEN_ACCEPT_PREVIOUS_WINDOWS` | 1 | 直前いくつ前の世代まで受け付けるか |
| `PRESENT_BEFORE_MINUTES` | 5 | 開始何分前から出席として受け付けるか |
| `PRESENT_AFTER_MINUTES` | 5 | 開始何分後まで出席とするか |
| `LATE_UNTIL_MINUTES` | 20 | 開始何分後まで遅刻として受け付けるか |
| `CAMPUS_IP_RANGES` | （なし・設定必須） | 学内とみなすIPレンジのリスト（CIDR表記） |
| `LOGIN_MAX_FAILURES` | 5 | レート制限の閾値（失敗回数） |
| `LOGIN_WINDOW_MINUTES` | 10 | 失敗回数を数える期間 |
| `LOGIN_LOCKOUT_MINUTES` | 15 | 制限がかかる時間 |
| `BURST_THRESHOLD_COUNT` | 3 | バースト検知の閾値（同一IPからの登録件数） |
| `BURST_WINDOW_SECONDS` | 60 | バースト検知の集計期間 |

**`TOKEN_SECRET`の扱い**
- `.env`で管理し，`.gitignore`に含める（**リポジトリに絶対にコミットしない**）
- `.env.example`にはキー名だけを書き，値は空にする
- 起動時に未設定なら**エラーで停止する**．開発用の既定値をコードに埋めてはいけない（本番でそのまま動いてしまうため）

**`CAMPUS_IP_RANGES`の扱い**
- 実際の学内IPレンジも`.env`側で管理し，**リポジトリにコミットしない**
- 秘密鍵ほどの機密性はないが，リポジトリを公開した場合に学内ネットワークの構成を晒すことになるため，隠せるものは隠す
- 文書やコード中の例には`192.168.0.0/16`のようなプライベートアドレスの汎用例のみを使う

**リポジトリに書いてよい値・書いてはいけない値**

| 種類 | 扱い | 理由 |
|---|---|---|
| トークンの生成方式・長さ・更新間隔 | **書いてよい** | 安全性は鍵の秘密性のみに依存すべきで，方式を隠すことに依存する設計は誤り |
| トークンの例（架空の値） | 書いてよい | HMACの出力から鍵は逆算できず，かつ数秒で失効するため |
| `TOKEN_SECRET`の値 | 禁止 | 漏れると任意の有効トークンを生成でき，動的QRが無意味になる |
| 実際の学内IPレンジ | 禁止 | 学内ネットワーク構成の露出 |
| 実在の学籍番号・氏名・メールアドレス | 禁止 | 個人情報．例には架空の値（`S0001`等）を使う |
| 本物のパスワード（テスト用も含む） | 禁止 | テストコードへの直書きも同様に禁止 |

---

## 公開する関数

### パスワード

```python
def hash_password(plain: str) -> str:
    """パスワードをハッシュ化する（bcrypt）．"""

def verify_password(plain: str, password_hash: str) -> bool:
    """平文とハッシュを照合する．"""
```

- `passlib`（bcrypt）を使う．自前でハッシュ処理を書かない
- `verify_password`は，ユーザーが存在しない場合でも**ダミーのハッシュに対して照合を実行する**．早期リターンすると応答時間の差からアカウントの存在が推測できる（タイミング攻撃）

### ログインセッション

サーバー側でセッションを保持する（`login_sessions`テーブル）．採用理由は[DB設計](db-design.md)の設計判断を参照．

```python
def create_login_session(user_id: int, client_ip: str, user_agent: str) -> str:
    """新しいログインセッションを作成し，Cookieに入れるIDを返す．"""

def get_session_user(session_id: str) -> User | None:
    """セッションIDから利用者を引く．無効・期限切れ・失効済みならNone．"""

def revoke_login_session(session_id: str) -> None:
    """セッションを1つ失効させる（ログアウト）．"""

def revoke_all_sessions_for_user(user_id: int) -> None:
    """そのユーザーの全セッションを失効させる（乗っ取り対応）．"""
```

**実装上の必須事項**
- セッションIDは`secrets.token_urlsafe(32)`等の**暗号論的乱数**で生成する．連番・UUIDv1・時刻由来の値は使わない（推測されるとセッションを乗っ取られる）
- **DBに保存するのはセッションIDのSHA-256ハッシュ**．生の値は保存しない．`create_login_session`は生の値を返し（Cookieに入れる），DBには`id_hash`だけを書く．`get_session_user`は受け取った値をハッシュ化して照合する
  - こうするとDBが漏れてもセッションを乗っ取れない．セッションIDは十分長い乱数なので低速ハッシュは不要でSHA-256で足りる
- **Cookieに入れるのはセッションIDだけ**．ユーザーIDやロールをCookieに入れない
- `get_session_user`は`revoked_at`と`expires_at`を必ず確認する．どちらかに該当したら`None`を返す
- **ログイン成功時にセッションIDを再発行する**（セッション固定攻撃対策．攻撃者が事前に用意したIDのまま認証させない）

### 動的トークン

```python
def new_token_salt() -> str:
    """セッション固有の塩を生成する（セッション開始時・作り直し時に呼ぶ）．"""

def generate_token(session_id: int, token_salt: str,
                   at: datetime | None = None) -> str:
    """指定時刻の世代に対応するトークンを返す．at=Noneなら現在時刻．"""

def verify_token(session_id: int, token_salt: str, token: str,
                 at: datetime | None = None) -> bool:
    """トークンが現在世代または直前世代として妥当かを判定する．"""
```

**方式**

```
window = floor(unix_time / QR_ROTATE_SECONDS)
token  = HMAC-SHA256(TOKEN_SECRET, f"{session_id}:{token_salt}:{window}") の先頭16文字（16進）
```

**検証**：`window`と`window - 1`（`TOKEN_ACCEPT_PREVIOUS_WINDOWS`の数だけ遡る）について再計算し，一致するか調べる．

**実装上の必須事項**
- 比較は`hmac.compare_digest`を使う（`==`は文字列の一致位置によって処理時間が変わり，1文字ずつ推測される余地がある）
- `session_id`をHMACの入力に含めることで，**別のセッションのトークンを流用できないようにする**（同時刻に2つの授業が開講されていても互いのQRは使えない）
- `token_salt`を混ぜることで，**`TOKEN_SECRET`の漏洩だけではトークンを生成できないようにする**．攻撃者は対象セッションの塩をDBから入手する必要がある
- `new_token_salt`は`secrets.token_urlsafe(16)`等の暗号論的乱数を使う
- `at`引数はテスト専用．本番の呼び出しでは省略し，サーバー時刻を使う
- **`token_salt`は引数として受け取る**．`security.py`からDBを引かない（純粋関数のままにしてテストしやすさを保つため）

**塩の作り直しによる失効**
「QRを撮影されて出回った」と教員が気付いた場合，`token_salt`を作り直すと**出回っている全てのQRが即座に無効になる**．これは秘密鍵のみから導出する方式にはできなかった操作である．

**この方式の限界（脅威モデルに記載）**
- ワンタイム化はしない（同じ世代内なら同じトークンが複数人に通る）．QRを多数の学生が同時に読む以上これは必須の性質であり，二重登録はDBの一意制約と`scan_seq`で防ぐ
- `TOKEN_SECRET`と`token_salt`の**両方**が漏れると，そのセッションのトークンを任意に生成できる

### アクセス元IPの判定

```python
def is_campus_ip(client_ip: str) -> bool:
    """アクセス元IPが学内レンジに含まれるかを判定する．"""
```

- `ipaddress`モジュールで`CAMPUS_IP_RANGES`（CIDR）と照合する
- **引数に渡すIPの取得方法が重要**：リバースプロキシ経由の場合は`X-Forwarded-For`を見る必要があるが，このヘッダは**クライアントが自由に送れる**．信頼できるプロキシの背後にいる場合に限り，プロキシが付けた最後の値のみを使う．プロキシを経由しない構成では`request.client.host`を使い，`X-Forwarded-For`は一切参照しない
- この判断を誤ると「クライアントが自己申告したIPで学内判定する」ことになり，対策が完全に無効化される（④クライアントを信用しない，の最重要ポイント）

```python
def get_client_ip(request) -> str:
    """信頼できる経路からアクセス元IPを取得する．"""
```

`main.py`側でヘッダを直接読まず，必ずこの関数を通す．

### 受付時間帯の判定

```python
class AttendanceStatus(str, Enum):
    PRESENT = "present"
    LATE    = "late"

def classify_attendance(
    scheduled_start_at: datetime,
    now: datetime,
) -> AttendanceStatus | None:
    """出席区分を返す．受付時間外ならNone．"""
```

`scheduled_start_at`からの経過時間を`t`（分）とする．**境界値はすべて「学生に有利な側」に含める**と決定した．

| 条件 | 戻り値 |
|---|---|
| `t < -5` | `None`（早すぎる） |
| `-5 <= t <= +5` | `PRESENT` |
| `+5 < t <= +20` | `LATE` |
| `t > +20` | `None`（受付終了） |

- **`t = -5`ちょうど → `PRESENT`**（受付開始の瞬間から受け付ける）
- **`t = +5`ちょうど → `PRESENT`**（遅刻にしない）
- **`t = +20`ちょうど → `LATE`**（受付終了にしない）

境界を学生に有利な側へ倒す理由は，1秒の差で不利益が生じると異議申し立てが増え，教員の手動修正への依存が高まるためである．手動修正はそれ自体が攻撃面であり，運用の摩擦を減らすことがセキュリティ上も望ましい．

- `now`は**サーバー時刻**を渡す．クライアントから受け取った時刻を渡してはいけない
- 「早すぎる」場合（開始5分前より前）も`None`を返す．授業前に前もって読み取っておく行為を防ぐ

### 端末の紐付け

```python
def issue_device_id() -> str:
    """新しい端末識別子を発行する（暗号論的乱数）．"""

class DeviceCheckResult(str, Enum):
    OK          = "ok"           # 未登録，または同一ユーザー
    CONFLICT    = "conflict"     # 別のユーザーに紐付いている

def check_device_binding(device_id: str, user_id: int) -> DeviceCheckResult:
    """端末が別アカウントに紐付いていないかを調べ，必要なら紐付けを記録する．"""
```

- `CONFLICT`でも**登録をブロックしない**．`audit_logs`に`device_conflict`として記録し，教員のアラート画面に出す
- `device_id`はHttpOnlyのCookieで配る．JavaScriptから読めない形にして，ページ側で書き換えられないようにする
- **限界**：Cookieを削除すれば新しい端末として扱われ，シークレットモードでも回避できる．そのためブロックの根拠にはしない

### レート制限

```python
def is_login_rate_limited(login_id: str, client_ip: str) -> bool:
    """直近の失敗回数から，ログイン試行を拒否すべきかを判定する．"""
```

- `audit_logs`の`action='login'` かつ `result='failure'` を，`login_id`別と`client_ip`別の両方で数える
- **両方見る理由**：`login_id`だけだと1つのIPから多数のIDを総当たりされる．`client_ip`だけだと分散したIPから1つのIDを狙われる

### 異常検知

```python
def detect_burst(attendance_session_id: int, client_ip: str) -> bool:
    """同一IPから短時間に閾値を超える登録があったかを判定する．"""
```

---

## 監査ログの書き込み

```python
def write_audit_log(
    action: str,
    result: str,                      # "success" | "failure"
    actor_user_id: int | None = None,
    attempted_login_id: str | None = None,
    target_type: str | None = None,
    target_id: int | None = None,
    client_ip: str | None = None,
    device_id: str | None = None,
    detail: str | None = None,
) -> None:
    """監査ログを1件記録する．"""
```

**呼び出し側の責務**
- 出席登録は**成功・失敗のいずれも**記録する．失敗理由を`detail`に入れる
- 手動修正は`manual_corrections`への記録と**同一トランザクション**で行い，ログの書き込みが失敗したら修正をロールバックする
- `detail`にパスワードとトークンを入れない

---

## main.py 側から見た呼び出し順（出席登録）

[API設計](api-design.md)の検証順序に対応する擬似コード．担当Bはこの形で実装する．

```python
@app.post("/attendances")
def register_attendance(req: RegisterRequest, request: Request,
                        user = Depends(require_role("student"))):
    client_ip = security.get_client_ip(request)
    device_id = request.cookies.get("device_id")

    # 4. IP検証（トークン検証より前に置く．学外からの試行にトークンの有効性を漏らさないため）
    if not security.is_campus_ip(client_ip):
        security.write_audit_log("attendance_register", "failure",
                                 actor_user_id=user.id, client_ip=client_ip,
                                 detail="off_campus")
        raise HTTPException(403, "学内ネットワークからアクセスしてください")

    # 5. セッションの存在と状態
    sess = get_open_session_or_404(req.attendance_session_id)

    # 6. 履修確認
    require_enrolled(user.id, sess.course_id)

    # 7. トークン検証
    if not security.verify_token(sess.id, req.token):
        security.write_audit_log("attendance_register", "failure",
                                 actor_user_id=user.id, client_ip=client_ip,
                                 target_type="attendance_session", target_id=sess.id,
                                 detail="invalid_token")
        raise HTTPException(403, "無効なQRです")

    # 8. 何回目の読み取りか
    scan_seq = count_scans(sess.id, user.id) + 1
    if scan_seq > sess.required_scan_count:
        raise HTTPException(409, "この回の出席は既に登録されています")

    # 9. 受付時間帯（1回目のみ）
    if scan_seq == 1:
        status = security.classify_attendance(sess.scheduled_start_at, utcnow())
        if status is None:
            raise HTTPException(403, "受付時間を過ぎています")
    else:
        status = None   # 在室確認では出席区分を変更しない

    # 10. 端末の紐付け（ブロックしない）
    if device_id and security.check_device_binding(device_id, user.id) == "conflict":
        security.write_audit_log("device_conflict", "success",
                                 actor_user_id=user.id, client_ip=client_ip,
                                 device_id=device_id, target_id=sess.id)

    # 11. 記録（一意制約違反は409に変換）
    with transaction():
        insert_scan(sess.id, user.id, scan_seq, client_ip, device_id)
        if scan_seq == 1:
            insert_attendance(sess.id, user.id, status)

    # 12. 監査ログ
    security.write_audit_log("attendance_register", "success",
                             actor_user_id=user.id, client_ip=client_ip,
                             device_id=device_id,
                             target_type="attendance_session", target_id=sess.id,
                             detail=f"scan_seq={scan_seq}")
```

---

## この境界を守るための取り決め

1. `main.py`から`security.py`の内部関数（アンダースコア始まり）を呼ばない
2. `main.py`にセキュリティ判定のロジックを書かない．「IPが`192.168.`で始まるか」のような判定を直接書き始めたら設計違反
3. `security.py`はHTTPのことを知らない．`Request`オブジェクトを受け取るのは`get_client_ip`だけに限定する
4. 設定値を参照するのは`security.py`側．`main.py`に閾値や分数をハードコードしない
5. この文書のシグネチャを変える場合は**先に文書を更新してから実装する**（担当Bの作業を壊さないため）
