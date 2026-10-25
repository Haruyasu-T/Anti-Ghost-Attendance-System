# DB設計

[要件定義](requirements.md)と[脅威モデル](threat-model.md)をもとにしたSQLiteのテーブル設計．

考え方としては，検証と制約をできるだけDBに落とし込む．アプリのロジックにバグがあっても最後にDBが止めてくれる状態にしておきたい．

## テーブル一覧

| テーブル | 役割 |
|---|---|
| `users` | 学生・教員．`role`で権限を分ける |
| `login_sessions` | ログインセッション．失効させられるようサーバー側で持つ |
| `courses` | 授業 |
| `enrollments` | 履修関係 |
| `attendance_sessions` | 出席セッション（授業回ごと） |
| `attendances` | 出席記録．1セッション×1学生で1行 |
| `attendance_scans` | 読み取りイベント．1回目・2回目…を個別に記録 |
| `manual_corrections` | 手動修正の監査ログ |
| `device_bindings` | 端末とアカウントの紐付け |
| `audit_logs` | セキュリティ関連イベントの記録 |

ガイドの最低構成は4テーブル（`users` / `courses` / `sessions` / `attendances`）だが，要件を満たすために6つ足している．足した理由は下の「設計メモ」に書いた．

## DDL

### users

```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    login_id      TEXT    NOT NULL UNIQUE,   -- 学生は学籍番号，教員は職員番号
    role          TEXT    NOT NULL CHECK (role IN ('student', 'teacher')),
    display_name  TEXT    NOT NULL,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);
```

`role` はCHECK制約で値を絞る．アプリ側のバリデーションをすり抜けても不正なロールは入らない．

平文パスワードを入れるカラムは作らない．

### login_sessions

```sql
CREATE TABLE login_sessions (
    id_hash      TEXT    PRIMARY KEY,   -- セッションIDのSHA-256
    user_id      INTEGER NOT NULL REFERENCES users(id),
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT    NOT NULL,
    expires_at   TEXT    NOT NULL,
    revoked_at   TEXT,                  -- NULLなら有効
    client_ip    TEXT,
    user_agent   TEXT
);

CREATE INDEX idx_login_sessions_user ON login_sessions (user_id);
```

セッションIDそのものは保存しない．Cookieには生の乱数を入れて，DBにはSHA-256ハッシュだけを置く．照合するときは受け取った値をハッシュ化して突き合わせる．パスワードと同じやり方で，これならDBが漏れてもセッションを乗っ取られない．

セッションIDは十分に長い乱数なので，bcryptのような低速ハッシュまでは要らない．SHA-256で足りる．

Cookieに入れるのはセッションIDだけにする．ユーザーIDやロールをCookieに入れるとクライアント側で書き換えられてしまう．

`revoked_at` があることで発行済みのセッションを取り消せる．これがサーバー側セッションを選んだ理由（設計メモ参照）．

### courses

```sql
CREATE TABLE courses (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL,
    teacher_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);
```

`teacher_id` が「教員が見られるのは担当授業だけ」という制限の根拠になる．

### enrollments

```sql
CREATE TABLE enrollments (
    course_id INTEGER NOT NULL REFERENCES courses(id),
    user_id   INTEGER NOT NULL REFERENCES users(id),
    PRIMARY KEY (course_id, user_id)
);
```

履修していない学生の登録を弾くのに要る．あと「誰が欠席か」を出すには履修者名簿が要る（欠席は「行がないこと」で表すので）．

### attendance_sessions

```sql
CREATE TABLE attendance_sessions (
    id                  INTEGER PRIMARY KEY,
    course_id           INTEGER NOT NULL REFERENCES courses(id),
    scheduled_start_at  TEXT    NOT NULL,          -- 授業の開始予定時刻
    started_at          TEXT    NOT NULL,          -- 教員がセッションを開始した時刻
    closed_at           TEXT,
    status              TEXT    NOT NULL DEFAULT 'open'
                                CHECK (status IN ('open', 'closed')),
    required_scan_count INTEGER NOT NULL DEFAULT 1,
    token_salt          TEXT    NOT NULL,
    created_by          INTEGER NOT NULL REFERENCES users(id)
);
```

`scheduled_start_at` と `started_at` を分けているのが要点．出席／遅刻の判定は「授業の開始時刻」を基準にすべきで，教員がボタンを押した時刻を使ってはいけない．教員が5分遅れて開始したら全員遅刻になってしまう．

`required_scan_count` で2回目以降の再表示を表す．教員が再表示するたびに1つ増える．

`token_salt` はセッション開始時に作る乱数で，QRトークンの導出に混ぜる．作り直すと出回っているQRが全部無効になる．

### attendances

```sql
CREATE TABLE attendances (
    id                    INTEGER PRIMARY KEY,
    attendance_session_id INTEGER NOT NULL REFERENCES attendance_sessions(id),
    user_id               INTEGER NOT NULL REFERENCES users(id),
    status                TEXT    NOT NULL CHECK (status IN ('present', 'late', 'absent')),
    record_source         TEXT    NOT NULL DEFAULT 'auto'
                                  CHECK (record_source IN ('auto', 'manual')),
    first_recorded_at     TEXT    NOT NULL,
    UNIQUE (attendance_session_id, user_id)
);
```

`UNIQUE (attendance_session_id, user_id)` が二重出席防止の最後の砦．アプリ側の重複チェックが漏れてもDBが拒否する．

`record_source` で「システムが自動判定した記録」と「教員が手動で直した記録」を区別する．

欠席は基本的に「この表に行がないこと」で表す（履修者名簿との差分）．教員が明示的に欠席として確定させたいときだけ `absent` の行を作る．

### attendance_scans

```sql
CREATE TABLE attendance_scans (
    id                    INTEGER PRIMARY KEY,
    attendance_session_id INTEGER NOT NULL REFERENCES attendance_sessions(id),
    user_id               INTEGER NOT NULL REFERENCES users(id),
    scan_seq              INTEGER NOT NULL,   -- 何回目の読み取りか（1から）
    scanned_at            TEXT    NOT NULL,   -- サーバー側の時刻
    client_ip             TEXT    NOT NULL,
    device_id             TEXT,
    UNIQUE (attendance_session_id, user_id, scan_seq)
);
```

`attendances` が「最終的な出席区分」を持ち，こちらが「読み取りの履歴」を持つ二段構成．

`UNIQUE (session, user, scan_seq)` で同じ回の読み取りを二重に登録できないようにする．

各読み取りに `client_ip` と `device_id` を残しておくと，異常検知（バーストや端末の使い回し）と事後の追跡ができる．

### manual_corrections

```sql
CREATE TABLE manual_corrections (
    id                    INTEGER PRIMARY KEY,
    attendance_session_id INTEGER NOT NULL REFERENCES attendance_sessions(id),
    target_user_id        INTEGER NOT NULL REFERENCES users(id),
    teacher_id            INTEGER NOT NULL REFERENCES users(id),
    before_status         TEXT,               -- NULL = 記録なしから新規追加
    after_status          TEXT    NOT NULL,
    reason                TEXT    NOT NULL,
    client_ip             TEXT,
    corrected_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);
```

手動修正の監査ログ．追記専用として扱い，アプリからのUPDATEとDELETEは実装しない．

「誰が・いつ・どの学生のどの授業回を・何から何に」という要件をそのままカラムにしている．`before_status` がNULLなら「記録が無い状態から追加した」という意味．

### device_bindings

```sql
CREATE TABLE device_bindings (
    device_id     TEXT    PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    first_seen_at TEXT    NOT NULL,
    last_seen_at  TEXT    NOT NULL
);
```

1つの端末を最初に使ったアカウントを記録する．別のアカウントが同じ `device_id` で登録しようとしたらブロックせず検知・記録する（Cookie削除で回避できる程度の対策なので，ブロックの根拠にするには弱い）．

### audit_logs

```sql
CREATE TABLE audit_logs (
    id                 INTEGER PRIMARY KEY,
    occurred_at        TEXT    NOT NULL DEFAULT (datetime('now')),
    action             TEXT    NOT NULL,
    result             TEXT    NOT NULL CHECK (result IN ('success', 'failure')),
    actor_user_id      INTEGER REFERENCES users(id),
    attempted_login_id TEXT,               -- ログイン失敗時（存在しないIDの場合）
    target_type        TEXT,
    target_id          INTEGER,
    client_ip          TEXT,
    device_id          TEXT,
    detail             TEXT
);

CREATE INDEX idx_audit_logs_action_time ON audit_logs (action, occurred_at);
CREATE INDEX idx_audit_logs_ip_time     ON audit_logs (client_ip, occurred_at);
CREATE INDEX idx_audit_logs_login_time  ON audit_logs (attempted_login_id, occurred_at);
```

記録する `action` は以下．

| action | いつ記録するか |
|---|---|
| `login` | ログイン試行（成功も失敗も） |
| `logout` | ログアウト |
| `session_start` | 出席セッション開始 |
| `session_close` | 出席セッション終了 |
| `rescan_start` | 2回目以降のQR再表示 |
| `token_rotate` | 塩の作り直し（QRの失効） |
| `session_start_time_update` | 授業開始時刻の訂正．`detail` に変更前後の時刻 |
| `attendance_register` | 出席登録．失敗も理由つきで |
| `manual_correction` | 手動修正 |
| `device_conflict` | 別アカウントに紐付いた端末からの登録を検知 |

インデックスはレート制限の検索（IP別・ログインID別の直近の失敗回数）を想定して張っている．

ログに残してはいけないものが2つある．パスワード（平文もハッシュも）と，QRの検証トークンそのもの．トークンは有効期限内なら再利用できてしまうので，どうしても必要ならハッシュ化して記録する．

## テーブルの関係

```
users ──┬─< login_sessions
        ├─< courses (teacher_id)
        ├─< enrollments >── courses
        ├─< attendances
        ├─< attendance_scans
        ├─< manual_corrections (teacher_id / target_user_id)
        ├─< device_bindings
        └─< audit_logs (actor_user_id)

courses ──< attendance_sessions ──┬─< attendances
                                  ├─< attendance_scans
                                  └─< manual_corrections
```

## 設計メモ

### `sessions` ではなく `attendance_sessions` にした

「セッション」はWebのログインセッションを指す語としても使う．コード中で `session` が2つの意味を持つと認可のバグを生みやすいので，出席セッションであることを名前で明示した．

### `attendances` と `attendance_scans` を分けた

要件に相反する制約が2つあったため．「同一授業で複数回登録できない」（一意制約が必要）と，「2回目以降のQRを読ませて記録する」（複数行が必要）．

1テーブルで両立させようとすると一意制約が張れなくなり，二重出席防止がアプリのロジックだけに依存する．そこで「確定した出席区分」（1行・一意制約つき）と「読み取りの履歴」（複数行）に分けた．

### ログインセッションをサーバー側で持つ

JWTのような署名付きCookieならDB保存が不要で実装も軽い．それでもサーバー側で持つことにした．

| 方式 | 良い点 | 悪い点 |
|---|---|---|
| 署名付きCookie（JWT等） | サーバー側の保存が不要 | 発行済みトークンを取り消せない |
| サーバー側セッション（採用） | `revoked_at` を立てるだけで即座に無効化できる | DBへの保存と参照が必要 |

決め手は脅威モデルの「教員アカウントの乗っ取り」．乗っ取りに気付いたときにそのアカウントの全セッションを即座に失効させられることが対策として意味を持つ．取り消せない方式だと，攻撃者のセッションが期限切れになるまで手が出せない．

この規模ではスケーラビリティの問題は起きないので，短所は実質ない．

### `enrollments` を足した

ガイドの最低構成には無いが，これが無いと履修していない学生の登録を弾けないし，「誰が欠席か」も出せない（履修者名簿との差分でしか求まらない）．

### トークン用のテーブルを作らず，塩を混ぜて計算する

```
window = floor(unix時刻 / QR_ROTATE_SECONDS)
token  = HMAC-SHA256(TOKEN_SECRET, f"{session_id}:{token_salt}:{window}") の先頭16文字
```

3案を比べた．

| 方式 | 良い点 | 悪い点 |
|---|---|---|
| DBに保存（ランダム生成） | 漏洩しても被害は数秒間・そのセッションのみ | 5秒ごとに1行増える（90分授業で1000行超）．掃除が必要．生成と表示の競合も考える必要がある |
| 秘密鍵のみから計算 | 保存不要．実装が単純 | 秘密鍵が漏れるだけで恒久的に全セッションを破られる．特定のトークンを失効できない |
| 秘密鍵＋セッション固有の塩（採用） | 保存はセッション開始時の1回だけ．実装は単純なまま．鍵が漏れても塩がなければ破れない．塩を作り直せば全QRを即座に失効できる | 塩を得るためのDB読み取りが要る（ただしセッションの状態確認で既に読んでいるので増分ゼロ） |

DB保存案の利点として最初は「ワンタイム化できる」を挙げていたが，これは本システムでは成立しない．QRはプロジェクターに投影されて多数の学生が同時に読むので，ワンタイムにすると最初の1人しか登録できない．「同じ学生が同じ回に2回登録できない」の方は一意制約と `scan_seq` で担保済み．

したがってDB保存案の実質的な利点は「漏洩時の被害が限定的」だけで，塩を混ぜればその差はほぼ埋まる．

前提として `TOKEN_SECRET` は環境変数で管理し，コードにも設定ファイルにも書かない．塩と組み合わせても，鍵とDBの両方が漏れれば破られる．

### 時刻の扱い

時刻カラムはUTCのISO 8601文字列で保存し，表示するときにJSTへ変換する．

出席／遅刻の判定に使うのは `scheduled_start_at` とサーバーの現在時刻だけ．クライアントから送られた時刻は一切使わない．

### SQLiteで注意すること

**外部キー制約がデフォルトで無効**．接続ごとに `PRAGMA foreign_keys = ON` を実行しないと `REFERENCES` が飾りになる．B-1で一番見落としやすいところ．

CHECK制約は有効なので，`role` や `status` の値域はDBで守られる．

監査ログの改変防止をDBレベルで強制する（トリガーでUPDATE/DELETEを禁止する等）ことはできるが，今回はアプリ側で「修正・削除を実装しない」ことで担保する．DBに直接アクセスできる人による改変は防げないという限界は残る．

## B-1でやること

- 上のDDLに対応する `app/models.py`（SQLAlchemyのモデル定義）
- 初期データ投入スクリプト（テスト用の教員1名・学生数名・授業1つ・履修関係）
- 接続時に `PRAGMA foreign_keys = ON` を必ず実行する設定

契約テストが [tests/test_models.py](../tests/test_models.py) にある．未実装のうちはスキップされ，実装が進むと自動的に有効になる．