# DB設計

[要件定義](requirements.md)と[脅威モデル](threat-model.md)を前提に，SQLiteでのテーブル設計を定義する．

設計方針は「**検証と制約をDBレベルに落とし込み，アプリのロジックが漏れても最後の防壁が残る状態にする**」こと（⑤安全なデフォルト）．

---

## テーブル一覧

| テーブル | 役割 |
|---|---|
| `users` | 学生・教員．`role`で権限分離 |
| `login_sessions` | ログインセッション（サーバー側で保持し，失効させられる） |
| `courses` | 授業．担当教員を持つ |
| `enrollments` | 履修関係（誰がどの授業を取っているか） |
| `attendance_sessions` | 出席セッション（授業回ごと） |
| `attendances` | 出席記録．**1セッション×1学生につき1行**（一意制約） |
| `attendance_scans` | 読み取りイベント．1回目・2回目…を個別に記録 |
| `manual_corrections` | 手動修正の監査ログ（追記専用） |
| `device_bindings` | 端末とアカウントの紐付け |
| `audit_logs` | セキュリティ関連イベントの記録（ログイン試行・登録失敗など） |

開発フェーズ詳細ガイドでは最低4テーブル（`users` / `courses` / `sessions` / `attendances`）と書いているが，要件を満たすために6つ追加している．追加した理由は後述の「設計判断」に記載する．

---

## DDL

### users

```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    login_id      TEXT    NOT NULL UNIQUE,   -- 学生は学籍番号，教員は職員番号
    role          TEXT    NOT NULL CHECK (role IN ('student', 'teacher')),
    display_name  TEXT    NOT NULL,
    password_hash TEXT    NOT NULL,          -- ハッシュのみ．平文は保存しない
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);
```

- `role`を`CHECK`制約で限定する．アプリ側のバリデーションを通り抜けても不正なロールは入らない
- `password_hash`にはbcrypt（またはArgon2）のハッシュを入れる．平文パスワードを保持するカラムは**作らない**

### login_sessions

```sql
CREATE TABLE login_sessions (
    id           TEXT    PRIMARY KEY,   -- 暗号論的乱数．Cookieに入れる値
    user_id      INTEGER NOT NULL REFERENCES users(id),
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT    NOT NULL,
    expires_at   TEXT    NOT NULL,
    revoked_at   TEXT,                  -- 失効させた時刻．NULLなら有効
    client_ip    TEXT,
    user_agent   TEXT
);

CREATE INDEX idx_login_sessions_user ON login_sessions (user_id);
```

**Cookieに入れるのは`id`（乱数）だけ**．ユーザーIDやロールをCookieに入れてはいけない．クライアント側で書き換えられる値を認可の根拠にすることになる（④クライアントを信用しない）．

- `id`は`secrets.token_urlsafe()`等の暗号論的乱数で生成する．連番や推測可能な値は使わない
- `revoked_at`があることで**発行済みのセッションを取り消せる**．これが署名付きCookie（JWT等）ではなくサーバー側セッションを選んだ理由（後述の設計判断を参照）
- `expires_at`で有効期限を持たせ，期限切れのセッションは認証を通さない

### courses

```sql
CREATE TABLE courses (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL,
    teacher_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);
```

- `teacher_id`が「教員が閲覧・修正できる範囲を担当授業に限定する」という要件の根拠になる（②最小権限）

### enrollments

```sql
CREATE TABLE enrollments (
    course_id INTEGER NOT NULL REFERENCES courses(id),
    user_id   INTEGER NOT NULL REFERENCES users(id),
    PRIMARY KEY (course_id, user_id)
);
```

- 履修していない学生の出席登録を拒否するために必要
- 「誰が欠席なのか」を出すには履修者名簿が必要（欠席は「行がないこと」で表現するため）

### attendance_sessions

```sql
CREATE TABLE attendance_sessions (
    id                  INTEGER PRIMARY KEY,
    course_id           INTEGER NOT NULL REFERENCES courses(id),
    scheduled_start_at  TEXT    NOT NULL,          -- 授業の開始予定時刻（出席/遅刻の判定基準）
    started_at          TEXT    NOT NULL,          -- 教員が実際にセッションを開始した時刻
    closed_at           TEXT,
    status              TEXT    NOT NULL DEFAULT 'open'
                                CHECK (status IN ('open', 'closed')),
    required_scan_count INTEGER NOT NULL DEFAULT 1, -- 教員が再表示するたびに +1
    created_by          INTEGER NOT NULL REFERENCES users(id)
);
```

- **`scheduled_start_at`と`started_at`を分けている**のが重要な点．出席／遅刻の判定は「授業の開始時刻」を基準にすべきで，教員がボタンを押した時刻を基準にしてはいけない（教員が5分遅れて開始したら全員が遅刻になってしまう）
- `required_scan_count`で2回目以降の再表示を表現する．教員が再表示するたびに1つ増える

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

- **`UNIQUE (attendance_session_id, user_id)`が二重出席防止の最終防壁**．アプリ側の重複チェックが漏れても，DBが登録を拒否する
- `record_source`で「システムが自動判定した記録」と「教員が手動修正した記録」を区別する（要件の「元の記録と手動修正を区別できるようにする」に対応）
- 欠席は原則「この表に行がないこと」で表現する（履修者名簿との差分）．教員が明示的に欠席として確定させたい場合のみ`absent`の行を作る

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

- `attendances`が「最終的な出席区分」を持ち，`attendance_scans`が「読み取りの履歴」を持つ二段構成
- `UNIQUE (session, user, scan_seq)`により，同じ回の読み取りを二重に登録できない
- `client_ip`と`device_id`を各読み取りに残すことで，異常検知（バースト・端末の使い回し）と事後追跡ができる（⑥追跡可能性）

### manual_corrections

```sql
CREATE TABLE manual_corrections (
    id                    INTEGER PRIMARY KEY,
    attendance_session_id INTEGER NOT NULL REFERENCES attendance_sessions(id),
    target_user_id        INTEGER NOT NULL REFERENCES users(id),
    teacher_id            INTEGER NOT NULL REFERENCES users(id),
    before_status         TEXT,               -- NULL = 記録なしから新規追加した
    after_status          TEXT    NOT NULL,
    reason                TEXT,
    client_ip             TEXT,
    corrected_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);
```

- 手動修正の監査ログ．**追記専用として扱い，アプリからのUPDATE / DELETEは実装しない**
- 「誰が・いつ・どの学生のどの授業回を・変更前から変更後へ」という要件をそのままカラムにしている
- `before_status`がNULLなら「記録がない状態から追加した」ことを意味する

### device_bindings

```sql
CREATE TABLE device_bindings (
    device_id     TEXT    PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    first_seen_at TEXT    NOT NULL,
    last_seen_at  TEXT    NOT NULL
);
```

- 1つの端末を最初に使ったアカウントを記録する
- 別のアカウントが同じ`device_id`で登録しようとした場合は**ブロックせず検知・記録する**（脅威モデルの決定通り．Cookie削除で回避できる程度の対策なので，ブロックの根拠にするには弱い）

### audit_logs

```sql
CREATE TABLE audit_logs (
    id                 INTEGER PRIMARY KEY,
    occurred_at        TEXT    NOT NULL DEFAULT (datetime('now')),
    action             TEXT    NOT NULL,   -- login / attendance_register / manual_correction ...
    result             TEXT    NOT NULL CHECK (result IN ('success', 'failure')),
    actor_user_id      INTEGER REFERENCES users(id),
    attempted_login_id TEXT,               -- ログイン失敗時（存在しないIDの場合に使う）
    target_type        TEXT,
    target_id          INTEGER,
    client_ip          TEXT,
    device_id          TEXT,
    detail             TEXT                -- 失敗理由など
);

CREATE INDEX idx_audit_logs_action_time ON audit_logs (action, occurred_at);
CREATE INDEX idx_audit_logs_ip_time     ON audit_logs (client_ip, occurred_at);
CREATE INDEX idx_audit_logs_login_time  ON audit_logs (attempted_login_id, occurred_at);
```

記録する`action`：

| action | 記録するタイミング |
|---|---|
| `login` | ログイン試行（成功・失敗の両方） |
| `logout` | ログアウト |
| `session_start` | 出席セッション開始 |
| `session_close` | 出席セッション終了 |
| `rescan_start` | 2回目以降のQR再表示の開始 |
| `attendance_register` | 出席登録（成功・**失敗も理由つきで**） |
| `manual_correction` | 手動修正 |
| `device_conflict` | 既に別アカウントに紐付いた端末からの登録を検知 |

インデックスはレート制限のための検索（IP別・ログインID別の直近の失敗回数）を想定して張っている．

**ログに残してはいけないもの**
- パスワード（平文・ハッシュとも）
- QRの検証トークンそのもの（有効期限内に読み取られると再利用できてしまうため．必要ならハッシュ化して記録する）

---

## ER図（テキスト表現）

```
users ──┬─< courses (teacher_id)
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

---

## 設計判断とその理由

### 1. なぜ`sessions`ではなく`attendance_sessions`にしたか
「セッション」はWebのログインセッションを指す語としても使われるため，コード中で`session`が2つの意味を持つと，認可のバグを生みやすい．出席セッションであることを名前で明示する．

### 2. なぜ`attendances`と`attendance_scans`を分けたか
要件に相反する2つの制約があるため．

- 「同一授業で複数回登録できない」（二重出席防止 → 一意制約が必要）
- 「2回目以降のQRを読ませて記録する」（複数回の記録が必要）

1つのテーブルで両方を満たそうとすると一意制約を張れなくなり，二重出席防止がアプリのロジックだけに依存する．そこで「確定した出席区分」（1行・一意制約つき）と「読み取りの履歴」（複数行）を分けた．

### 3. なぜログインセッションをサーバー側で持つか
Cookieに署名付きの認証情報を入れる方式（JWT等）ならDBへの保存が不要になり，実装も軽い．それでもサーバー側で保持する方式を選んだ．

| 方式 | 長所 | 短所 |
|---|---|---|
| 署名付きCookie（JWT等） | サーバー側の保存が不要．スケールしやすい | **発行済みトークンを取り消せない**．有効期限が切れるまで有効なまま |
| **サーバー側セッション（採用）** | `revoked_at`を立てるだけで即座に無効化できる．全セッションの一括失効も可能 | DBへの保存と参照が必要 |

決め手は[脅威モデル](threat-model.md)の「教員アカウントの乗っ取り」である．乗っ取りに気付いたときに**そのアカウントの全セッションを即座に失効させられること**が対策として意味を持つ．取り消せない方式では，攻撃者のセッションが期限切れになるまで手が出せない．

なお，本システムの規模ではスケーラビリティの短所は問題にならない．

### 4. なぜ`enrollments`を追加したか
ガイドの最低構成には無いが，以下が実現できないため追加した．

- 履修していない学生の登録を拒否する（②最小権限）
- 「誰が欠席か」を出す（履修者名簿との差分でしか求められない）

### 5. なぜトークン用のテーブルを作らないか
動的QRのトークンは**DBに保存せず，秘密鍵とサーバー時刻から都度計算する**方式を採る（詳細は[security.pyインターフェース](security-interface.md)）．

| 方式 | 長所 | 短所 |
|---|---|---|
| DBに保存（ランダム生成） | ワンタイム化（使用済みフラグ）ができる | 5秒ごとに1行増える（90分授業で1000行超）．期限切れ行の掃除が必要 |
| **秘密鍵から計算（採用）** | 保存不要．期限は計算で自然に切れる．「直前1世代も受け付ける」を単純に実装できる | ワンタイム化ができない．秘密鍵が漏れると任意のトークンを生成できる |

ワンタイム化できない点は，二重登録が`attendances`の一意制約と`scan_seq`の管理で防がれているため実害にならないと判断した．一方で**秘密鍵の漏洩は「教室にいなくても有効なQRを作れる」ことに直結する**ため，鍵は環境変数で管理し，コードにも設定ファイルにも書かない．この点は脅威として明記が必要（後述の「フェーズ2で見つかった脅威」を参照）．

### 6. 時刻の扱い
- すべての時刻カラムはUTCのISO 8601文字列で保存し，表示時にJSTへ変換する
- 出席／遅刻の判定に使うのは`scheduled_start_at`とサーバーの現在時刻のみ．クライアントから送られた時刻は一切使わない（④クライアントを信用しない）

### 7. SQLite固有の注意点
- **外部キー制約はデフォルトで無効**．接続ごとに`PRAGMA foreign_keys = ON`を実行する必要がある（忘れると`REFERENCES`が飾りになる）
- `CHECK`制約は有効なので，`role`や`status`の値域はDBで守られる
- 監査ログの改変防止をDBレベルで強制する（トリガーで`UPDATE`/`DELETE`を禁止するなど）ことは可能だが，今回はアプリ側で「修正・削除の実装をしない」ことで担保する．**DBに直接アクセスできる者による改変は防げない**という限界がある

---

## フェーズ3で作るもの（担当Bのタスク）
- 上記DDLに対応する`app/models.py`（SQLAlchemyのモデル定義）
- 初期データ投入スクリプト（テスト用の教員1名・学生数名・授業1つ・履修関係）
- `PRAGMA foreign_keys = ON`を接続時に必ず実行する設定
