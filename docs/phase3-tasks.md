# フェーズ3 実装タスク一覧

[開発フェーズ詳細ガイド](development-phases-guide.md)のフェーズ3を，3人体制の担当別に分解したもの．
設計の詳細は[DB設計](db-design.md)・[API設計](api-design.md)・[security.pyインターフェース](security-interface.md)・[画面設計](screen-design.md)を参照する．

---

## 着手順の原則

**最初に `models.py`（B-1）を上げること．** `security.py`のうちDBを触る関数と，すべてのAPIがこれを待っている．

一方で，`security.py`の**前半（A-1〜A-5）はDBに依存しない**ので，`models.py`を待たずに着手できる．担当Aは純粋関数から始めれば，B-1と並行して進められる．

```
        B-1 models.py ──┬──> B-3 以降のAPI全部
                        └──> A-6 以降（DB依存：セッション・監査ログ・端末紐付け等）

A-1〜A-5（DB不要）────────> 先行して着手できる
        └─ A-3 トークン ──> B-4, B-5 が依存

C-1〜C-2（モックで先行可）──> B-3 完成後に結合
```

**PRの粒度**：原則1タスク＝1PR．大きくなるほどレビューが形骸化する．

---

## 担当A（セキュリティ）

`app/security.py` と認可まわり．**このプロジェクトで面接に直結する部分**なので，生成コードをそのまま通さず，1つずつ「なぜこの実装か」を説明できる状態にする．

### A-1. 設定値の読み込み
- `.env.example`と`.gitignore`は設定済み．`cp .env.example .env`して各自の値を入れる
- [security-interface.md](security-interface.md)の設定値一覧を`python-dotenv`で読み込む仕組みを作る
- **`TOKEN_SECRET`が未設定なら起動時にエラーで停止させる**．開発用の既定値をコードに埋めない
- 完了条件：`TOKEN_SECRET`を空にして起動するとエラーで止まる

### A-2. パスワードのハッシュ化
- `hash_password` / `verify_password`（passlib のbcrypt）
- ユーザーが存在しない場合も**ダミーハッシュに対して照合を実行する**（早期リターンすると応答時間でアカウントの存在が分かる）
- 完了条件：正しいパスワードで`True`，誤りで`False`．同じ平文でもハッシュが毎回変わること（ソルト）を確認

### A-3. 動的トークンの生成・検証 ★心臓部
- `new_token_salt()` / `generate_token(session_id, token_salt, at=None)` / `verify_token(session_id, token_salt, token, at=None)`
- 方式：`HMAC-SHA256(TOKEN_SECRET, f"{session_id}:{token_salt}:{window}")` の先頭16文字．`window = floor(unix時刻 / QR_ROTATE_SECONDS)`
- **必須事項**
  - 比較は `hmac.compare_digest`（`==`はタイミング攻撃の余地がある）
  - `session_id`をHMACの入力に含める（別セッションのトークンを流用させない）
  - `token_salt`を混ぜる（`TOKEN_SECRET`の漏洩だけでは破られないようにする）
  - `token_salt`は**引数で受け取る**．`security.py`からDBを引かない（純粋関数のままテストできる状態を保つ）
  - 現在世代と直前1世代を受け付ける
- 完了条件（pytest）
  - 生成直後のトークンが通る
  - 1世代前のトークンが通る
  - 2世代前のトークンが**通らない**
  - 別の`session_id`のトークンが**通らない**
  - **別の`token_salt`のトークンが通らない**（塩を作り直すと失効することの確認）
  - 1文字書き換えたトークンが**通らない**

### A-4. アクセス元IPの判定
- `is_campus_ip(client_ip)` / `get_client_ip(request)`
- `ipaddress`モジュールでCIDRと照合
- **`X-Forwarded-For`の扱いに注意**．このヘッダはクライアントが自由に送れる．信頼できるプロキシの背後にいる構成でない限り参照しない．誤ると「クライアントの自己申告で学内判定する」ことになり対策が完全に無効化される
- 完了条件：学内レンジ内で`True`，外で`False`．偽の`X-Forwarded-For`を付けたリクエストで判定が変わらないこと

### A-5. 受付時間帯の判定
- `classify_attendance(scheduled_start_at, now)` → `PRESENT` / `LATE` / `None`
- **境界値は決定済み**（[decisions.md](decisions.md) D-10）：ちょうどの値は学生に有利な側に含める
- 完了条件（pytest）：境界値をすべて確認する

| 経過時間 `t`（分） | 期待値 |
|---|---|
| `t = -6` | `None`（早すぎる） |
| `t = -5` ちょうど | `PRESENT` |
| `t = 0` | `PRESENT` |
| `t = +5` ちょうど | `PRESENT`（遅刻にしない） |
| `t = +6` | `LATE` |
| `t = +20` ちょうど | `LATE`（受付終了にしない） |
| `t = +21` | `None`（受付終了） |

### A-6. ログインセッション（B-1 完了後）
- `create_login_session` / `get_session_user` / `revoke_login_session` / `revoke_all_sessions_for_user`
- セッションIDは`secrets.token_urlsafe(32)`等の**暗号論的乱数**．連番やUUIDv1は使わない
- **DBに保存するのはセッションIDのSHA-256ハッシュ**．生の値は保存しない（DBが漏れても乗っ取られないようにする）
- **Cookieに入れるのはセッションIDだけ**．ユーザーIDやロールを入れない
- `get_session_user`は`revoked_at`と`expires_at`を必ず確認する
- **ログイン成功時にセッションIDを再発行する**（セッション固定攻撃対策）
- 完了条件：`revoke_login_session`を呼んだ後，同じCookieでアクセスすると401になる

### A-7. 認可の依存関数
- `require_login()` / `require_role("teacher")` / `require_course_owner()` / `require_session_owner()`
- FastAPIの`Depends`として宣言的に付ける形にする．各エンドポイントに`if`を書く方式にしない（1箇所の書き忘れが脆弱性になる）
- 完了条件：学生のセッションで教員用エンドポイントを叩くと403，他の教員の授業を指定すると404

### A-8. 監査ログ
- `write_audit_log(...)`
- **パスワードとトークンを`detail`に入れない**
- 完了条件：ログイン成功・失敗の両方が`audit_logs`に残る

### A-9. 端末の紐付け
- `issue_device_id()` / `check_device_binding(device_id, user_id)`
- HttpOnly Cookieで配る．**ブロックせず検知・記録のみ**
- 完了条件：別アカウントで同じ`device_id`を使うと`conflict`が返り，`audit_logs`に記録される（登録自体は成功する）

### A-10. レート制限
- `is_login_rate_limited(login_id, client_ip)`
- **`login_id`別と`client_ip`別の両方**を見る（片方だけだと分散攻撃か総当たりのどちらかを取り逃す）

### A-11. バースト検知
- `detect_burst(attendance_session_id, client_ip)`

### A-12. 継続タスク：B・CのPRレビュー
セキュリティ観点で見る．特に：
- 認可の依存関数が付いているか（付け忘れが最大のリスク）
- クライアントから来た値を判定に使っていないか
- エラー時に内部情報を返していないか
- フロントで`localStorage`にトークンを保存していないか

---

## 担当B（バックエンド／DB・API）

`app/models.py` と `app/main.py`．

### B-1. models.py ★最優先・全員のブロッカー
- [DB設計](db-design.md)のDDLに対応するSQLAlchemyモデル（10テーブル）
- `attendance_sessions.token_salt`と`login_sessions.id_hash`を忘れずに入れる
- **接続ごとに`PRAGMA foreign_keys = ON`を実行する**．SQLiteは外部キーがデフォルト無効で、忘れると`REFERENCES`が飾りになる
- 一意制約を必ず入れる：`attendances(attendance_session_id, user_id)` と `attendance_scans(attendance_session_id, user_id, scan_seq)`
- 完了条件：DBを作成し、同じ`(session, user)`で2行入れようとすると**DBが拒否する**ことを確認

### B-2. 初期データ投入スクリプト
- 教員1名・学生4〜5名・授業1つ・履修関係
- **学籍番号は架空の値（`S0001`等）を使う．実在の値を入れない**
- パスワードはA-2の`hash_password`を通す

### B-3. 認証API
- `POST /auth/login` / `POST /auth/logout` / `GET /auth/me`
- Cookieは`HttpOnly` / `Secure` / `SameSite=Lax`
- **失敗時に「IDが無い」と「パスワードが違う」を区別しない**
- セッション管理（A-6）・レート制限（A-10）・監査ログ（A-8）を組み込む

### B-4. 出席セッション系API
- `POST /courses/{id}/attendance-sessions`（`scheduled_start_at`を受け取る）
- `GET /attendance-sessions/{id}/token` ← **最も認可を間違えてはいけないエンドポイント．教員かつ担当授業のみ**
- `POST /attendance-sessions/{id}/rescan` / `POST .../rotate-token` / `POST .../close`
- セッション開始時に`new_token_salt()`で塩を生成して保存する
- 完了条件：**学生のセッションで`/token`を叩くと403**（テストを必ず書く）

### B-5. 出席登録API ★核心
- `POST /attendances`
- [API設計](api-design.md)の検証順序を**そのままの順で**実装する．特に**IP検証をトークン検証より前**に置く（学外からの試行にトークンの有効性を漏らさないため）
- 1回目のみ受付時間帯を判定．2回目以降は在室確認なので判定しない
- 一意制約違反は409に変換する
- 成功・失敗の両方を監査ログに記録
- 完了条件：正常登録・期限切れ・学外IP・二重登録・未履修 の5パターンをテストで確認

### B-6. 出席状況一覧API
- `GET /attendance-sessions/{id}/attendances`
- **履修者全員を返す**（未登録者も空欄の行として含める．欠席者を見落とさないため）

### B-7. 手動修正API
- `PATCH /attendances/{id}`
- **`manual_corrections`への記録と同一トランザクション**にする．監査ログの書き込みが失敗したら修正自体をロールバックする（記録のない修正を残さない）
- `record_source`を`manual`に更新
- 完了条件：修正すると`manual_corrections`に変更前後の値が残る

### B-8. アラートAPI
- `GET /attendance-sessions/{id}/alerts`（端末の重複・バースト）

---

## 担当C（フロントエンド／インフラ）

`app/templates/` とデプロイ．

### C-1. 共通レイアウトとCSS
- スマホの縦画面前提．教員の管理画面はPC

### C-2. ログイン画面（S1）
- 他の画面の前提になるので最初に作る
- 「授業開始前にログインしておいてください」の案内を入れる（QRを読んでから未ログインだと、ログイン中に5秒の有効期限が切れる）
- B-3が未完でもモックで先行できる

### C-3. 学生ホーム（S2）
- 「QRを読み取る」「自分の履歴」の2つだけ．**他人の記録への導線を画面上に作らない**

### C-4. QR読み取り→結果画面（S3）
- `html5-qrcode`等でカメラ起動．端末標準のカメラアプリから`/scan`に着地しても同じ処理
- **期限切れ時の「もう一度読む」を1タップで**．5秒更新なので失敗は前提．やり直しが煩雑だと手動修正への依存が増え、結果としてセキュリティが落ちる

### C-5. 教員のQR表示画面（S6）
- `qrcode.js`等でクライアント側描画（サーバーから画像を返す必要はない）
- 5秒ごとに`GET .../token`をポーリングして再描画
- **更新までの残り時間を視覚的に出す**（切り替わる直前に読み始めて失敗するのを減らす）
- QRは投影前提で大きく．登録済み人数と受付中の区分も表示
- 「2回目のQRを表示」ボタン（確認ダイアログは出さない．学生に気付かれる前に押せるように）
- 「QRを作り直す」ボタン（**こちらは確認ダイアログを出す**．全員が再読み取りになるため）

### C-6. 出席状況一覧（S7）と手動修正ダイアログ
- 履修者全員を表示．「1回目のみ」に警告マーク（ただし自動で欠席にはしない）
- 修正ダイアログには**理由の入力欄**と「この操作は記録されます」の明示を入れる（記録が残ると見せること自体が抑止になる）

### C-7. 学生の履歴画面（S4）
- 本人の記録のみ。学籍番号の入力欄やURLパラメータを設けない

### C-8. デプロイ環境の準備
- 無料枠のホスティング（Render / Railway / Fly.io 等）を調査して比較
- HTTPSが使えることが必須（トークンとCookieを平文で流さない）
- 環境変数の設定方法を確認（`TOKEN_SECRET`をどこに置くか）

### C-9. CIの有効化
- `.github/workflows/test.yml`は設置済み（pushとPRで`pytest`を自動実行する）
- 最初のテストがマージされたら，`main`のBranch protectionで「Require status checks to pass before merging」を有効にする
- フェーズ1で設定できなかった項目がここで回収できる

### 担当Cが踏みやすい落とし穴
1. トークンを`localStorage`に保存しない（XSSで盗まれる経路を作る）
2. `device_id`をJavaScriptで独自に作って送らない（クライアントで偽装できるものを判定に使うことになる）
3. 時刻をクライアントで計算して送らない（判定はサーバー）
4. **画面にボタンを出さないことは認可ではない**．APIを直接叩かれる前提で考える
5. サーバーの例外メッセージをそのまま画面に出さない

---

## 3人共通のルール

- ブランチ名：`feature/token-generation`のように機能単位（[CONTRIBUTING.md](../CONTRIBUTING.md)）
- PRの本文に「何を」「なぜ」「セキュリティ機能なら限界は何か」を書く
- 作者以外の1人以上がApproveしてから Squash and merge
- **生成コードをそのままマージしない**．1つずつ「なぜこうなっているか」を確認する
- 実装中に[security-interface.md](security-interface.md)のシグネチャを変えたくなったら，**先に文書を更新してから実装する**（他の担当の作業を壊さないため）
- 詰まったら早めに共有する．特にA-3（トークン）とB-5（出席登録）は他がブロックされる
