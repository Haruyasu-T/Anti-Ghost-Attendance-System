# フェーズ3 実装タスク

[開発フェーズ詳細ガイド](development-phases-guide.md)のフェーズ3を，3人の担当別に分けたもの．
設計の詳細は[DB設計](db-design.md)・[API設計](api-design.md)・[security.pyのインターフェース](security-interface.md)・[画面設計](screen-design.md)を見ること．

## 着手の順番

最初に `models.py`（B-1）を上げること．`security.py` のDBを触る関数も，APIも全部これを待っている．

一方で `security.py` の前半（A-1〜A-5）はDBに依存しないので，`models.py` を待たずに始められる．担当Aは純粋関数から手を付ければB-1と並行して進められる．

```
        B-1 models.py ──┬──> B-3 以降のAPI全部
                        └──> A-6 以降（セッション・監査ログ・端末紐付け等）

A-1〜A-5（DB不要）────────> 先に着手できる
        └─ A-3 トークン ──> B-4, B-5 が依存

C-1〜C-2（モックで先行可）──> B-3 完成後に結合
```

PRは原則1タスク1本．大きくなるほどレビューが形だけになる．

---

## 担当A（セキュリティ）

`app/security.py` と認可まわり．面接に直結する部分なので，生成コードをそのまま通さず1つずつ「なぜこの実装か」を説明できる状態にしておく．

### A-1. 設定値の読み込み ✅ 実装済み

`app/config.py` に集約．`cp .env.example .env` して各自の値を入れる．

`TOKEN_SECRET` が未設定なら起動時にエラーで止まる．開発用の既定値はコードに埋めない．不正なCIDRや整数変換の失敗も起動時に弾く．

### A-2. パスワードのハッシュ化 ✅ 実装済み

`hash_password` / `verify_password`．

`bcrypt` を直接使う（`passlib` は新しい `bcrypt` と非互換で動かなかった）．bcryptは72バイトで切り捨てるので，SHA-256で畳んでから渡している．

ユーザーが存在しない場合もダミーハッシュに対して照合を実行する．早期リターンすると応答時間でアカウントの存在が分かってしまう．

### A-3. 動的トークンの生成・検証 ✅ 実装済み

`new_token_salt()` / `generate_token(session_id, token_salt, at=None)` / `verify_token(session_id, token_salt, token, at=None)`．

`HMAC-SHA256(TOKEN_SECRET, f"{session_id}:{token_salt}:{window}")` の先頭16文字．`window = floor(unix時刻 / QR_ROTATE_SECONDS)`．

比較は `hmac.compare_digest`．一致してもループを抜けない（抜けると何世代前で一致したかが処理時間に出る）．

テスト済み：生成直後が通る／1世代前が通る／2世代前は通らない／別の `session_id` は通らない／別の `token_salt` は通らない／1文字書き換えは通らない．

### A-4. アクセス元IPの判定 ✅ 実装済み

`is_campus_ip(client_ip)` / `get_client_ip(request)`．

`TRUSTED_PROXY_COUNT` を導入した．0なら `X-Forwarded-For` を一切見ず，Nなら右からN番目を使う．外部にデプロイするとロードバランサの背後に入るのでヘッダを見る必要があるが，素直に先頭を使うと学外の攻撃者が偽装できてしまう．

### A-5. 受付時間帯の判定 ✅ 実装済み

`classify_attendance(scheduled_start_at, now)` → `PRESENT` / `LATE` / `None`．

境界値は学生に有利な側に含める（[decisions.md](decisions.md) D-10）．

| 経過時間 `t`（分） | 期待値 |
|---|---|
| `t = -6` | `None`（早すぎる） |
| `t = -5` ちょうど | `PRESENT` |
| `t = 0` | `PRESENT` |
| `t = +5` ちょうど | `PRESENT`（遅刻にしない） |
| `t = +6` | `LATE` |
| `t = +20` ちょうど | `LATE`（受付終了にしない） |
| `t = +21` | `None`（受付終了） |

タイムゾーンなしの `datetime` は `ValueError` で落とす．

### A-6. ログインセッション ⚠ 実装済み・B-1待ち

`create_login_session` / `get_session_user` / `revoke_login_session` / `revoke_all_sessions_for_user`．

- セッションIDは `secrets.token_urlsafe(32)` などの暗号論的乱数．連番やUUIDv1は使わない
- DBに保存するのはSHA-256ハッシュ．生の値は保存しない
- Cookieに入れるのはセッションIDだけ．ユーザーIDやロールは入れない
- `get_session_user` は `revoked_at` と `expires_at` を必ず見る
- ログイン成功時にセッションIDを再発行する（セッション固定攻撃の対策）

完了の目安：`revoke_login_session` を呼んだ後，同じCookieでアクセスすると401になる．

**B-1側で足りないもの**：`LoginSession` の `revoked_at` / `created_at` / `client_ip` / `user_agent`．特に `revoked_at` が無いと失効させられず，サーバー側セッションを選んだ意味が無くなる．

### A-7. 認可の依存関数 ⚠ 実装済み・B-1待ち

`require_login()` / `require_role("teacher")` / `require_course_owner()` / `require_session_owner()`．

FastAPIの `Depends` として宣言的に付ける形にする．各エンドポイントに `if` を書く方式にしない．1箇所の書き忘れがそのまま脆弱性になる．

`app/auth.py` に置いた．`security.py` をHTTPから切り離しておくため．
DBセッションの受け渡しに `app/db.py` も暫定で作った（担当Bが引き取ってよい）．

完了の目安：学生のセッションで教員用エンドポイントを叩くと403，他の教員の授業を指定すると404．

**B-1待ち**：`Course` / `AttendanceSession` を引くため．動作確認はB-1完了後．

### A-8. 監査ログ ⚠ 実装済み・B-1待ち

`write_audit_log(db, ...)` と `write_audit_log_now(session_factory, ...)` の2つ．

後者は独立したトランザクションで即コミットする．失敗して例外を投げる経路で
前者を使うと，ロールバックでログごと消えてしまうため．拒否された試行こそ
後から追いたい情報なので経路を分けた．

パスワードとトークンを `detail` に入れない．秘密鍵の混入は実装側でも弾く．

完了の目安：ログイン成功・失敗の両方が `audit_logs` に残る．

**B-1側で足りないもの**：`AuditLog` テーブルそのもの．A-10（レート制限）と
A-11（バースト検知）もこれを読むので，同時に止まっている．

### A-9. 端末の紐付け

`issue_device_id()` / `check_device_binding(device_id, user_id)`．HttpOnly Cookieで配る．ブロックせず検知・記録だけ．

完了の目安：別アカウントで同じ `device_id` を使うと `conflict` が返り `audit_logs` に記録される．登録自体は成功する．

### A-10. レート制限

`is_login_rate_limited(login_id, client_ip)`．`login_id` 別と `client_ip` 別の両方を見る．片方だけだと分散攻撃か総当たりのどちらかを取り逃す．

### A-11. バースト検知

`detect_burst(attendance_session_id, client_ip)`．

### A-12. B・CのPRレビュー（継続）

セキュリティ観点で見る．特に：

- 認可の依存関数が付いているか（付け忘れが最大のリスク）
- クライアントから来た値を判定に使っていないか
- エラー時に内部情報を返していないか
- フロントで `localStorage` にトークンを保存していないか

---

## 担当B（バックエンド／DB・API）

`app/models.py` と `app/main.py`．

### B-1. models.py（最優先・全員のブロッカー）

[DB設計](db-design.md)のDDLに対応するSQLAlchemyモデル（10テーブル）．

- `attendance_sessions.token_salt` と `login_sessions.id_hash` を忘れずに
- **接続ごとに `PRAGMA foreign_keys = ON` を実行する**．SQLiteは外部キーがデフォルト無効で，忘れると `REFERENCES` が飾りになる
- 一意制約を必ず入れる：`attendances(attendance_session_id, user_id)` と `attendance_scans(attendance_session_id, user_id, scan_seq)`

契約テストが [tests/test_models.py](../tests/test_models.py) にある．未実装のうちはスキップされ，実装すると自動的に有効になる．期待する形（`Base` / `create_db_engine(url)` / 各モデルクラス）はテスト冒頭のdocstringに書いてある．名前や型を変えたい場合は，先にテストと設計文書を更新してから実装すること．

### B-2. 初期データ投入スクリプト

教員1名・学生4〜5名・授業1つ・履修関係．学籍番号は架空の値（`S0001` など）を使い，実在の値は入れない．パスワードは A-2 の `hash_password` を通す．

### B-3. 認証API

`POST /auth/login` / `POST /auth/logout` / `GET /auth/me`．

Cookieは `HttpOnly` / `Secure` / `SameSite=Lax`．失敗時に「IDが無い」と「パスワードが違う」を区別しない．セッション管理（A-6）・レート制限（A-10）・監査ログ（A-8）を組み込む．

### B-4. 出席セッション系API

- `POST /courses/{id}/attendance-sessions`（`scheduled_start_at` を受け取る）
- `GET /attendance-sessions/{id}/token` — 教員かつ担当授業のみ．**最も認可を間違えてはいけないエンドポイント**
- `POST /attendance-sessions/{id}/rescan` / `POST .../rotate-token` / `POST .../close`
- セッション開始時に `new_token_salt()` で塩を作って保存する

完了の目安：学生のセッションで `/token` を叩くと403（テストを必ず書く）．

### B-5. 出席登録API（核心）

`POST /attendances`．

[API設計](api-design.md)の検証順序をそのままの順で実装する．特にIP検証をトークン検証より前に置く（学外からの試行にトークンの有効性を漏らさないため）．

1回目のみ受付時間帯を判定．2回目以降は在室確認なので判定しない．一意制約違反は409に変換．成功も失敗も監査ログに記録．

完了の目安：正常登録・期限切れ・学外IP・二重登録・未履修 の5パターンをテストで確認．

### B-6. 出席状況一覧API

`GET /attendance-sessions/{id}/attendances`．履修者全員を返す（未登録者も空欄の行として含める．欠席者を見落とさないため）．

### B-7. 手動修正API

`PATCH /attendances/{id}`．`reason` は必須で，空文字は400で拒否．

`manual_corrections` への記録と同一トランザクションにする．監査ログの書き込みが失敗したら修正自体をロールバックする．記録の残らない修正を作らないため．`record_source` を `manual` に更新．

完了の目安：修正すると `manual_corrections` に変更前後の値が残る．

### B-8. アラートAPI

`GET /attendance-sessions/{id}/alerts`（端末の重複・バースト）．

---

## 担当C（フロントエンド／インフラ）

`app/templates/` とデプロイ．

### C-1. 共通レイアウトとCSS

スマホの縦画面前提．教員の管理画面はPC．

### C-2. ログイン画面（S1）

他の画面の前提になるので最初に作る．「授業開始前にログインしておいてください」の案内を入れる（QRを読んでから未ログインだと，ログイン中に5秒の有効期限が切れる）．B-3が未完でもモックで先行できる．

### C-3. 学生ホーム（S2）

「QRを読み取る」「自分の履歴」の2つだけ．他人の記録への導線を画面上に作らない．

### C-4. QR読み取りと結果画面（S3）

`html5-qrcode` などでカメラを起動．端末標準のカメラアプリから `/scan` に着地しても同じ処理にする．

期限切れ時の「もう一度読む」を1タップで．5秒更新なので失敗は前提で，やり直しが煩雑だと手動修正への依存が増えて結果的にセキュリティが落ちる．

### C-5. 教員のQR表示画面（S6）

`qrcode.js` などでクライアント側描画（サーバーから画像を返す必要はない）．5秒ごとに `GET .../token` をポーリングして再描画．

更新までの残り時間を視覚的に出す（切り替わる直前に読み始めて失敗するのを減らす）．QRは投影前提で大きく．登録済み人数と受付中の区分も出す．

「2回目のQRを表示」ボタンは確認ダイアログを出さない（学生に気付かれる前に押せるように）．「QRを作り直す」ボタンは確認ダイアログを出す（全員が再読み取りになるため）．

### C-6. 出席状況一覧（S7）と手動修正ダイアログ

履修者全員を表示．「1回目のみ」に警告マーク（ただし自動で欠席にはしない）．

修正ダイアログには理由の入力欄（必須）と「この操作は記録されます」の明示を入れる．記録が残ると見せること自体が抑止になる．

### C-7. 学生の履歴画面（S4）

本人の記録のみ．学籍番号の入力欄やURLパラメータを作らない．

### C-8. デプロイ環境の準備

無料枠のホスティング（Render / Railway / Fly.io など）を調べて比較する．HTTPSが使えることが必須（トークンとCookieを平文で流さないため）．環境変数の設定方法も確認しておく（`TOKEN_SECRET` をどこに置くか）．

デプロイ後，学内Wi-Fiに繋いだ状態でIP確認サイトを見て，大学のグローバル出口IPを `CAMPUS_IP_RANGES` に設定する．出口が複数ある可能性があるので，学内の何箇所かで確認した方がいい．この値はコミットしない．

あわせて `TRUSTED_PROXY_COUNT` を1（ロードバランサ1台の背後の場合）にする．ここを間違えるとIP検証が機能しなくなる．

### C-9. CIの有効化

`.github/workflows/test.yml` は設置済み（pushとPRで `pytest` が走る）．

Branch protectionで「Require status checks to pass before merging」を有効にする．フェーズ1で設定できなかった項目がここで回収できる．

### 担当Cが踏みやすいところ

1. トークンを `localStorage` に保存しない（XSSで盗まれる経路を作る）
2. `device_id` をJavaScriptで独自に作って送らない（クライアントで偽装できるものを判定に使うことになる）
3. 時刻をクライアントで計算して送らない（判定はサーバー）
4. 画面にボタンを出さないことは認可ではない．APIを直接叩かれる前提で考える
5. サーバーの例外メッセージをそのまま画面に出さない

---

## 3人共通のルール

- ブランチ名は機能単位（`feature/token-generation` など）．[CONTRIBUTING.md](../CONTRIBUTING.md) 参照
- PRの本文に「何を」「なぜ」「セキュリティ機能なら限界は何か」を書く
- 作者以外の1人以上がApproveしてから Squash and merge
- 生成コードをそのままマージしない．1つずつ「なぜこうなっているか」を確認する
- 実装中に [security-interface.md](security-interface.md) のシグネチャを変えたくなったら，先に文書を更新してから実装する
- 詰まったら早めに共有する．特にA-3（トークン）とB-5（出席登録）は他の人がブロックされる
