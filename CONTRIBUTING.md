# 開発の進め方

3人で開発するにあたって決めたルール．

## ブランチ

**`main` 1本で運用する．** `develop` のような中間ブランチは置かない（3人・数週間の規模で挟む利点が薄く，どこにPRを出すか迷う原因になるため．一時期 `develop` があったが廃止した）．

`main` は常に動く状態を保つ．直接コミットしない．

作業ブランチは `main` から都度切って，マージされたら削除する．**マージ済みのブランチは残さない**（どれが生きているか分からなくなる）．

名前の付け方：

- `feature/xxx` — 新機能（例：`feature/dynamic-qr-token`，`feature/ip-verification`）
- `fix/xxx` — バグ修正（例：`fix/duplicate-attendance`）
- `docs/xxx` — ドキュメントのみ（例：`docs/threat-model`）

機能単位で切る．

## 作業の流れ

```bash
git checkout main
git pull
git checkout -b feature/xxx
```

作業してコミットする．コミットはこまめに，1コミット1つの意味のある変更で．

```bash
git push -u origin feature/xxx
```

GitHubでPull Requestを作る．タイトルは変更内容が分かるように．本文には「何を」「なぜ」を書き，セキュリティに関わる機能なら「限界は何か」も書く．

作者以外の1人以上がレビューしてApproveしたら Squash and merge．履歴をきれいに保つため．マージ後はブランチを削除する．

## レビューで見ること

- 設計文書と食い違っていないか
- 認可の依存関数が付いているか（付け忘れが一番危ない）
- クライアントから来た値を判定の根拠にしていないか
- エラーメッセージで内部情報を漏らしていないか

生成したコードをそのままマージしない．1つずつ「なぜこうなっているか」を確認してから通す．

## mainの保護設定

**現状，保護は効いていない．** GitHub Free の個人アカウント＋Privateリポジトリでは，Branch protection も Rulesets も使えないため（Rulesets は Team 以上，classic の Branch protection は Pro 以上）．

したがって以下は**全員が意識して守る運用ルール**であって，仕組みで強制されていない．

- `main` に直接pushしない
- 作者以外の1人以上がApproveしてからマージする

publicにすれば無料で保護が使えるようになるので，公開のタイミング（フェーズ5）で設定する．そのときに「Require status checks to pass before merging」も有効にする（CIは `.github/workflows/test.yml` で動いている）．

## コンフリクトを避けるために

- 触るファイルが被りそうなときは事前に一声かける（`security.py` と `main.py` を同時に触る場合など）
- 長引きそうなブランチは定期的に `main` を取り込む（`git merge main` か `git pull origin main`）
- 設計文書のシグネチャを変えたくなったら，先に文書を更新してから実装する

## コミットとリポジトリで気をつけること

リポジトリは最終的に公開する予定なので，以下は絶対に入れない．

- `TOKEN_SECRET` の値（`.env` は `.gitignore` 済み）
- 実際の学内IPレンジ
- 実在の学籍番号・氏名・メールアドレス（例には `S0001` のような架空の値を使う）
- 本物のパスワード（テストコードへの直書きも含む）
