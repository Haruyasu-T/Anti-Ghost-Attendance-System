# ブランチ運用ルール

2人チーム開発を前提にしたルール．

## ブランチ構成
- `main`：常に動く状態を保つ．直接コミット禁止．
- 作業ブランチ：`main`から都度切る．レビューされてマージされたら削除．

## ブランチ命名規則
- `feature/xxx`：新機能（例: `feature/dynamic-qr-token`, `feature/ip-verification`）
- `fix/xxx`：バグ修正（例: `fix/duplicate-attendance`）
- `docs/xxx`：ドキュメントのみ（例: `docs/threat-model`）

機能単位で切る．

## 作業フロー
1. `git checkout main && git pull` で最新化してから新しいブランチを切る
2. 作業してコミット（こまめに，1コミット=1つの意味のある変更）
3. `git push -u origin <ブランチ名>`
4. GitHubでPull Requestを作成する．タイトルは変更内容が分かるように，本文には「何を」「なぜ」「セキュリティ機能なら限界は何か」を書く
5. もう片方が読んでコメント／Approve
6. Approveが付いたら **Squash and merge** でマージ（コミット履歴をきれいに保つため）
7. マージ後はブランチを削除する

## GitHub側の設定（Branch protection rule）
`Settings → Branches → Add rule` で `main` に対して以下を設定する．
- Require a pull request before merging
- Require approvals（1件以上）
- Do not allow bypassing the above settings
- Require branches to be up to date before merging

## 衝突を避けるコツ
- 触るファイルが被りそうな作業は事前に一言共有する（例: `security.py`と`main.py`を同時に触る等）
- 長期化しそうなブランチは定期的に`main`を取り込む（`git merge main`または`git pull origin main`）
