# 学内Wi-Fi連動 QR出席管理システム

QRコードを学内Wi-Fi環境下で読み込んだときだけ出席として認めることで，代返（なりすまし出席）を防ぐ出席管理システムです．

大学の授業でよくある「友人にQRのスクショを送って出席にしてもらう」「1回目だけ出て帰る」といった手口を，具体的な攻撃として想定した上で対策を設計しました．

## 何をやっているか

- **動的QR** — 5秒ごとにトークンが変わるので，スクショを転送しても間に合わない
- **サーバー側でのIP検証** — 学内ネットワークからのアクセスだけを受け付ける．クライアントの自己申告は使わない
- **2回目以降のQR再表示** — 教員が任意のタイミングでもう一度読ませることで，中抜けを検知する
- **DBレベルの一意制約** — 二重出席をアプリのロジックではなくDBで止める
- **監査ログ** — 誰が・いつ・どの端末から登録したかを残し，端末の使い回しや異常な登録を検知する

対策しても防ぎきれない部分（学内にいる共犯者による代理登録，アカウントの貸与など）は，隠さず限界として文書に書いています．

## 技術スタック

- Python 3.11+ / FastAPI / SQLAlchemy / SQLite
- HTML / JavaScript（QRの表示と読み取り）

## ドキュメント

設計の判断はすべて `docs/` に残しています．

| 文書 | 内容 |
|---|---|
| [要件定義](docs/requirements.md) | 何を作るか |
| [脅威モデル](docs/threat-model.md) | 想定した攻撃と対策，残る限界 |
| [DB設計](docs/db-design.md) | テーブル定義と設計の理由 |
| [API設計](docs/api-design.md) | エンドポイントと認可・検証の順序 |
| [security.pyのインターフェース](docs/security-interface.md) | セキュリティ機能の契約 |
| [画面設計](docs/screen-design.md) | 画面のラフ |
| [決めたことと，その理由](docs/decisions.md) | 設計判断の記録．採用しなかった案とその理由も |
| [フェーズ3 実装タスク](docs/phase3-tasks.md) | 担当別のタスク |

## セットアップ

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env       # TOKEN_SECRET などを設定する
uvicorn app.main:app --reload
```

`TOKEN_SECRET` は次のコマンドで生成できます．

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

未設定だと起動時にエラーで止まります（開発用の既定値をコードに埋めていないため）．

## テスト

```bash
pytest
```

pushとPull Requestで GitHub Actions が自動実行します．

## 開発ルール

`main` への直接コミットは禁止で，機能ブランチとPRレビューで進めています．詳しくは [CONTRIBUTING.md](CONTRIBUTING.md) を参照してください．

## メンバー

3人チームで開発しています．

- 担当A：バックエンド／セキュリティ設計（`security.py`，脅威モデル）
- 担当B：DB設計とAPI実装（`models.py`，`main.py`）
- 担当C：フロントエンド／インフラ（画面，デプロイ）

要件定義と設計は3人で一緒に進め，実装から分担しました．
