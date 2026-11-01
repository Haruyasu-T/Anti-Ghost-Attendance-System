# 学内Wi-Fi連動 QR出席管理システム

**Anti-Ghost Attendance System (AGAS)** — version 0.1.0

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

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

### 1. 依存関係

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Windowsで `activate` が「スクリプトの実行が無効」と言われる場合は，以降のコマンドを `venv\Scripts\python.exe -m ...` の形で実行すれば同じことができます．有効化に失敗したまま `pip install` すると，グローバル側に入ってしまうので注意．

### 2. 設定

```bash
cp .env.example .env
```

必須は2つです．`TOKEN_SECRET` は次のコマンドで生成できます．

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

`CAMPUS_IP_RANGES` はローカルで動かすだけなら `127.0.0.1/32,192.168.0.0/16` で足ります．**本物の学内IPはデプロイ後に学内Wi-Fiから調べる値**なので，ここには書きません（[test-report.md](docs/test-report.md)）．

どちらも未設定だと起動時にエラーで止まります．開発用の既定値をコードに埋めていないためです（[decisions.md](docs/decisions.md) D-1）．

### 3. データベース

```bash
python -m scripts.init_db      # 10テーブルを作る
python -m scripts.seed_data    # 教員2名・学生5名・授業2つを入れる
```

**この2つを飛ばすとログインで500になります．** テーブルはアプリ起動時にも作られますが，中身が空だとアカウントが1つも無いためです．

`seed_data` はパスワードを**実行時に1度だけ表示します**．控えておいてください．固定値をリポジトリに置かないためで，環境変数 `SEED_PASSWORD` を指定すればその値を使います．

作られるアカウントは `T0001`・`T0002`（教員）と `S0001`〜`S0005`（学生）です．すべて架空の値です．`S0005` はどの授業にも履修登録していません（未履修者の拒否を試すため）．

### 4. 起動

```bash
uvicorn app.main:app --reload
```

**ブラウザでは `http://localhost:8000` を開いてください．**

`http://192.168.x.x` のようなLAN内のアドレスだとログインできません．セッションCookieに `Secure` を付けているため，HTTPSでないとブラウザが保存しないからです（`localhost` だけは例外扱いされます）．同じ理由でQR読み取りのカメラも起動しません．

**スマホから試すにはデプロイが必要です**（[deployment-guide.md](docs/deployment-guide.md)）．

## テスト

```bash
pytest
```

pushとPull Requestで GitHub Actions が自動実行します．

## 開発ルール

`main` への直接コミットは禁止で，機能ブランチとPRレビューで進めています．詳しくは [CONTRIBUTING.md](CONTRIBUTING.md) を参照してください．

## 製作者

3人チームで開発しています．要件定義と設計は3人で一緒に進め，実装から分担しました．

| 学籍番号 | 氏名 | 担当 |
|---|---|---|
| 2410990066 | 田中晴康 | 担当A：バックエンド／セキュリティ設計（`security.py`，脅威モデル） |
| 2410990054 | 藤本遥希 | 担当B：DB設計とAPI実装（`models.py`，`main.py`） |
| 2410990040 | 吉木郁矢 | 担当C：フロントエンド／インフラ（画面，デプロイ） |

## AIの活用範囲

<!-- TODO: 公開前に本人が書くこと．下は担当Aの分の下書き． -->

**担当A**：設計判断とセキュリティ要件は自分で決め，実装とレビューの相談に
生成AI（Claude）を使いました．具体的には，脅威モデルから対策を洗い出す過程の
議論，`security.py` のテストケースの洗い出し，ドキュメントの推敲です．
採用した設計判断は [decisions.md](docs/decisions.md) に理由ごと記録しており，
「AIが出した案をそのまま入れた」ものはありません．採用しなかった案も残しています．

**担当B**：（本人が記入）

**担当C**：（本人が記入）

## バージョン

`0.1.0`．まだ実地テストを通していない開発版です．

タグは付けていません．部活内での実地テスト（[test-report.md](docs/test-report.md)）を
通した版に `1.0.0` を付ける予定です．

## ライセンス

このソフトウェアは **Apache License 2.0** で公開しています．全文は [LICENSE](LICENSE)．

<!-- TODO: 著作権者の表記（NOTICE ファイル）は未確定．公開前に決めて追加する． -->


### 使用しているソフトウェア

QRの生成・読み取りライブラリと Python のパッケージについては
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md) にまとめています．

| ライブラリ | 用途 | ライセンス |
|---|---|---|
| [qrcodejs](https://github.com/davidshimjs/qrcodejs) | 教員画面のQR生成 | MIT |
| [html5-qrcode](https://github.com/mebjas/html5-qrcode) | 学生画面のQR読み取り | Apache-2.0 |
| FastAPI / SQLAlchemy / Pydantic ほか | バックエンド | MIT / BSD / Apache-2.0 |

いずれもこのリポジトリには同梱しておらず，実行時に取得します．
