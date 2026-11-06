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

`requirements.txt` は版を `==` で固定しています．テストを通した組み合わせと，サーバーで動く組み合わせを一致させるためです（[D-24](docs/decisions.md)）．版を上げるときは，入れ直してテストを通してから書き直してください．

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

pushとPull Requestで GitHub Actions が自動実行します．テストとは別に，依存ライブラリの既知の脆弱性を `pip-audit` で調べるジョブも走ります（更新のPRは Dependabot が毎週上げてきます）．

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

**担当A**：セキュリティ要件と脅威の洗い出し，設計判断とその採否の決定を
自分で行い，実装は生成AI（Claude）に依頼する形で進めました．
`security.py` とテストのコードは，大部分がAIによるものです．
自分が担ったのは，何をどう守るかを決めること，出てきた実装が意図どおりかを
確認すること，そして採用しなかった案も含めて理由を残すことです．
設計判断は [decisions.md](docs/decisions.md) に22件，不採用の案ごと記録しました．
AIの説明に根拠が示されないときは差し戻し，誤りがあった場合は記録を訂正しています．

**担当B**：以下のような手順で機能の実装を行いました．

1. 生成AIを用いて既存コードの概要を確認する
2. 機能を実現するための方針を考える
3. 方針に基づいてコードの作成を依頼する
4. コードの調整を生成AIに依頼するか，簡単な調整は自ら編集する

**担当C**：担当した部分のコード作成とエラーの修正には，ほぼ全面的に
生成AIを活用しました．自分で考えたのは，システムに必要な機能と実現したい
動作で，それをAIに指示しています．生成されたコードは実際に動かし，
意図した動作になっているかを確認しながら，必要な修正を指示しました．

## バージョン

`0.1.0`．まだ実地テストを通していない開発版です．

タグは付けていません．部活内での実地テスト（[test-report.md](docs/test-report.md)）を
通した版に `1.0.0` を付ける予定です．

## ライセンス

このソフトウェアは **Apache License 2.0** で公開しています．全文は [LICENSE](LICENSE)．

著作権表示は [NOTICE](NOTICE) にあります（`Copyright 2026 田中晴康`）．
`LICENSE` は Apache の原文のままにしてあります．末尾の付録は「自分の作品に
この License を適用する方法」を説明する雛形で，編集する箇所ではないためです．

各ソースファイルの先頭には SPDX 形式の2行を入れています．

```
# SPDX-FileCopyrightText: 2026 田中晴康
# SPDX-License-Identifier: Apache-2.0
```

Apache 2.0 が再配布時に求めているのは `LICENSE` と `NOTICE` の同梱（第4条）で，
**ファイル単位の表示は義務ではありません．** 1ファイルだけ抜き出されて他所に
置かれたときに，それが何なのか分かるようにするために入れてあります．
付録の13行の定型文ではなく SPDX 形式にしたのは，ライセンス検査ツールが読める形で，
かつ各ファイル冒頭の説明を下へ押し込まないためです．


### 使用しているソフトウェア

QRの生成・読み取りライブラリと Python のパッケージについては
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md) にまとめています．

| ライブラリ | 用途 | ライセンス |
|---|---|---|
| [qrcodejs](https://github.com/davidshimjs/qrcodejs) | 教員画面のQR生成 | MIT |
| [html5-qrcode](https://github.com/mebjas/html5-qrcode) | 学生画面のQR読み取り | Apache-2.0 |
| FastAPI / SQLAlchemy / Pydantic ほか | バックエンド | MIT / BSD / Apache-2.0 |

いずれもこのリポジトリには同梱しておらず，実行時に取得します．

### 商標

QRコードは株式会社デンソーウェーブの登録商標です

QR Code is a registered trademark of DENSO WAVE INCORPORATED in Japan and in other countries.

コードシンボルの生成・読み取り自体にライセンスや使用料は不要ですが，
**「QRコード」という名称を使う画面・印刷物ごとに登録商標文を掲載する**よう
求められています（[デンソーウェーブ 商標FAQ](https://www.denso-wave.com/ja/adcd/support/faq/trademark/)）．
そのため，アプリ側は全ページ共通のフッター（`app/templates/base.html`）に入れ，
フッターを隠している投影画面だけ `app/templates/teacher_qr.html` に直接置いています．
