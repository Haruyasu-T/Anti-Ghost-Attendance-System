# 使用しているソフトウェアとそのライセンス

このシステムは以下のソフトウェアを利用している．いずれも本リポジトリには
**同梱しておらず**，実行時に取得する（Python は `pip install`，
フロントエンドのライブラリは CDN から配信）．

## 法的な位置づけ

MIT や Apache 2.0 の著作権表示義務は，**コピーを再配布するとき**に生じる．
このリポジトリはソースコードだけを配布し，第三者のコードを含めていないので，
厳密にはこの文書を置く義務はない．

それでも書いているのは2つの理由から．

1. 何に依存しているかを明示するため（サプライチェーンの可視化）
2. 将来 Docker イメージや配布物にまとめる場合，**その時点で義務が発生する**ため，
   先に一覧を作っておく

`certifi` のみ MPL-2.0（弱いコピーレフト）で，他とは条件が異なる．
ファイル単位の開示義務なので，改変せずに使う限り影響はない．

---

## フロントエンド（CDN配信・SRI付き）

| ライブラリ | バージョン | 用途 | ライセンス | 著作権者 |
|---|---|---|---|---|
| [qrcodejs](https://github.com/davidshimjs/qrcodejs) | 1.0.0 | 教員画面のQR**生成** | MIT | Kazuhiko Arase (2009), davidshimjs (2012) |
| [html5-qrcode](https://github.com/mebjas/html5-qrcode) | 2.3.8 | 学生画面のQR**読み取り** | Apache-2.0 | MINHAZ (mebjas) 2020-2023 |

どちらも `integrity` 属性（SRI）付きで読み込んでいる．CDN側が差し替えられても
ハッシュが合わなければ実行されない．

- `app/templates/teacher_qr.html` — qrcodejs（cdnjs）
- `app/templates/scan.html` — html5-qrcode（unpkg）

**注記**：html5-qrcode は内部に ZXing-js（`third_party/zxing-js.umd.js`）を
同梱している．こちらは別の著作権者による Apache-2.0 で，将来このライブラリを
自前で同梱する場合は ZXing 側の表示も必要になる．

---

## Python（実行時に必要なもの）

`requirements.txt` に直接書いているもの．

| パッケージ | バージョン | ライセンス |
|---|---|---|
| fastapi | 0.141.1 | MIT |
| uvicorn | 0.52.4 | BSD-3-Clause |
| sqlalchemy | 2.0.52 | MIT |
| pydantic | 2.13.5 | MIT |
| python-multipart | 0.0.32 | Apache-2.0 |
| jinja2 | 3.1.6 | BSD-3-Clause |
| bcrypt | 5.0.0 | Apache-2.0 |
| python-dotenv | 1.2.3 | BSD-3-Clause |

## Python（テストのみ）

| パッケージ | バージョン | ライセンス |
|---|---|---|
| pytest | 9.1.1 | MIT |
| httpx | 0.28.1 | BSD-3-Clause |

## Python（上記が引き込む依存）

直接指定していないが，インストールされるもの．

| パッケージ | バージョン | ライセンス |
|---|---|---|
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.14.2 | MIT |
| certifi | 2026.7.22 | **MPL-2.0** |
| click | 8.5.0 | BSD-3-Clause |
| colorama | 0.4.6 | BSD-3-Clause |
| greenlet | 3.5.5 | MIT AND PSF-2.0 |
| h11 | 0.16.0 | MIT |
| httpcore | 1.0.9 | BSD-3-Clause |
| httptools | 0.8.0 | MIT |
| idna | 3.19 | BSD-3-Clause |
| iniconfig | 2.3.0 | MIT |
| MarkupSafe | 3.0.3 | BSD-3-Clause |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause |
| pluggy | 1.6.0 | MIT |
| pydantic-core | 2.46.5 | MIT |
| Pygments | 2.21.0 | BSD-2-Clause |
| PyYAML | 6.0.3 | MIT |
| starlette | 1.6.0 | BSD-3-Clause |
| typing-extensions | 4.16.0 | PSF-2.0 |
| typing-inspection | 0.4.4 | MIT |
| watchfiles | 1.2.0 | MIT |
| websockets | 17.1 | BSD-3-Clause |

`uvicorn[standard]` が `httptools` / `watchfiles` / `websockets` / `PyYAML` /
`colorama` を引き込む．`uvloop` は Linux 用で，Windows ではインストールされない．

---

## この一覧の作り方

手で書き写すと必ずずれるので，インストール済みのパッケージのメタデータから
生成する．

```bash
python -c "
import importlib.metadata as md
for d in sorted(md.distributions(), key=lambda x: (x.metadata['Name'] or '').lower()):
    n = d.metadata['Name']
    if not n: continue
    lic = d.metadata.get('License-Expression') or d.metadata['License'] or ''
    print(f'| {n} | {d.version} | {lic.strip().splitlines()[0] if lic.strip() else \"(分類子を参照)\"} |')
"
```

依存を追加・更新したら，この文書も更新する．

最終確認日：2026-11-01
