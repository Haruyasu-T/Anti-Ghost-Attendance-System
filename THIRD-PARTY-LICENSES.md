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

**現時点では，コピーレフトのライセンスを持つ依存は1つも無い**（MIT / BSD /
Apache-2.0 / PSF-2.0 のみ）．以前は `certifi` が MPL-2.0 で唯一の例外だったが，
`httpx2` が `truststore` を使う構成になり，依存から外れた（2026-11-15 時点）．

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

## Python

**版は `requirements.lock` と一致させている．** サーバーに入るのはこのファイルで，
Linux / Python 3.11 向けの一覧である（[decisions.md](docs/decisions.md) D-27）．

### 直接指定しているもの（`requirements.txt`）

| パッケージ | バージョン | ライセンス |
|---|---|---|
| fastapi | 0.162.2 | MIT |
| uvicorn | 0.54.0 | BSD-3-Clause |
| sqlalchemy | 2.1.8 | MIT |
| pydantic | 2.14.3 | MIT |
| python-multipart | 0.0.33 | Apache-2.0 |
| jinja2 | 3.1.6 | BSD-3-Clause |
| bcrypt | 5.0.0 | Apache-2.0 |
| python-dotenv | 1.2.4 | BSD-3-Clause |

### テストのみ

| パッケージ | バージョン | ライセンス |
|---|---|---|
| pytest | 9.2.0 | MIT |
| httpx2 | 2.16.0 | BSD-3-Clause |

### 上記が引き込むもの

直接指定していないが，インストールされる．

| パッケージ | バージョン | ライセンス |
|---|---|---|
| annotated-doc | 0.0.6 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.16.0 | MIT |
| click | 8.5.1 | BSD-3-Clause |
| h11 | 0.16.0 | MIT |
| httpcore2 | 2.16.0 | BSD-3-Clause |
| httptools | 0.9.0 | MIT |
| idna | 3.20 | BSD-3-Clause |
| iniconfig | 2.3.1 | MIT |
| MarkupSafe | 3.0.4 | BSD-3-Clause |
| opentelemetry-api | 1.45.2 | Apache-2.0 |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause |
| pluggy | 1.7.0 | MIT |
| pydantic-core | 2.50.4 | MIT |
| Pygments | 2.21.0 | BSD-2-Clause |
| PyYAML | 6.0.3 | MIT |
| starlette | 1.10.0 | BSD-3-Clause |
| truststore | 0.10.5 | MIT |
| typing-extensions | 4.16.0 | PSF-2.0 |
| typing-inspection | 0.4.5 | MIT |
| uvloop | 0.23.0 | Apache-2.0 OR MIT（両方のライセンスファイルを同梱） |
| watchfiles | 1.3.0 | MIT |
| websockets | 17.4 | BSD-3-Clause |

`uvicorn[standard]` が `httptools` / `watchfiles` / `websockets` / `PyYAML` /
`uvloop` を引き込む．**`uvloop` は Linux 専用**で，Windows ではインストール
されない（`requirements.lock` でマーカーを付けている）．逆に Windows では
`click` が `colorama` を要求するが，サーバーはLinuxなのでこの一覧には入れていない．

`httpx2` / `httpcore2` / `truststore` は `starlette` の `TestClient` が使う．
starlette 1.6 から `httpx` ではなく `httpx2` を使うため入れ替えた（2026-11-01）．
`certifi` はこの入れ替えで依存から外れた（`truststore` がOSの証明書ストアを使うため）．

開発・CIの中だけで使うツールは，`requirements.txt` にも この一覧にも入れていない．
成果物に含まれないため．該当するのは `pip-audit`（CI）と `prettier`（整形・
`package.json` の devDependencies）．

---

## この一覧の作り方

手で書き写すと必ずずれる（実際，2026-11-01 から 11-15 の間に9個の版がずれていた）ので，
**`requirements.lock` を正として**，インストール済みパッケージのメタデータから生成する．

```bash
python -c "
import re, pathlib, importlib.metadata as md
norm = lambda n: re.sub(r'[-_.]+', '-', n).lower()
lock = dict(
    (norm(m.group(1)), (m.group(1), m.group(2)))
    for m in (
        re.match(r'^([A-Za-z0-9._-]+)==([^\s;]+)', l.strip())
        for l in pathlib.Path('requirements.lock').read_text(encoding='utf-8').splitlines()
        if l.strip() and not l.strip().startswith('#')
    ) if m
)
installed = dict((norm(d.metadata['Name']), d) for d in md.distributions() if d.metadata['Name'])
for key in sorted(lock):
    name, ver = lock[key]
    d = installed.get(key)
    if d is None:
        print(f'| {name} | {ver} | **手元に無い（別途確認）** |'); continue
    lic = (d.metadata.get('License-Expression') or d.metadata['License'] or '').strip()
    print(f'| {name} | {ver} | {lic.splitlines()[0] if lic else \"(分類子を参照)\"} |')
"
```

**手元がWindowsだと `uvloop` だけ出てこない**（Linux専用）．そのときはLinux用の
wheelからメタデータを読む．

```bash
pip download --no-deps --platform manylinux_2_17_x86_64 --python-version 3.11 \
    --only-binary=:all: uvloop==0.23.0 -d /tmp/uvloop
python -c "
import zipfile, glob
with zipfile.ZipFile(glob.glob('/tmp/uvloop/*.whl')[0]) as z:
    name = [n for n in z.namelist() if n.endswith('.dist-info/METADATA')][0]
    print('\n'.join(l for l in z.read(name).decode().splitlines()
                    if l.startswith(('License', 'Classifier: License'))))
"
```

依存を追加・更新したら，**`requirements.lock` と一緒にこの文書も更新する**．

最終確認日：2026-11-15（`requirements.lock` の33件すべてと突き合わせ済み）
