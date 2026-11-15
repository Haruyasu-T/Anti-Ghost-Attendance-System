# SPDX-FileCopyrightText: 2026 田中晴康
# SPDX-License-Identifier: Apache-2.0

"""`/about`（ライセンス表示）のテスト．

ライセンス表示は**利用者が見られる場所に置く**必要がある．認証の後ろに隠すと
表示したことにならないので，「ログインなしで見られる」ことを固定する．
"""
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import __version__
from app.main import app

client = TestClient(app)

REPO_ROOT = Path(__file__).resolve().parents[1]

# デンソーウェーブ指定の文例そのまま（末尾に句点を付けない）
TRADEMARK = "QRコードは株式会社デンソーウェーブの登録商標です"


def test_about_is_public():
    """ログインしていなくても見られる（リダイレクトもしない）．"""
    response = client.get("/about")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_about_shows_the_license():
    assert "Apache License" in client.get("/about").text


def test_about_credits_every_author():
    """製作者が1人でも落ちていないこと．"""
    body = client.get("/about").text

    for author in ("田中晴康", "藤本遥希", "吉木郁矢"):
        assert author in body


def test_about_does_not_show_student_ids():
    """製作者欄に学籍番号を出さないこと．

    `login_id` は学籍番号そのもの（`docs/db-design.md`）なので，**動いている
    画面**に並べると有効なログインIDを公開することになる．パスワードが分からな
    ければ入れないが，ログイン失敗を重ねられればレート制限（D-22）で本人たちの
    アカウントがロックされる．`README.md` は静的な文書なので扱いを分けた
    （`CONTRIBUTING.md`）．

    学籍番号そのものをこのファイルに書くと同じ問題になるので，**製作者欄に
    数字が1文字も無いこと**で確かめる．
    """
    body = client.get("/about").text
    credits = re.search(r'<ul class="credits">(.*?)</ul>', body, re.S)

    assert credits is not None, "製作者欄の構造が変わっている"
    assert re.search(r"\d", credits.group(1)) is None


def test_readme_version_matches_the_code():
    """READMEの版表記が `__version__` と一致していること.

    `app/__init__.py` が正本で，`/about` 画面もREADMEもこの値を出す．
    「更新時は両方を直すこと」とコメントに書いてあるが，**手の約束は破られる**
    （ライセンス文書が2週間ずれていたのと同じ）ので，ここで固定する．
    """
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    versions = set(re.findall(r"version (\d+\.\d+\.\d+)", readme))
    versions |= set(re.findall(r"^`(\d+\.\d+\.\d+)`", readme, re.M))

    assert versions, "READMEに版の表記が見つからない"
    assert versions == {__version__}, (
        f"READMEの版が __version__（{__version__}）と違う: {sorted(versions)}"
    )


def test_notice_names_the_copyright_holder():
    """著作権者は `NOTICE` に書くこと（Apache 2.0 の作法）．

    `LICENSE` は Apache の原文のままにしてある．末尾の付録にある
    `Copyright [yyyy] [name of copyright owner]` は「自分の作品にこの License を
    適用する方法」の雛形で，埋める場所ではない．著作権者の正本は `NOTICE` 側．
    """
    notice = (REPO_ROOT / "NOTICE").read_text(encoding="utf-8")

    assert "Copyright 2026 田中晴康" in notice
    assert "Apache License" in notice


def test_about_shows_the_version_from_the_package():
    """バージョンの正本は `app/__init__.py`．画面に直書きしていないことを確かめる．"""
    assert __version__ in client.get("/about").text


@pytest.mark.parametrize(
    "library, license_name",
    [
        ("qrcodejs", "MIT"),
        ("html5-qrcode", "Apache-2.0"),
        ("bcrypt", "Apache-2.0"),
        ("SQLAlchemy", "MIT"),
    ],
)
def test_about_lists_third_party_licenses(library, license_name):
    """同梱していなくても，使っているものは示す（将来の配布時に義務が生じる）．"""
    body = client.get("/about").text

    assert library in body
    assert license_name in body


def test_every_page_links_to_about():
    """全ページのフッターから辿れること．ログイン画面にも出す．"""
    for path in ("/login", "/about"):
        assert 'href="/about"' in client.get(path).text


def test_pages_show_the_qr_trademark():
    """「QRコード」の名称を使う画面ごとに登録商標文を出すこと．

    デンソーウェーブは，名称を使う**画面・印刷物ごと**に登録商標文を掲載する
    よう求めている（コードの生成・読み取り自体は無料で手続きも要らない）．
    全ページ共通のフッター（`base.html`）に入れてあるので，代表して2つ見る．
    """
    for path in ("/login", "/about"):
        assert TRADEMARK in client.get(path).text


def test_the_projector_screen_carries_the_trademark_itself():
    """投影画面は，フッターに頼らず自分で登録商標文を持つこと．

    この画面だけ `projector-page` でフッターをCSSで隠している（教室の後方から
    見せるため）．フッターだけに頼ると**この画面が掲載漏れになる**．
    描画には教員のセッションが要るので，テンプレートを直接確かめる．
    """
    projector = (REPO_ROOT / "app" / "templates" / "teacher_qr.html").read_text(
        encoding="utf-8"
    )

    assert TRADEMARK in projector


def test_about_does_not_leak_a_logout_button():
    """未ログインで開いたとき，ログアウトボタンを出さない（CSRFトークンが無い）．"""
    assert "data-logout" not in client.get("/about").text
