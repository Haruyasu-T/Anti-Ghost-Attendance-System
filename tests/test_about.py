"""`/about`（ライセンス表示）のテスト．

ライセンス表示は**利用者が見られる場所に置く**必要がある．認証の後ろに隠すと
表示したことにならないので，「ログインなしで見られる」ことを固定する．
"""
import pytest
from fastapi.testclient import TestClient

from app import __version__
from app.main import app

client = TestClient(app)


def test_about_is_public():
    """ログインしていなくても見られる（リダイレクトもしない）．"""
    response = client.get("/about")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_about_shows_the_license():
    assert "Apache License" in client.get("/about").text


def test_about_credits_every_author():
    """製作者が1人でも落ちていないこと．

    著作権者の表記（`NOTICE`）はまだ未確定なので，ここでは**製作者名の表示**
    だけを固定する．ライセンス側の表記を決めたらそちらのテストを足す．
    """
    body = client.get("/about").text

    for author in ("田中晴康", "藤本遥希", "吉木郁矢"):
        assert author in body


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


def test_about_does_not_leak_a_logout_button():
    """未ログインで開いたとき，ログアウトボタンを出さない（CSRFトークンが無い）．"""
    assert "data-logout" not in client.get("/about").text
