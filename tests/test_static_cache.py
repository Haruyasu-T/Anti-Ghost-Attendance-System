# SPDX-FileCopyrightText: 2026 田中晴康
# SPDX-License-Identifier: Apache-2.0

"""静的ファイルのキャッシュ対策のテスト（app/assets.py）．

scan.js を直したのにブラウザが古い版を使い続けた，という実際の不具合に対する
作り込みなので，「中身が変わったら URL も変わる」ことを中心に確かめる．
"""
import re

import pytest
from fastapi.testclient import TestClient

from app import assets
from app.assets import asset_version, static_url
from app.main import app

client = TestClient(app)

VERSION_RE = re.compile(r"\?v=[0-9a-f]{8}")


def test_static_url_has_a_version():
    url = static_url("js/scan.js")
    assert url.startswith("/static/js/scan.js?v=")
    assert VERSION_RE.search(url)


def test_version_changes_when_the_file_changes(tmp_path, monkeypatch):
    """中身が1バイト変わればハッシュも変わる．これが対策の本体．"""
    monkeypatch.setattr(assets, "STATIC_DIR", tmp_path)
    assets._cache.clear()
    target = tmp_path / "sample.js"

    target.write_text("console.log('a');", encoding="utf-8")
    before = asset_version("sample.js")

    target.write_text("console.log('b');", encoding="utf-8")
    after = asset_version("sample.js")

    assert before and after
    assert before != after


def test_same_content_gives_the_same_version(tmp_path, monkeypatch):
    monkeypatch.setattr(assets, "STATIC_DIR", tmp_path)
    assets._cache.clear()
    (tmp_path / "a.js").write_text("same", encoding="utf-8")
    (tmp_path / "b.js").write_text("same", encoding="utf-8")
    assert asset_version("a.js") == asset_version("b.js")


@pytest.mark.parametrize("path", ["missing.js", "../main.py", "../../README.md"])
def test_unknown_or_outside_paths_fall_back_to_a_plain_url(path):
    """存在しないものと static の外を指すものは、クエリ無しでそのまま返す．

    ここで例外を投げると画面全体が落ちる．付かないだけなら画面は出る．
    """
    assert asset_version(path) == ""
    assert "?v=" not in static_url(path)


def test_rendered_page_puts_a_version_on_css_and_js():
    response = client.get("/login")
    assert response.status_code == 200
    body = response.text
    for path in ("css/style.css", "js/auth.js", "js/common.js"):
        assert f"/static/{path}?v=" in body, path


def test_versioned_request_is_cached_for_a_long_time():
    version = asset_version("js/common.js")
    response = client.get(f"/static/js/common.js?v={version}")
    assert response.status_code == 200
    assert "immutable" in response.headers["cache-control"]


def test_request_without_a_version_is_always_revalidated():
    """付け忘れた URL が古いまま固定されないようにしておく．"""
    response = client.get("/static/js/common.js")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-cache"
