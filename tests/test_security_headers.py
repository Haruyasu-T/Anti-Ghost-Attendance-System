# SPDX-FileCopyrightText: 2026 田中晴康
# SPDX-License-Identifier: Apache-2.0

"""セキュリティヘッダーのテスト（app/security_headers.py）．

ヘッダーは「付いていないこと」に気付きにくい．ミドルウェアを外したり
ディレクティブを1つ削ったりしても画面は普通に動くので，テストで固定する．
"""
import pytest
from fastapi.testclient import TestClient

from app import config
from app.main import app
from app.security_headers import CSP

client = TestClient(app)
https_client = TestClient(app, base_url="https://testserver")


@pytest.mark.parametrize(
    "header, expected",
    [
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "same-origin"),
    ],
)
def test_fixed_headers_are_present(header, expected):
    assert client.get("/login").headers[header] == expected


def test_csp_is_enforced_by_default():
    """既定は Report-Only ではなく強制．緩い側を既定にしない．"""
    headers = client.get("/login").headers

    assert "Content-Security-Policy" in headers
    assert "Content-Security-Policy-Report-Only" not in headers


@pytest.mark.parametrize(
    "directive",
    [
        "default-src 'self'",
        "base-uri 'none'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "style-src 'self'",
    ],
)
def test_csp_locks_down_the_dangerous_directives(directive):
    assert directive in client.get("/login").headers["Content-Security-Policy"]


def test_csp_forbids_inline_scripts():
    """テンプレートにインラインJSが無いので 'unsafe-inline' は要らない．

    ここが通らなくなったら，インラインスクリプトを足した誰かが
    CSPを緩めたということ．**緩めるのではなく外部ファイルにすること**．
    """
    csp = client.get("/login").headers["Content-Security-Policy"]

    assert "'unsafe-inline'" not in csp
    assert "'unsafe-eval'" not in csp


@pytest.mark.parametrize(
    "origin",
    ["https://cdnjs.cloudflare.com", "https://unpkg.com"],
)
def test_csp_allows_the_two_qr_libraries(origin):
    """QRの生成と読み取りはCDNから読む（SRI付き）．ここを閉じると画面が壊れる．"""
    csp = client.get("/login").headers["Content-Security-Policy"]
    script_src = next(d for d in csp.split("; ") if d.startswith("script-src"))

    assert origin in script_src


def test_permissions_policy_allows_the_camera_only():
    """カメラを閉じるとQRの読み取り画面が動かなくなる．他は閉じる．"""
    policy = client.get("/login").headers["Permissions-Policy"]

    assert "camera=(self)" in policy
    assert "microphone=()" in policy
    assert "geolocation=()" in policy


def test_hsts_only_over_https():
    """HTTPのlocalhostに付けると、ブラウザがHTTPSに固定して開発が止まる．"""
    assert "Strict-Transport-Security" not in client.get("/login").headers
    assert "max-age=" in https_client.get("/login").headers["Strict-Transport-Security"]


def test_headers_are_on_static_files_too():
    """ミドルウェアなので静的ファイルの応答にも付く．"""
    headers = client.get("/static/css/style.css").headers

    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in headers


def test_report_only_can_be_switched_on(monkeypatch):
    """実地テスト中に読み取りが壊れたときの逃げ道が効くこと．"""
    monkeypatch.setenv("CSP_REPORT_ONLY", "true")
    config.get_settings.cache_clear()
    try:
        headers = client.get("/login").headers

        assert headers["Content-Security-Policy-Report-Only"] == CSP
        assert "Content-Security-Policy" not in headers
    finally:
        config.get_settings.cache_clear()


def test_invalid_report_only_value_stops_startup():
    """設定ミスは使う瞬間ではなく読み込み時に弾く（config.py の方針）．"""
    import os

    os.environ["CSP_REPORT_ONLY"] = "maybe"
    config.get_settings.cache_clear()
    try:
        with pytest.raises(config.ConfigError):
            config.get_settings()
    finally:
        del os.environ["CSP_REPORT_ONLY"]
        config.get_settings.cache_clear()
