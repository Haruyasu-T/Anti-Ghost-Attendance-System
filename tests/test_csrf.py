"""CSRF対策のテスト．

トークンの導出（security.py）と、ミドルウェアによる強制（auth.py）の両方を見る。
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import auth, security

SESSION_A = "session-id-for-user-a"
SESSION_B = "session-id-for-user-b"


# ============================================ トークンの導出


def test_token_is_stable_for_the_same_session():
    """同じセッションなら毎回同じトークンになること（保存せず再計算するため）."""
    assert security.csrf_token_for_session(SESSION_A) == \
        security.csrf_token_for_session(SESSION_A)


def test_token_differs_between_sessions():
    """セッションごとに違う値になること.

    同じなら、攻撃者が自分のトークンを被害者のリクエストに使い回せてしまう。
    """
    assert security.csrf_token_for_session(SESSION_A) != \
        security.csrf_token_for_session(SESSION_B)


def test_token_does_not_leak_the_session_id():
    token = security.csrf_token_for_session(SESSION_A)

    assert SESSION_A not in token
    assert len(token) == security.CSRF_TOKEN_LENGTH


def test_token_does_not_leak_the_secret():
    from app import config

    token = security.csrf_token_for_session(SESSION_A)

    assert config.get_settings().token_secret not in token


@pytest.mark.parametrize("session_id", ["", None])
def test_no_token_without_session(session_id):
    assert security.csrf_token_for_session(session_id) == ""


def test_verify_accepts_the_matching_token():
    token = security.csrf_token_for_session(SESSION_A)

    assert security.verify_csrf_token(SESSION_A, token) is True


def test_verify_rejects_another_sessions_token():
    """他人のセッションのトークンを使い回せないこと."""
    token_b = security.csrf_token_for_session(SESSION_B)

    assert security.verify_csrf_token(SESSION_A, token_b) is False


@pytest.mark.parametrize("provided", ["", None, "x" * 32])
def test_verify_rejects_invalid_tokens(provided):
    assert security.verify_csrf_token(SESSION_A, provided) is False


# ============================================ ミドルウェアによる強制


@pytest.fixture
def client():
    app = FastAPI()
    app.add_middleware(auth.CsrfMiddleware)

    @app.get("/read")
    def read():
        return {"ok": True}

    @app.post("/write")
    def write():
        return {"ok": True}

    @app.post("/auth/login")
    def login():
        return {"ok": True}

    return TestClient(app)


def test_get_needs_no_token(client):
    """読み取りだけのリクエストは対象外（状態を変えないため）."""
    assert client.get("/read").status_code == 200


def test_post_with_valid_token_passes(client):
    client.cookies.set(auth.SESSION_COOKIE, SESSION_A)
    token = security.csrf_token_for_session(SESSION_A)

    response = client.post("/write", headers={security.CSRF_HEADER: token})

    assert response.status_code == 200


def test_post_without_token_is_rejected(client):
    """ログイン中にトークン無しでPOSTすると拒否されること.

    攻撃者のページから送られるリクエストがこれに当たる。Cookieは自動で
    付くが、トークンは同一生成元ポリシーのせいで読み取れないため付けられない。
    """
    client.cookies.set(auth.SESSION_COOKIE, SESSION_A)

    response = client.post("/write")

    assert response.status_code == 403


def test_post_with_another_sessions_token_is_rejected(client):
    client.cookies.set(auth.SESSION_COOKIE, SESSION_A)
    token_b = security.csrf_token_for_session(SESSION_B)

    response = client.post("/write", headers={security.CSRF_HEADER: token_b})

    assert response.status_code == 403


def test_post_with_garbage_token_is_rejected(client):
    client.cookies.set(auth.SESSION_COOKIE, SESSION_A)

    response = client.post("/write", headers={security.CSRF_HEADER: "deadbeef"})

    assert response.status_code == 403


def test_login_is_exempt(client):
    """ログインは対象外（まだセッションが無いので検証できない）."""
    assert client.post("/auth/login").status_code == 200


def test_unauthenticated_post_falls_through(client):
    """未ログインのPOSTはミドルウェアで止めず、認可側（401）に任せること.

    ここで403を返すと、本来401を返すべき場面が403になって紛らわしい。
    セッションが無いならCSRFで守るべき状態も無い。
    """
    response = client.post("/write")

    assert response.status_code == 200  # このテスト用アプリには認可が無いので通る
