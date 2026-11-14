# SPDX-FileCopyrightText: 2026 田中晴康
# SPDX-License-Identifier: Apache-2.0

"""読み取り画面（/scan）のテスト.

QRを読むと `/scan?s=...&t=...` に直接着地する．ログインが切れていたときに
何が返るかは授業中に学生が見るものなので，形式まで含めて固定しておく．
"""

import re
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models, security
from app.db import get_db
from app.main import app

REPO_ROOT = Path(__file__).resolve().parents[1]


def _test_db(tmp_path) -> Session:
    engine = models.create_db_engine(f"sqlite:///{tmp_path / 'scan.db'}")
    models.Base.metadata.create_all(engine)
    return Session(engine)


def _client(db) -> TestClient:
    app.dependency_overrides[get_db] = lambda: db
    # Cookieに Secure を付けているため https でないとログインが保持されない
    return TestClient(app, base_url="https://testserver")


def test_unauthenticated_scan_returns_html_guidance_not_json(tmp_path):
    """未ログインで開いたら、JSONではなく日本語の案内画面を返すこと.

    401のJSON（{"detail": "ログインが必要です"}）がそのまま出ると、
    学生には何が起きたか伝わらない。
    """
    db = _test_db(tmp_path)
    try:
        response = _client(db).get("/scan?s=1&t=deadbeefdeadbeef")
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 401
    assert response.headers["content-type"].startswith("text/html")
    assert "もう一度QRを読み取ってください" in response.text
    assert 'href="/login"' in response.text


def test_scan_guidance_extends_the_shared_layout(tmp_path):
    """案内画面が共通レイアウトを継承していること.

    main.py の中にHTMLを直書きすると、共通ヘッダーもスキップリンクも
    付かず、CSSのパスも url_for を通らない。テンプレート側に置いたことを
    ここで固定しておく。
    """
    db = _test_db(tmp_path)
    try:
        response = _client(db).get("/scan")
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert "本文へ移動" in response.text          # スキップリンク
    assert 'class="brand"' in response.text       # 共通ヘッダー
    assert 'id="live-region"' in response.text    # 読み上げ用の領域


def _student_client(db, tmp_path) -> TestClient:
    db.add(models.User(
        login_id="S0001",
        role="student",
        display_name="学生01",
        password_hash=security.hash_password("student-password"),
    ))
    db.commit()
    client = _client(db)
    client.post("/auth/login", json={"login_id": "S0001", "password": "student-password"})
    return client


def test_scan_page_ships_the_zoom_control_hidden(tmp_path):
    """ズームの操作列を持ち，既定では隠れていること.

    後方の席からだとQRが小さいという声が実地テストで出たので足した機能．
    対応しているかはカメラ次第なので，**起動して能力を確かめるまでは出さない**．
    非対応の端末で操作できる見た目だけ出すと，動かないものを触らせることになる．
    """
    db = _test_db(tmp_path)
    try:
        response = _student_client(db, tmp_path).get("/scan")
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 200
    assert 'id="zoom-row"' in response.text
    assert 'id="zoom"' in response.text
    # hidden が外れていると、非対応の端末でも出てしまう
    assert 'class="zoom-row" hidden' in response.text


def test_zoom_row_is_really_hidden_by_css(tmp_path):
    """`[hidden]` を CSS で打ち消していないこと.

    `.zoom-row { display:flex }` は `[hidden]` の `display:none`（UA由来）に
    **勝ってしまう**ので、明示的に打ち消す必要がある。これが無いと
    HTMLに hidden が付いていても画面には出る。`.btn[hidden]` と同じ事情。
    """
    css = (REPO_ROOT / "app" / "static" / "css" / "style.css").read_text(encoding="utf-8")

    assert ".zoom-row[hidden]" in css, "hidden を打ち消す指定が無い"

    # 整形で `display: none` と空白が入るので、空白を潰してから見る
    block = css.split(".zoom-row[hidden]")[1].split("}")[0]
    assert "display:none" in re.sub(r"\s+", "", block)


def test_teacher_cannot_open_the_scan_page(tmp_path):
    """教員アカウントは読み取り画面を開けないこと.

    未ログインとは別物の異常系なので、案内画面ではなく403を返す。
    """
    db = _test_db(tmp_path)
    db.add(models.User(
        login_id="T0001",
        role="teacher",
        display_name="教員",
        password_hash=security.hash_password("teacher-password"),
    ))
    db.commit()

    try:
        client = _client(db)
        login = client.post(
            "/auth/login",
            json={"login_id": "T0001", "password": "teacher-password"},
        )
        response = client.get("/scan")
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert login.status_code == 200
    assert response.status_code == 403
