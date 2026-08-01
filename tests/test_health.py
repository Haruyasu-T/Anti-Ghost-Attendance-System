"""アプリが起動し，ヘルスチェックが応答することを確認する．

フェーズ3のテストが揃うまでの土台となる最小のテスト．
これが通ることで「依存が requirements.txt だけで揃う」「アプリが import できる」
ことがCI上で確認できる．
"""

from fastapi.testclient import TestClient

from app.main import app


def test_health_returns_ok():
    client = TestClient(app)
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
