"""テスト共通の設定．

各テストが .env や CI の環境変数に依存しないよう，設定を明示的に固定する．
テストが実行環境によって結果を変えると，何を検証したのか分からなくなるため．
"""

import pytest


@pytest.fixture(autouse=True)
def test_settings(monkeypatch):
    """全テストで使う設定値を固定する（テスト用のダミー値）."""
    monkeypatch.setenv("TOKEN_SECRET", "test-secret-not-a-real-key")
    monkeypatch.setenv("CAMPUS_IP_RANGES", "192.168.0.0/16,10.0.0.0/8")
    monkeypatch.setenv("QR_ROTATE_SECONDS", "5")
    monkeypatch.setenv("TOKEN_ACCEPT_PREVIOUS_WINDOWS", "1")
    monkeypatch.setenv("PRESENT_BEFORE_MINUTES", "5")
    monkeypatch.setenv("PRESENT_AFTER_MINUTES", "5")
    monkeypatch.setenv("LATE_UNTIL_MINUTES", "20")
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "0")

    from app import config

    # 設定はキャッシュされるため，テストごとに作り直す
    config.get_settings.cache_clear()
    yield
    config.get_settings.cache_clear()
