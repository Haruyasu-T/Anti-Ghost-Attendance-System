"""テスト共通の設定．

各テストが .env や CI の環境変数に依存しないよう，設定を明示的に固定する．
テストが実行環境によって結果を変えると，何を検証したのか分からなくなるため．

DBも同じ理由で毎回使い捨てのファイルに向ける．
以前はここで `DATABASE_URL` を固定していなかったため，`get_db` を差し替え
忘れたテストが**開発機の `attendance.db` をそのまま読み書きしていた**．
実際，受付時間の設定テーブルを足したときに「開発機のDBには新しいテーブルが
無い」という理由でテストが落ちて発覚した．テストが手元のDBの状態に左右される
のも，テストが手元のDBを壊せるのも，どちらも避ける．

スキーマはセッション中に1回だけ作り，各テストにはそれをコピーして渡す．
テストごとに `create_all` を呼ぶと，CHECK制約とインデックスを毎回作り直すことに
なり，全体で1分以上遅くなった（実測 +0.31秒/件）．ファイルのコピーなら数ミリ秒．
"""

import shutil

import pytest


@pytest.fixture(scope="session")
def _schema_template(tmp_path_factory):
    """空のDBを1つだけ作っておく．各テストはこれをコピーして使う."""
    from app import models

    path = tmp_path_factory.mktemp("schema") / "template.db"
    engine = models.create_db_engine(f"sqlite:///{path}")
    models.Base.metadata.create_all(engine)
    engine.dispose()
    return path


@pytest.fixture(autouse=True)
def test_settings(monkeypatch, tmp_path, _schema_template):
    """全テストで使う設定値とDBを固定する（テスト用のダミー値）."""
    monkeypatch.setenv("TOKEN_SECRET", "test-secret-not-a-real-key")
    monkeypatch.setenv("CAMPUS_IP_RANGES", "192.168.0.0/16,10.0.0.0/8")
    monkeypatch.setenv("QR_ROTATE_SECONDS", "5")
    monkeypatch.setenv("TOKEN_ACCEPT_PREVIOUS_WINDOWS", "1")
    monkeypatch.setenv("PRESENT_BEFORE_MINUTES", "5")
    monkeypatch.setenv("PRESENT_AFTER_MINUTES", "5")
    monkeypatch.setenv("LATE_UNTIL_MINUTES", "20")
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "0")

    # `get_db` を差し替えないテストでも、空のDBとして成立するようにしておく
    db_path = tmp_path / "test.db"
    shutil.copyfile(_schema_template, db_path)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    from app import config, db as db_module

    # 設定もエンジンもキャッシュされるため，テストごとに作り直す
    def reset():
        config.get_settings.cache_clear()
        db_module.get_engine.cache_clear()
        db_module.get_session_factory.cache_clear()

    reset()
    yield
    reset()
