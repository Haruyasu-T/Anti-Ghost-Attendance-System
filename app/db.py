"""DBの接続とセッションの受け渡し．

暫定的に担当Aが作った．FastAPIの依存関数（`app/auth.py`）がDBセッションを
必要とするため．担当Bが `models.py` を仕上げる際に，こちらに寄せたい形が
あれば引き取ってもらって構わない．

方針：
- Engineは1つだけ作って使い回す（`lru_cache`）
- `get_db` は1リクエスト1トランザクション．正常終了でコミット，例外でロールバック
- **失敗を記録してから例外を投げる経路では，このセッションに監査ログを書かない**．
  ロールバックで一緒に消えるため．`security.write_audit_log_now` を使うこと
"""

from __future__ import annotations

from functools import lru_cache

from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings


@lru_cache(maxsize=1)
def get_engine():
    from app import models

    return models.create_db_engine(get_settings().database_url)


@lru_cache(maxsize=1)
def get_session_factory() -> sessionmaker:
    return sessionmaker(bind=get_engine(), class_=Session, expire_on_commit=False)


def get_db():
    """FastAPIの依存関数．1リクエスト1トランザクション."""
    session_factory = get_session_factory()
    with session_factory() as db:
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
