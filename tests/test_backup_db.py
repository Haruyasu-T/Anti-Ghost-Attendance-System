# SPDX-FileCopyrightText: 2026 田中晴康
# SPDX-License-Identifier: Apache-2.0

"""バックアップスクリプトのテスト（scripts/backup_db.py）．

「取れた」だけでは意味がない．**元と同じ中身が入っていること**と，
**壊れていたら気づくこと**を確かめる．
"""
import sqlite3

import pytest
from sqlalchemy.orm import Session

from app import models, security
from app.db import get_engine
from scripts import backup_db


def _seeded_db():
    """利用者・授業・履修・出席を1件ずつ入れたDBを作る."""
    engine = get_engine()
    with Session(engine) as db:
        teacher = models.User(login_id="T0001", role="teacher", display_name="教員",
                              password_hash=security.hash_password("x"))
        student = models.User(login_id="S0001", role="student", display_name="学生",
                              password_hash=security.hash_password("x"))
        db.add_all([teacher, student])
        db.flush()
        course = models.Course(name="情報セキュリティ", teacher_id=teacher.id)
        db.add(course)
        db.flush()
        db.add(models.Enrollment(course_id=course.id, user_id=student.id))
        db.commit()
    return backup_db.source_path()


def test_backup_matches_the_original(tmp_path):
    source = _seeded_db()
    destination = tmp_path / "backup.db"

    counts = backup_db.backup(source, destination)

    assert destination.is_file()
    assert counts["users"] == 2
    assert counts["courses"] == 1
    assert counts["enrollments"] == 1
    # 実際に開いて読めること（「取れたが開けない」を防ぐのが目的）
    with sqlite3.connect(destination) as conn:
        ids = [r[0] for r in conn.execute("SELECT login_id FROM users ORDER BY login_id")]
    assert ids == ["S0001", "T0001"]


def test_backup_refuses_to_overwrite(tmp_path):
    """VACUUM INTO は既存ファイルに書けない．黙って失敗させず理由を出す."""
    source = _seeded_db()
    destination = tmp_path / "backup.db"
    backup_db.backup(source, destination)

    with pytest.raises(SystemExit, match="既にあります"):
        backup_db.backup(source, destination)


def test_a_file_that_is_not_a_database_is_rejected(tmp_path):
    """「取れたが開けない」を検知できること."""
    broken = tmp_path / "broken.db"
    broken.write_bytes(b"this is not a database")

    with pytest.raises(SystemExit, match="開けません"):
        backup_db.verify(broken, {"users": 2})


def test_missing_rows_are_detected(tmp_path):
    """開けても中身が足りなければ落ちること．ここが検証の本体."""
    source = _seeded_db()
    destination = tmp_path / "backup.db"
    counts = backup_db.backup(source, destination)

    # バックアップ側から1件消して、同じ期待値で検証し直す
    with sqlite3.connect(destination) as conn:
        conn.execute("DELETE FROM enrollments")
        conn.commit()

    with pytest.raises(SystemExit, match="件数が一致しません"):
        backup_db.verify(destination, counts)


def test_non_sqlite_is_rejected(monkeypatch):
    """MySQLに移ったときに、このスクリプトで取れたつもりにならないようにする."""
    from app import config

    monkeypatch.setenv("DATABASE_URL", "mysql+pymysql://user@localhost/attendance")
    config.get_settings.cache_clear()
    with pytest.raises(SystemExit, match="SQLite"):
        backup_db.source_path()


def test_file_name_uses_the_display_timezone():
    import datetime as dt

    from app.config import DISPLAY_TIMEZONE

    moment = dt.datetime(2026, 10, 19, 21, 5, 30, tzinfo=DISPLAY_TIMEZONE)
    assert backup_db.default_destination(moment).name == "attendance-20261019-210530.db"
