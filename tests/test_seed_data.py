"""初期データ投入（B-2）のテスト.

投入した中身が「実機テストに使える形」になっているかを確認する．
特に、アカウントごとにパスワードが違うことを見る．共通にしてしまうと、
学生役に配った時点で教員にも管理者にもログインできてしまい、
「学生は教員用の操作ができない」という確認が成立しなくなる．
"""

import pytest
from sqlalchemy.orm import Session

from app import models, security
from scripts import seed_data
from scripts.seed_data import seed


@pytest.fixture(autouse=True)
def small_counts(monkeypatch):
    """テストでは人数を減らす.

    パスワードのハッシュ化は意図的に重い処理なので、既定の12人分を
    毎回作ると1分以上かかる。確認したいのは人数ではなく「1人ずつ別の
    パスワードになっているか」なので、少人数で十分。
    """
    monkeypatch.setattr(seed_data, "ADMIN_COUNT", 1)
    monkeypatch.setattr(seed_data, "TEACHER_COUNT", 1)
    monkeypatch.setattr(seed_data, "STUDENT_COUNT", 3)


def _seeded(tmp_path):
    engine = models.create_db_engine(f"sqlite:///{tmp_path / 'seed.db'}")
    models.Base.metadata.create_all(engine)
    db = Session(engine)
    credentials = seed(db)
    return db, credentials


def test_seeds_the_expected_number_of_accounts(tmp_path):
    db, credentials = _seeded(tmp_path)

    assert db.query(models.User).filter_by(role="admin").count() == seed_data.ADMIN_COUNT
    assert db.query(models.User).filter_by(role="teacher").count() == seed_data.TEACHER_COUNT
    assert db.query(models.User).filter_by(role="student").count() == seed_data.STUDENT_COUNT
    assert len(credentials) == db.query(models.User).count()

    db.close()


def test_every_account_has_its_own_password(tmp_path):
    """パスワードがアカウントごとに違うこと.

    ここが共通だと、学生役に配った時点で教員・管理者にも入れてしまう。
    攻撃テスト（学生が教員用APIを叩けない）の前提が崩れる。
    """
    db, credentials = _seeded(tmp_path)

    assert len(set(credentials.values())) == len(credentials)

    db.close()


def test_each_password_only_opens_its_own_account(tmp_path):
    """あるアカウントのパスワードが、他のアカウントでは通らないこと."""
    db, credentials = _seeded(tmp_path)
    users = {user.login_id: user for user in db.query(models.User).all()}

    for login_id, password in credentials.items():
        assert security.verify_password(password, users[login_id].password_hash) is True
        for other_id, other in users.items():
            if other_id != login_id:
                assert security.verify_password(password, other.password_hash) is False

    db.close()


def test_passwords_are_not_stored_as_plaintext(tmp_path):
    db, credentials = _seeded(tmp_path)

    for user in db.query(models.User).all():
        assert user.password_hash != credentials[user.login_id]
        assert credentials[user.login_id] not in user.password_hash

    db.close()


def test_students_are_enrolled_so_the_flow_can_be_tested(tmp_path):
    """学生が授業に履修登録されていること.

    未履修だと出席登録が拒否されるので、そのままでは通しの確認ができない。
    未履修の拒否を試したいときは、管理画面から履修者を外す。
    """
    db, _ = _seeded(tmp_path)

    enrolled = (
        db.query(models.Enrollment)
        .filter(models.Enrollment.course_id == db.query(models.Course).first().id)
        .count()
    )

    assert enrolled == seed_data.STUDENT_COUNT

    db.close()
