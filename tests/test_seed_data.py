"""初期データ投入（B-2）のテスト.

投入した中身が「動作確認に使える形」になっているかを確認する．
特に、認可と未履修の拒否を試すための材料が揃っていることを見る．
"""

from sqlalchemy.orm import Session

from app import models, security
from scripts.seed_data import UNENROLLED, seed


def _seeded(tmp_path) -> Session:
    engine = models.create_db_engine(f"sqlite:///{tmp_path / 'seed.db'}")
    models.Base.metadata.create_all(engine)
    db = Session(engine)
    seed(db, "test-password")
    return db


def test_seeds_teachers_students_and_courses(tmp_path):
    db = _seeded(tmp_path)

    assert db.query(models.User).filter_by(role="teacher").count() == 2
    assert db.query(models.User).filter_by(role="student").count() == 5
    assert db.query(models.Course).count() == 2

    db.close()


def test_each_course_belongs_to_a_different_teacher(tmp_path):
    """教員ごとに別の授業があること.

    「他の教員の授業は見えない」を試すには、比較対象が要る．
    """
    db = _seeded(tmp_path)

    owners = {course.teacher_id for course in db.query(models.Course).all()}

    assert len(owners) == 2

    db.close()


def test_one_student_is_left_unenrolled(tmp_path):
    """未履修の学生が1人残っていること.

    未履修者の出席登録が拒否されることを実機で試すために必要．
    全員を履修させてしまうと、このパスを踏めない．
    """
    db = _seeded(tmp_path)

    enrolled_ids = {
        user.login_id
        for user in db.query(models.User)
        .join(models.Enrollment, models.Enrollment.user_id == models.User.id)
        .all()
    }

    assert UNENROLLED
    assert not (UNENROLLED & enrolled_ids)

    db.close()


def test_passwords_are_hashed_not_stored_as_plaintext(tmp_path):
    db = _seeded(tmp_path)

    for user in db.query(models.User).all():
        assert user.password_hash != "test-password"
        assert security.verify_password("test-password", user.password_hash) is True

    db.close()
