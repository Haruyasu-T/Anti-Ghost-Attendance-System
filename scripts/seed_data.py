"""動作確認用の初期データを投入する（B-2）.

    python -m scripts.init_db      # 先にテーブルを作る
    python -m scripts.seed_data

パスワードはこのファイルに書かない．環境変数 SEED_PASSWORD があればそれを使い，
無ければ毎回ランダムに生成して標準出力に1度だけ表示する．

固定値を書くと，それがそのままリポジトリに残り，デプロイ先にも同じ
パスワードのアカウントが出来上がる．「開発用の初期値」がそのまま本番に
残るのは典型的な事故なので，最初から書けない形にしておく（decisions.md D-1
で TOKEN_SECRET に既定値を置かなかったのと同じ理由）．

学籍番号・氏名はすべて架空の値．実在の学生の情報は入れない．
"""

import os
import secrets
import sys

from sqlalchemy.orm import Session

from app import models, security
from app.db import get_engine

# 教員2名にしているのは「他の教員の授業は見えない」ことを試せるようにするため．
# 1名だけだと，認可が壊れていても気付けない．
TEACHERS = [
    ("T0001", "情報 太郎", "情報セキュリティ"),
    ("T0002", "工学 花子", "ネットワーク基礎"),
]

# S0005 はどの授業にも履修登録しない．未履修者が出席登録を試みたときに
# 拒否されることを確認するために残しておく（test-report.md の攻撃テスト用）．
STUDENTS = [
    ("S0001", "学生 一郎"),
    ("S0002", "学生 二郎"),
    ("S0003", "学生 三郎"),
    ("S0004", "学生 四郎"),
    ("S0005", "学生 五郎"),
]
UNENROLLED = {"S0005"}


def seed(db: Session, password: str) -> None:
    """教員2名・学生5名・授業2つ・履修関係を作る."""
    password_hash = security.hash_password(password)

    teachers = {}
    for login_id, display_name, course_name in TEACHERS:
        teacher = models.User(
            login_id=login_id,
            role="teacher",
            display_name=display_name,
            password_hash=password_hash,
        )
        db.add(teacher)
        db.flush()
        course = models.Course(name=course_name, teacher_id=teacher.id)
        db.add(course)
        db.flush()
        teachers[login_id] = course

    first_course = teachers["T0001"]
    for login_id, display_name in STUDENTS:
        student = models.User(
            login_id=login_id,
            role="student",
            display_name=display_name,
            password_hash=password_hash,
        )
        db.add(student)
        db.flush()
        if login_id not in UNENROLLED:
            db.add(models.Enrollment(course_id=first_course.id, user_id=student.id))

    db.commit()


def main() -> int:
    engine = get_engine()

    with Session(engine) as db:
        # login_id は unique なので、二重投入は IntegrityError になる．
        # 例外で落とすより、何が起きたかを説明して止める．
        if db.query(models.User).count() > 0:
            print(
                "既にユーザーが登録されています。投入を中止しました。\n"
                "作り直す場合はDBファイルを削除してから "
                "python -m scripts.init_db をやり直してください。",
                file=sys.stderr,
            )
            return 1

        password = os.environ.get("SEED_PASSWORD") or secrets.token_urlsafe(12)
        seed(db, password)

    print("初期データを投入しました。")
    print(f"  教員   {', '.join(t[0] for t in TEACHERS)}")
    print(f"  学生   {', '.join(s[0] for s in STUDENTS)}"
          f"（{', '.join(sorted(UNENROLLED))} は未履修）")
    print(f"  パスワード（全員共通・この表示限り）  {password}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
