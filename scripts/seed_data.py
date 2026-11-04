# SPDX-FileCopyrightText: 2026 田中晴康
# SPDX-License-Identifier: Apache-2.0

"""動作確認用の初期データを投入する（B-2）.

    python -m scripts.init_db      # 先にテーブルを作る
    python -m scripts.seed_data

管理者1名・教員1名・学生15名・授業1つを作る．人数は環境変数で変えられる
（`SEED_STUDENT_COUNT` など）．

**パスワードはアカウントごとに別々に生成する．** 実機テストでは学生役に
アカウントを配るので，共通にすると学生役が教員や管理者にもログインできて
しまう．そうなると「学生は教員用APIを叩けない」という確認が成立しない．

生成した値はこのファイルにもDBにも平文で残らない．実行時に1度だけ表示する
ので，その場で控えること．忘れた場合は作り直しになる（DBにはハッシュしか
無いので元の値は取り出せない）．

学籍番号・氏名はすべて架空の値．実在の人の情報は入れない．
"""

import os
import secrets
import sys

from sqlalchemy.orm import Session

from app import models, security
from app.db import get_engine

# 手で入力してもらうので、見間違えやすい文字（0 O o 1 l I）を外す．
_PASSWORD_ALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_PASSWORD_LENGTH = 12

ADMIN_COUNT = int(os.environ.get("SEED_ADMIN_COUNT", "1"))
TEACHER_COUNT = int(os.environ.get("SEED_TEACHER_COUNT", "1"))
STUDENT_COUNT = int(os.environ.get("SEED_STUDENT_COUNT", "15"))
COURSE_NAME = os.environ.get("SEED_COURSE_NAME", "情報セキュリティ")


def new_password() -> str:
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(_PASSWORD_LENGTH))


def seed(db: Session) -> dict:
    """初期データを投入し、{ログインID: パスワード} を返す.

    返り値は表示のためだけに使う．保存しないこと．
    """
    credentials: dict = {}

    def add_user(login_id: str, role: str, display_name: str) -> models.User:
        password = new_password()
        user = models.User(
            login_id=login_id,
            role=role,
            display_name=display_name,
            password_hash=security.hash_password(password),
        )
        db.add(user)
        db.flush()
        credentials[login_id] = password
        return user

    for i in range(1, ADMIN_COUNT + 1):
        add_user(f"A{i:04d}", "admin", f"管理者{i:02d}")

    # 授業は教員ごとに1つ作る．担当教員が違う授業を用意しておくと、
    # 「他の教員の授業は見えない」ことを試せる（教員が1名なら試せない）。
    courses = []
    for i in range(1, TEACHER_COUNT + 1):
        teacher = add_user(f"T{i:04d}", "teacher", f"教員{i:02d}")
        name = COURSE_NAME if i == 1 else f"{COURSE_NAME}（{i}）"
        course = models.Course(name=name, teacher_id=teacher.id)
        db.add(course)
        db.flush()
        courses.append(course)

    # 学生は全員、最初の授業に履修登録する．未履修者の拒否を試したくなったら、
    # 管理画面の「履修者」から外せばよい（アカウントを作り直す必要はない）。
    for i in range(1, STUDENT_COUNT + 1):
        student = add_user(f"S{i:04d}", "student", f"学生{i:02d}")
        if courses:
            db.add(models.Enrollment(course_id=courses[0].id, user_id=student.id))

    db.commit()
    return credentials


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

        credentials = seed(db)

    print("初期データを投入しました。")
    print(f"  授業：{COURSE_NAME}（学生は全員この授業に履修登録済み）")
    print()
    print("  パスワードはこの表示限りです。控えてから閉じてください。")
    print("  DBにはハッシュしか保存していないので、後から取り出せません。")
    print()
    print("  ログインID  パスワード")
    print("  ----------  ------------")
    for login_id in sorted(credentials):
        print(f"  {login_id:<10}  {credentials[login_id]}")
    print()
    print("  学生役に配るのは S で始まるものだけにしてください。")
    print("  教員（T）と管理者（A）を渡すと、学生役が出席を操作できてしまいます。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
