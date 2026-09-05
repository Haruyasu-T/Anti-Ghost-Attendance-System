"""管理者機能（D-17）のテスト.

管理者は授業と履修の割り当てだけを行い，出席記録には触れない．
その分離が実際に効いているかを見る．UIで選択肢を絞っても，
URLを直接叩かれれば意味がないので，すべてAPIに対して確認する．
"""

import datetime as dt

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models, security
from app.db import get_db
from app.main import app

PASSWORD = "admin-tests-password"


def _fixture(tmp_path):
    engine = models.create_db_engine(f"sqlite:///{tmp_path / 'admin.db'}")
    models.Base.metadata.create_all(engine)
    db = Session(engine)

    def user(login_id, role):
        return models.User(
            login_id=login_id, role=role, display_name=f"{login_id}の氏名",
            password_hash=security.hash_password(PASSWORD),
        )

    admin = user("A0001", "admin")
    t1, t2 = user("T0001", "teacher"), user("T0002", "teacher")
    s1, s2 = user("S0001", "student"), user("S0002", "student")
    db.add_all([admin, t1, t2, s1, s2])
    db.flush()

    course = models.Course(name="情報セキュリティ", teacher_id=t1.id)
    db.add(course)
    db.flush()
    db.add(models.Enrollment(course_id=course.id, user_id=s1.id))

    ids = {
        "admin": admin.id, "t1": t1.id, "t2": t2.id,
        "s1": s1.id, "s2": s2.id, "course": course.id,
    }
    db.commit()
    return db, ids


def _client(db, login_id) -> TestClient:
    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app, base_url="https://testserver")
    client.post("/auth/login", json={"login_id": login_id, "password": PASSWORD})
    return client


def _csrf(client):
    return {"X-CSRF-Token": security.csrf_token_for_session(client.cookies.get("session"))}


# ============================================== 権限の境界（ここが一番大事）


def test_teacher_and_student_cannot_reach_the_admin_console(tmp_path):
    """管理者以外は管理APIに触れないこと."""
    db, ids = _fixture(tmp_path)
    paths = ["/admin", "/admin/users", "/admin/courses",
             f"/admin/courses/{ids['course']}/enrollments"]
    try:
        results = {
            login_id: [_client(db, login_id).get(p).status_code for p in paths]
            for login_id in ("T0001", "S0001")
        }
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert results["T0001"] == [403] * len(paths)
    assert results["S0001"] == [403] * len(paths)


def test_admin_cannot_read_attendance_records(tmp_path):
    """管理者は出席記録を読めないこと.

    名簿を作る権限と記録を扱う権限を分けている。両方を持つアカウントが1つ
    乗っ取られると「自分を担当教員にして」「自分で出席を入れる」が
    1人で完結してしまう。
    """
    db, ids = _fixture(tmp_path)
    now = security.to_iso(dt.datetime.now(dt.timezone.utc))
    sess = models.AttendanceSession(
        course_id=ids["course"], scheduled_start_at=now, started_at=now,
        status="open", required_scan_count=1,
        token_salt=security.new_token_salt(), created_by=ids["t1"],
    )
    db.add(sess)
    db.commit()

    try:
        client = _client(db, "A0001")
        codes = [
            client.get(f"/attendance-sessions/{sess.id}/attendances").status_code,
            client.get(f"/attendance-sessions/{sess.id}/token").status_code,
            client.get(f"/attendance-sessions/{sess.id}/alerts").status_code,
            client.get("/courses").status_code,
            # 本人の記録しか返らないので管理者が叩いても中身は空だが、
            # 「触れない」ことを結果ではなく認可で示す
            client.get("/me/attendances").status_code,
        ]
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert codes == [403] * 5


def test_admin_cannot_assign_themselves_as_teacher(tmp_path):
    """管理者アカウントを担当教員にできないこと.

    これを許すと、管理者が自分の授業を作り、そのままQRトークンを取りに
    行ける経路ができる。ロールで弾いて、その経路自体を無くす。
    """
    db, ids = _fixture(tmp_path)
    try:
        client = _client(db, "A0001")
        created = client.post(
            "/admin/courses",
            json={"name": "自作の授業", "teacher_id": ids["admin"]},
            headers=_csrf(client),
        )
        updated = client.put(
            f"/admin/courses/{ids['course']}",
            json={"name": "情報セキュリティ", "teacher_id": ids["admin"]},
            headers=_csrf(client),
        )
        courses = client.get("/admin/courses").json()
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert created.status_code == 400
    assert updated.status_code == 400
    # 拒否されたので授業は増えず、担当も変わっていない
    assert [c["teacher_id"] for c in courses] == [ids["t1"]]


def test_student_cannot_be_assigned_as_teacher(tmp_path):
    db, ids = _fixture(tmp_path)
    try:
        client = _client(db, "A0001")
        response = client.post(
            "/admin/courses",
            json={"name": "学生が担当", "teacher_id": ids["s1"]},
            headers=_csrf(client),
        )
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 400


def test_teacher_cannot_be_enrolled_as_a_student(tmp_path):
    """教員を履修者に混ぜられないこと.

    混ざると出席一覧に教員が現れて名簿が壊れる。
    """
    db, ids = _fixture(tmp_path)
    try:
        client = _client(db, "A0001")
        response = client.put(
            f"/admin/courses/{ids['course']}/enrollments",
            json={"user_ids": [ids["s1"], ids["t2"]]},
            headers=_csrf(client),
        )
        enrolled = client.get(f"/admin/courses/{ids['course']}/enrollments").json()
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 400
    # 一部だけ通さない。S0001 も追加されていないこと
    assert [u["id"] for u in enrolled] == [ids["s1"]]


def test_admin_write_requires_csrf_token(tmp_path):
    db, ids = _fixture(tmp_path)
    try:
        client = _client(db, "A0001")
        response = client.post(
            "/admin/courses", json={"name": "CSRF無し", "teacher_id": ids["t1"]}
        )
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 403


# ====================================================== 通常の操作


def test_admin_can_create_and_edit_a_course(tmp_path):
    db, ids = _fixture(tmp_path)
    try:
        client = _client(db, "A0001")
        created = client.post(
            "/admin/courses",
            json={"name": "  ネットワーク基礎  ", "teacher_id": ids["t1"]},
            headers=_csrf(client),
        ).json()
        updated = client.put(
            f"/admin/courses/{created['id']}",
            json={"name": "ネットワーク応用", "teacher_id": ids["t2"]},
            headers=_csrf(client),
        ).json()
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert created["name"] == "ネットワーク基礎"      # 前後の空白は落とす
    assert created["teacher_id"] == ids["t1"]
    assert updated["name"] == "ネットワーク応用"
    assert updated["teacher_id"] == ids["t2"]
    assert updated["teacher_login_id"] == "T0002"


def test_blank_course_name_is_rejected(tmp_path):
    db, ids = _fixture(tmp_path)
    try:
        client = _client(db, "A0001")
        response = client.post(
            "/admin/courses", json={"name": "   ", "teacher_id": ids["t1"]},
            headers=_csrf(client),
        )
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 400


def test_enrollments_are_replaced_by_the_given_set(tmp_path):
    """送った集合でそのまま置き換わること（差分ではない）."""
    db, ids = _fixture(tmp_path)
    try:
        client = _client(db, "A0001")
        replaced = client.put(
            f"/admin/courses/{ids['course']}/enrollments",
            json={"user_ids": [ids["s2"]]},
            headers=_csrf(client),
        ).json()
        emptied = client.put(
            f"/admin/courses/{ids['course']}/enrollments",
            json={"user_ids": []},
            headers=_csrf(client),
        ).json()
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert [u["id"] for u in replaced] == [ids["s2"]]   # S0001 は外れ、S0002 が入る
    assert emptied == []


def test_removing_an_enrollment_keeps_the_attendance_record(tmp_path):
    """履修から外しても過去の出席記録は消さないこと.

    記録を消す権限を管理者に持たせない。名簿から外れるだけ。
    """
    db, ids = _fixture(tmp_path)
    now = security.to_iso(dt.datetime.now(dt.timezone.utc))
    sess = models.AttendanceSession(
        course_id=ids["course"], scheduled_start_at=now, started_at=now,
        status="open", required_scan_count=1,
        token_salt=security.new_token_salt(), created_by=ids["t1"],
    )
    db.add(sess)
    db.flush()
    db.add(models.Attendance(
        attendance_session_id=sess.id, user_id=ids["s1"],
        status="present", record_source="auto", first_recorded_at=now,
    ))
    db.commit()

    try:
        client = _client(db, "A0001")
        client.put(
            f"/admin/courses/{ids['course']}/enrollments",
            json={"user_ids": []}, headers=_csrf(client),
        )
        remaining = db.query(models.Attendance).filter(
            models.Attendance.user_id == ids["s1"]).count()
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert remaining == 1


def test_course_list_reports_counts_for_the_screen(tmp_path):
    """履修者数と実施回数を返すこと.

    実施回数は「担当教員を変えると過去の記録も移る」警告を出すのに使う。
    """
    db, ids = _fixture(tmp_path)
    now = security.to_iso(dt.datetime.now(dt.timezone.utc))
    db.add(models.AttendanceSession(
        course_id=ids["course"], scheduled_start_at=now, started_at=now,
        status="closed", closed_at=now, required_scan_count=1,
        token_salt=security.new_token_salt(), created_by=ids["t1"],
    ))
    db.commit()
    try:
        rows = _client(db, "A0001").get("/admin/courses").json()
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert rows[0]["enrolled_count"] == 1
    assert rows[0]["session_count"] == 1


def test_user_list_never_exposes_password_hashes(tmp_path):
    """割り当て候補の一覧にパスワードハッシュを含めないこと."""
    db, _ = _fixture(tmp_path)
    try:
        response = _client(db, "A0001").get("/admin/users")
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert "password_hash" not in response.text
    assert "$2b$" not in response.text
    # 割り当ての候補にならない管理者は一覧に出さない
    assert {u["role"] for u in response.json()} == {"teacher", "student"}


def test_admin_actions_are_recorded_in_the_audit_log(tmp_path):
    """管理操作が監査ログに残ること.

    名簿を動かせるアカウントなので、誰が何を変えたか追えないと困る。
    """
    db, ids = _fixture(tmp_path)
    try:
        client = _client(db, "A0001")
        created = client.post(
            "/admin/courses", json={"name": "監査確認", "teacher_id": ids["t1"]},
            headers=_csrf(client),
        ).json()
        client.put(
            f"/admin/courses/{created['id']}",
            json={"name": "監査確認", "teacher_id": ids["t2"]},
            headers=_csrf(client),
        )
        client.put(
            f"/admin/courses/{created['id']}/enrollments",
            json={"user_ids": [ids["s2"]]}, headers=_csrf(client),
        )
        logs = {
            row.action: row
            for row in db.query(models.AuditLog).filter(
                models.AuditLog.action.in_(
                    ["course_create", "course_update", "enrollment_update"])
            ).all()
        }
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert set(logs) == {"course_create", "course_update", "enrollment_update"}
    assert all(row.actor_user_id == ids["admin"] for row in logs.values())
    # 担当教員の変更は，変更前後が分かる形で残す
    assert logs["course_update"].detail == f"teacher_id={ids['t1']}->{ids['t2']}"


def test_missing_course_is_not_found(tmp_path):
    db, ids = _fixture(tmp_path)
    try:
        client = _client(db, "A0001")
        codes = [
            client.put("/admin/courses/9999",
                       json={"name": "無い授業", "teacher_id": ids["t1"]},
                       headers=_csrf(client)).status_code,
            client.get("/admin/courses/9999/enrollments").status_code,
            client.put("/admin/courses/9999/enrollments",
                       json={"user_ids": []}, headers=_csrf(client)).status_code,
        ]
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert codes == [404, 404, 404]


def test_admin_is_routed_to_the_admin_console(tmp_path):
    db, _ = _fixture(tmp_path)
    try:
        response = _client(db, "A0001").get("/", follow_redirects=False)
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.headers["location"] == "/admin"
