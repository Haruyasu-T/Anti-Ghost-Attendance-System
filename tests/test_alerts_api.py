# SPDX-FileCopyrightText: 2026 田中晴康
# SPDX-License-Identifier: Apache-2.0

"""アラートAPI（B-8）のテスト.

端末の重複とバーストを教員に見せるエンドポイント．
**検知するだけでブロックしない**（D-11）ので，出席記録そのものは変わらない．
そこも含めて確認する．
"""

import datetime as dt

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models, security
from app.db import get_db
from app.main import app

PASSWORD = "alerts-password"


def _fixture(tmp_path, student_count=3):
    engine = models.create_db_engine(f"sqlite:///{tmp_path / 'alerts.db'}")
    models.Base.metadata.create_all(engine)
    db = Session(engine)

    def user(login_id, role):
        return models.User(
            login_id=login_id, role=role, display_name=f"{login_id}の氏名",
            password_hash=security.hash_password(PASSWORD),
        )

    teacher = user("T0001", "teacher")
    other_teacher = user("T0002", "teacher")
    students = [user(f"S{i + 1:04d}", "student") for i in range(student_count)]
    db.add_all([teacher, other_teacher, *students])
    db.flush()

    course = models.Course(name="情報セキュリティ", teacher_id=teacher.id)
    other_course = models.Course(name="他教員の授業", teacher_id=other_teacher.id)
    db.add_all([course, other_course])
    db.flush()

    now = security.to_iso(dt.datetime.now(dt.timezone.utc))
    sess = models.AttendanceSession(
        course_id=course.id, scheduled_start_at=now, started_at=now,
        status="open", required_scan_count=1,
        token_salt=security.new_token_salt(), created_by=teacher.id,
    )
    other_sess = models.AttendanceSession(
        course_id=other_course.id, scheduled_start_at=now, started_at=now,
        status="open", required_scan_count=1,
        token_salt=security.new_token_salt(), created_by=other_teacher.id,
    )
    db.add_all([sess, other_sess])
    db.flush()

    ids = {
        "session": sess.id,
        "other_session": other_sess.id,
        "students": [s.id for s in students],
    }
    db.commit()
    return db, ids


def _scan(db, session_id, user_id, *, device_id, seconds_offset=0, seq=1):
    at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds_offset)
    db.add(models.AttendanceScan(
        attendance_session_id=session_id, user_id=user_id, scan_seq=seq,
        scanned_at=security.to_iso(at), client_ip="192.168.1.10", device_id=device_id,
    ))
    db.commit()


def _alerts(db, session_id, login_id="T0001"):
    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app, base_url="https://testserver")
    client.post("/auth/login", json={"login_id": login_id, "password": PASSWORD})
    return client.get(f"/attendance-sessions/{session_id}/alerts")


def test_no_alerts_when_everyone_uses_their_own_device(tmp_path):
    """正常な使い方でアラートが出ないこと.

    何にでもアラートを付ける実装でも通ってしまうのを避けるための対照．
    """
    db, ids = _fixture(tmp_path)
    for i, user_id in enumerate(ids["students"]):
        _scan(db, ids["session"], user_id, device_id=f"device-{i}")
    try:
        response = _alerts(db, ids["session"])
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 200
    assert response.json()["rows"] == []


def test_one_device_used_by_two_accounts_is_flagged(tmp_path):
    """1台の端末で2人が登録したら、両方にアラートが付くこと（A-8 アカウント貸与）."""
    db, ids = _fixture(tmp_path)
    first, second = ids["students"][0], ids["students"][1]
    _scan(db, ids["session"], first, device_id="shared-device")
    _scan(db, ids["session"], second, device_id="shared-device")
    try:
        rows = {r["user_id"]: r for r in _alerts(db, ids["session"]).json()["rows"]}
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert set(rows) == {first, second}
    for row in rows.values():
        assert any("同じ端末で複数アカウント" in a for a in row["alerts"])


def test_same_person_scanning_twice_is_not_flagged(tmp_path):
    """1人が2回読んでもアラートにしないこと.

    数えるのは件数ではなく人数。件数で数えると、2回目の読み取りを要求した
    授業で全員にアラートが出てしまう。
    """
    db, ids = _fixture(tmp_path)
    user_id = ids["students"][0]
    _scan(db, ids["session"], user_id, device_id="own-device", seq=1)
    _scan(db, ids["session"], user_id, device_id="own-device", seq=2, seconds_offset=1)
    try:
        response = _alerts(db, ids["session"])
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.json()["rows"] == []


def test_one_person_scanning_many_times_is_not_a_burst(tmp_path):
    """1人が閾値以上の回数を読んでもバーストにしないこと.

    バーストは「1台の端末で何人分を登録したか」であって、読み取り回数ではない。
    件数で数えると、教員が再表示を何度も要求した授業で全員が誤検知になる。
    上の test_same_person_scanning_twice では回数が閾値（3）に届かないため、
    件数で数える実装でも通ってしまう。ここは閾値を超える回数で試す。
    """
    db, ids = _fixture(tmp_path)
    user_id = ids["students"][0]
    for seq in range(1, 5):
        _scan(db, ids["session"], user_id, device_id="own-device",
              seq=seq, seconds_offset=seq)
    try:
        response = _alerts(db, ids["session"])
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.json()["rows"] == []


def test_burst_is_flagged_when_many_people_register_from_one_device(tmp_path):
    """短時間に同じ端末から複数人が登録したらバーストとして出ること."""
    db, ids = _fixture(tmp_path)
    for user_id in ids["students"]:  # 既定の閾値は3人
        _scan(db, ids["session"], user_id, device_id="burst-device")
    try:
        rows = _alerts(db, ids["session"]).json()["rows"]
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert len(rows) == 3
    for row in rows:
        assert any("短時間に同じ端末から複数人" in a for a in row["alerts"])


def test_slow_registrations_are_not_a_burst(tmp_path):
    """窓の外に散らばっていればバーストにしないこと.

    同じ端末を使い回してはいるが、時間が離れていれば「まとめて代返」とは
    言えない。端末重複のアラートは付くが、バーストは付けない。
    """
    db, ids = _fixture(tmp_path)
    for i, user_id in enumerate(ids["students"]):
        _scan(db, ids["session"], user_id, device_id="slow-device", seconds_offset=i * 600)
    try:
        rows = _alerts(db, ids["session"]).json()["rows"]
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert len(rows) == 3
    for row in rows:
        assert any("同じ端末で複数アカウント" in a for a in row["alerts"])
        assert not any("短時間" in a for a in row["alerts"])


def test_raw_device_id_is_never_returned(tmp_path):
    """生の device_id を返さないこと.

    認証情報ではないが、HttpOnlyのCookieで配っている値をわざわざ画面に
    出す理由がない。教員に必要なのは「この2人が同じ端末」と分かること。
    """
    db, ids = _fixture(tmp_path)
    _scan(db, ids["session"], ids["students"][0], device_id="secret-device-value")
    _scan(db, ids["session"], ids["students"][1], device_id="secret-device-value")
    try:
        response = _alerts(db, ids["session"])
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert "secret-device-value" not in response.text
    assert "端末1" in response.text


def test_device_conflict_recorded_at_registration_is_surfaced(tmp_path):
    """登録時に記録した紐付けの衝突が一覧に出ること.

    授業を跨いだ話なので、このセッションのスキャンだけを見ても分からない。
    監査ログが唯一の記録。
    """
    db, ids = _fixture(tmp_path)
    user_id = ids["students"][0]
    _scan(db, ids["session"], user_id, device_id="borrowed-device")
    security.write_audit_log(
        db, action="device_conflict", result="success", actor_user_id=user_id,
        client_ip="192.168.1.10", device_id="borrowed-device",
        target_type="attendance_session", target_id=ids["session"],
    )
    db.commit()
    try:
        rows = {r["user_id"]: r for r in _alerts(db, ids["session"]).json()["rows"]}
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert "別アカウントに紐付いた端末" in rows[user_id]["alerts"]


def test_alerts_do_not_leak_across_sessions(tmp_path):
    """別のセッションのスキャンを混ぜないこと."""
    db, ids = _fixture(tmp_path)
    _scan(db, ids["other_session"], ids["students"][0], device_id="shared-device")
    _scan(db, ids["other_session"], ids["students"][1], device_id="shared-device")
    try:
        response = _alerts(db, ids["session"])
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.json()["rows"] == []


def test_other_teachers_session_is_not_found(tmp_path):
    """他の教員のセッションは403ではなく404にすること."""
    db, ids = _fixture(tmp_path)
    try:
        response = _alerts(db, ids["other_session"], login_id="T0001")
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 404


def test_student_cannot_read_alerts(tmp_path):
    """学生はアラートを読めないこと.

    誰が疑われているかは、当人にも他の学生にも見せない。
    """
    db, ids = _fixture(tmp_path)
    try:
        response = _alerts(db, ids["session"], login_id="S0001")
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 403
