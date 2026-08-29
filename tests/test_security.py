"""security.py（A-2〜A-5）のテスト．

[docs/phase3-tasks.md](../docs/phase3-tasks.md) の完了条件をそのままテストにしている．
攻撃が防げることを確認する「防御側」のテストと，正当な利用が通ることを確認する
「対照」のテストを両方置く．全部拒否する実装でも通ってしまう状態を避けるため．
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app import config, security

BASE = datetime(2026, 7, 27, 1, 0, 0, tzinfo=timezone.utc)


def at_minutes(minutes: float) -> datetime:
    """授業開始からの経過時間（分）を時刻に変換する."""
    return BASE + timedelta(minutes=minutes)


# =========================================================== A-1. 設定


def test_missing_token_secret_stops_startup(monkeypatch):
    """TOKEN_SECRET が未設定なら起動を止めること.

    開発用の既定値をコードに埋めていたら，このテストは通らない．
    """
    monkeypatch.delenv("TOKEN_SECRET", raising=False)
    config.get_settings.cache_clear()

    with pytest.raises(config.ConfigError):
        config.get_settings()


def test_invalid_campus_ip_range_stops_startup(monkeypatch):
    """不正なCIDRは、使う瞬間ではなく起動時に弾くこと."""
    monkeypatch.setenv("CAMPUS_IP_RANGES", "not-an-ip-range")
    config.get_settings.cache_clear()

    with pytest.raises(config.ConfigError):
        config.get_settings()


# =================================================== A-2. パスワード


def test_password_roundtrip():
    hashed = security.hash_password("correct horse battery staple")

    assert security.verify_password("correct horse battery staple", hashed) is True
    assert security.verify_password("wrong password", hashed) is False


def test_password_hash_is_salted():
    """同じ平文でも毎回異なるハッシュになること（ソルトが効いている）."""
    first = security.hash_password("same-password")
    second = security.hash_password("same-password")

    assert first != second
    assert security.verify_password("same-password", first) is True
    assert security.verify_password("same-password", second) is True


def test_password_hash_is_not_the_plaintext():
    hashed = security.hash_password("plaintext-should-not-appear")

    assert "plaintext-should-not-appear" not in hashed


def test_long_passwords_are_fully_used():
    """72バイトを超えるパスワードでも、超過部分が無視されないこと.

    bcryptは72バイトで切り捨てるため、素で使うと「先頭72バイトが同じ別のパスワード」
    でも認証が通ってしまう。SHA-256で畳んでから渡すことでこれを防いでいる。
    """
    base = "a" * 72
    hashed = security.hash_password(base + "TAIL-ONE")

    assert security.verify_password(base + "TAIL-ONE", hashed) is True
    assert security.verify_password(base + "TAIL-TWO", hashed) is False
    assert security.verify_password(base, hashed) is False


def test_verify_password_handles_unknown_user():
    """存在しないユーザー（hashがNone）でもFalseを返し、例外にしないこと.

    実装側ではダミーハッシュに対して照合を実行し，応答時間を揃えている．
    """
    assert security.verify_password("anything", None) is False


# ===================================================== A-3. 動的トークン


def test_token_is_accepted_immediately():
    salt = security.new_token_salt()
    token = security.generate_token(1, salt, at=BASE)

    assert security.verify_token(1, salt, token, at=BASE) is True


def test_previous_window_token_is_accepted():
    """1世代前のトークンは受け付ける（読み取り中の切り替わりを救済する）."""
    salt = security.new_token_salt()
    token = security.generate_token(1, salt, at=BASE)

    later = BASE + timedelta(seconds=5)
    assert security.verify_token(1, salt, token, at=later) is True


def test_two_windows_old_token_is_rejected():
    """2世代前のトークンは受け付けないこと（転送の猶予を広げない）."""
    salt = security.new_token_salt()
    token = security.generate_token(1, salt, at=BASE)

    much_later = BASE + timedelta(seconds=15)
    assert security.verify_token(1, salt, token, at=much_later) is False


def test_token_from_another_session_is_rejected():
    """別の授業のQRを流用できないこと（session_idをHMACに含めている）."""
    salt = security.new_token_salt()
    token_for_session_1 = security.generate_token(1, salt, at=BASE)

    assert security.verify_token(2, salt, token_for_session_1, at=BASE) is False


def test_token_with_another_salt_is_rejected():
    """塩を作り直すと、出回っていたトークンが失効すること."""
    old_salt = security.new_token_salt()
    token = security.generate_token(1, old_salt, at=BASE)

    new_salt = security.new_token_salt()
    assert new_salt != old_salt
    assert security.verify_token(1, new_salt, token, at=BASE) is False


def test_tampered_token_is_rejected():
    """1文字書き換えたトークンが通らないこと."""
    salt = security.new_token_salt()
    token = security.generate_token(1, salt, at=BASE)

    flipped = "0" if token[0] != "0" else "1"
    tampered = flipped + token[1:]

    assert security.verify_token(1, salt, tampered, at=BASE) is False


@pytest.mark.parametrize("bad_token", ["", None, "x", "z" * 16])
def test_malformed_tokens_are_rejected(bad_token):
    """空・None・長さ違い・16進でない文字列でも例外にせず拒否すること."""
    salt = security.new_token_salt()

    assert security.verify_token(1, salt, bad_token, at=BASE) is False


def test_classify_token_valid():
    salt = security.new_token_salt()
    token = security.generate_token(1, salt, at=BASE)

    assert security.classify_token(1, salt, token, at=BASE) is security.TokenCheck.VALID


def test_classify_token_expired():
    """少し前の世代のトークンは EXPIRED として区別できること.

    監査ログで「読み取りが遅れただけ」と「偽造の試み」を見分けるため。
    ただし学生に返すメッセージは同じにする（decisions.md D-16）。
    """
    salt = security.new_token_salt()
    token = security.generate_token(1, salt, at=BASE)

    # 受け付ける範囲より後、遡る範囲の中
    later = BASE + timedelta(seconds=30)

    assert security.classify_token(1, salt, token, at=later) is security.TokenCheck.EXPIRED


def test_classify_token_too_old_is_invalid():
    """遡る範囲より前のトークンは INVALID になること.

    無制限に遡るとHMACの計算回数が増えるので、上限を設けている。
    """
    salt = security.new_token_salt()
    token = security.generate_token(1, salt, at=BASE)

    much_later = BASE + timedelta(minutes=5)

    assert security.classify_token(1, salt, token, at=much_later) is security.TokenCheck.INVALID


def test_classify_token_forged_is_invalid():
    """偽造したトークンは EXPIRED ではなく INVALID になること.

    ここが EXPIRED になると、攻撃者に「形式は正しかった」と伝わってしまう。
    """
    salt = security.new_token_salt()

    assert security.classify_token(1, salt, "deadbeefdeadbeef", at=BASE) is security.TokenCheck.INVALID


def test_classify_token_from_another_session_is_invalid():
    """別セッションのトークンは EXPIRED ではなく INVALID になること."""
    salt = security.new_token_salt()
    token = security.generate_token(1, salt, at=BASE)

    assert security.classify_token(2, salt, token, at=BASE) is security.TokenCheck.INVALID


def test_verify_token_matches_classify_token():
    """verify_token は classify_token の VALID と一致すること（包みが壊れていない）."""
    salt = security.new_token_salt()
    token = security.generate_token(1, salt, at=BASE)
    expired_at = BASE + timedelta(seconds=30)

    assert security.verify_token(1, salt, token, at=BASE) is True
    assert security.verify_token(1, salt, token, at=expired_at) is False


def test_token_does_not_reveal_the_secret():
    """トークンから秘密鍵が読み取れないこと（HMACの出力であることの確認）."""
    salt = security.new_token_salt()
    token = security.generate_token(1, salt, at=BASE)

    assert config.get_settings().token_secret not in token
    assert len(token) == security.TOKEN_LENGTH


# ======================================================== A-4. IP判定


@pytest.mark.parametrize("ip", ["192.168.1.10", "192.168.255.255", "10.0.0.1"])
def test_campus_ip_is_accepted(ip):
    assert security.is_campus_ip(ip) is True


@pytest.mark.parametrize("ip", ["203.0.113.5", "172.16.0.1", "8.8.8.8"])
def test_off_campus_ip_is_rejected(ip):
    assert security.is_campus_ip(ip) is False


@pytest.mark.parametrize("value", ["", "not-an-ip", "999.999.999.999", None])
def test_unparsable_ip_is_rejected(value):
    """解析できない値は拒否すること（判定不能なら通さない）."""
    assert security.is_campus_ip(value) is False


def _fake_request(peer_ip: str, forwarded_for: str | None = None):
    """get_client_ip に渡す最小限のリクエスト風オブジェクト."""
    headers = {}
    if forwarded_for is not None:
        headers["x-forwarded-for"] = forwarded_for
    return SimpleNamespace(client=SimpleNamespace(host=peer_ip), headers=headers)


def test_client_ip_uses_peer_address_when_no_proxy():
    request = _fake_request("192.168.1.10")

    assert security.get_client_ip(request) == "192.168.1.10"


def test_spoofed_forwarded_header_is_ignored_without_proxy():
    """TRUSTED_PROXY_COUNT=0 のとき、偽の X-Forwarded-For で判定が変わらないこと.

    ここが破られると、学外の攻撃者がヘッダを付けるだけでIP検証を突破できる．
    """
    request = _fake_request("203.0.113.5", forwarded_for="192.168.1.10")

    assert security.get_client_ip(request) == "203.0.113.5"
    assert security.is_campus_ip(security.get_client_ip(request)) is False


def test_client_ip_uses_last_entry_behind_one_proxy(monkeypatch):
    """プロキシ1台の背後では、X-Forwarded-For の右端を使うこと.

    攻撃者が偽の値を送っても、信頼できるプロキシが本物を末尾に追記するため、
    偽の値は左側に押しやられて使われない．
    """
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "1")
    config.get_settings.cache_clear()

    # 左が攻撃者の自己申告、右がプロキシの記録した実際の接続元
    request = _fake_request("10.1.1.1", forwarded_for="192.168.1.10, 203.0.113.5")

    assert security.get_client_ip(request) == "203.0.113.5"
    assert security.is_campus_ip(security.get_client_ip(request)) is False


def test_client_ip_is_empty_when_proxy_chain_is_shorter_than_expected(monkeypatch):
    """想定より短いプロキシ経路なら空を返すこと（推測で通さない）."""
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "2")
    config.get_settings.cache_clear()

    request = _fake_request("10.1.1.1", forwarded_for="192.168.1.10")

    assert security.get_client_ip(request) == ""
    assert security.is_campus_ip("") is False


# ================================================== A-5. 受付時間帯


@pytest.mark.parametrize(
    "minutes, expected",
    [
        (-6, None),                                  # 早すぎる
        (-5, security.AttendanceStatus.PRESENT),     # 境界ちょうど → 受付開始
        (0, security.AttendanceStatus.PRESENT),
        (5, security.AttendanceStatus.PRESENT),      # 境界ちょうど → 遅刻にしない
        (6, security.AttendanceStatus.LATE),
        (20, security.AttendanceStatus.LATE),        # 境界ちょうど → 受付終了にしない
        (21, None),                                  # 受付終了
    ],
)
def test_attendance_classification_boundaries(minutes, expected):
    assert security.classify_attendance(BASE, at_minutes(minutes)) is expected


def test_classify_attendance_rejects_naive_datetime():
    """タイムゾーンなしの datetime を黙って受け入れないこと.

    naive と aware を混ぜると判定がずれる．曖昧なまま進むより落とす方が安全．
    """
    naive_now = datetime(2026, 7, 27, 1, 0, 0)

    with pytest.raises(ValueError):
        security.classify_attendance(BASE, naive_now)
