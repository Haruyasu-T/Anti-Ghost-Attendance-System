# SPDX-FileCopyrightText: 2026 田中晴康
# SPDX-License-Identifier: Apache-2.0

"""依存のファイル2つが食い違っていないかを確かめる（D-27）.

`requirements.txt`（手元とCI）と `requirements.lock`（サーバー）は別のファイルなので，
**片方だけ上げて片方を忘れる**ことが起きうる．それが起きると「テストした版と
本番の版を一致させる」という目的そのものが崩れるが，動かしても気付けない．
サーバーに入れて初めて違う版が入る．

ここで固定するのは「2つが矛盾していないこと」だけである．
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# 例: `uvicorn[standard]==0.54.0` / `uvloop==0.23.0 ; sys_platform != "win32"`
_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)"
    r"(?:\[[^\]]*\])?"          # extras（[standard] など）は名前から外す
    r"==(?P<version>[^\s;]+)"
    r"(?:\s*;.*)?$"             # 環境マーカーは無視する
)


def _normalize(name: str) -> str:
    """PEP 503 の正規化．`Jinja2` と `jinja2`，`a_b` と `a-b` を同じものとして扱う."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse(path: Path) -> dict[str, str]:
    pinned: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _LINE.match(line)
        assert match is not None, f"{path.name} の行を読めない（`==` で固定されていない）: {raw!r}"
        pinned[_normalize(match.group("name"))] = match.group("version")
    return pinned


def test_both_files_pin_every_line():
    """どちらのファイルも全行が `==` で固定されていること.

    `>=` が1行でも混ざると、その行だけ入れた日によって変わる。
    行を読めない場合は _parse が落ちる。
    """
    direct = _parse(REPO_ROOT / "requirements.txt")
    locked = _parse(REPO_ROOT / "requirements.lock")

    assert direct, "requirements.txt が空"
    assert locked, "requirements.lock が空"


def test_lock_covers_every_direct_dependency():
    """`requirements.txt` に書いたものが，すべてロックにあること."""
    direct = _parse(REPO_ROOT / "requirements.txt")
    locked = _parse(REPO_ROOT / "requirements.lock")

    missing = sorted(set(direct) - set(locked))
    assert not missing, (
        f"requirements.lock に無い: {missing}。"
        "requirements.txt を上げたあと、ロックを作り直していない可能性がある"
    )


def test_versions_agree_between_the_two_files():
    """同じパッケージの版が2つのファイルで一致していること.

    **ここが落ちたら、ロックの作り直し忘れである．**
    直し方は requirements.lock の先頭に書いてある（CIが緑になった実行の
    `Record the installed set` の出力を貼る）。
    """
    direct = _parse(REPO_ROOT / "requirements.txt")
    locked = _parse(REPO_ROOT / "requirements.lock")

    disagreed = {
        name: (direct[name], locked[name])
        for name in sorted(set(direct) & set(locked))
        if direct[name] != locked[name]
    }

    assert not disagreed, (
        "requirements.txt とロックで版が違う（左: txt / 右: lock）: "
        f"{disagreed}"
    )


def _licensed_packages() -> dict[str, str]:
    """THIRD-PARTY-LICENSES.md の表から「パッケージ名 → 版」を読む."""
    text = (REPO_ROOT / "THIRD-PARTY-LICENSES.md").read_text(encoding="utf-8")
    found: dict[str, str] = {}
    for row in re.finditer(
        r"^\|\s*([A-Za-z0-9._-]+)\s*\|\s*([0-9][^\s|]*)\s*\|", text, re.M
    ):
        found[_normalize(row.group(1))] = row.group(2)
    return found


def test_license_document_lists_every_locked_package():
    """ロックにあるものが，ライセンス文書にすべて載っていること.

    載っていないパッケージがあると，**何に依存しているかの一覧として
    成立しない**（この文書の目的そのもの）。
    """
    locked = _parse(REPO_ROOT / "requirements.lock")
    listed = _licensed_packages()

    missing = sorted(set(locked) - set(listed))
    assert not missing, (
        f"THIRD-PARTY-LICENSES.md に無い: {missing}。"
        "依存を足したら、ロックと一緒にこの文書も更新すること"
    )


def test_license_document_versions_match_the_lock():
    """ライセンス文書の版がロックと一致していること.

    **2026-11-01 から 11-15 の間に9個の版がずれていた**（fastapi 0.141.1 と
    書いてあるのに実際は 0.162.2 など）。動かしても気付かないので、ここで見る。
    """
    locked = _parse(REPO_ROOT / "requirements.lock")
    listed = _licensed_packages()

    disagreed = {
        name: (locked[name], listed[name])
        for name in sorted(set(locked) & set(listed))
        if locked[name] != listed[name]
    }

    assert not disagreed, (
        "THIRD-PARTY-LICENSES.md とロックで版が違う（左: lock / 右: 文書）: "
        f"{disagreed}"
    )


def test_uvloop_keeps_its_platform_marker():
    """`uvloop` にマーカーが付いていること.

    uvloop は Windows に無い。ロックはLinux向けだが，手元で誤って入れたときに
    **そこだけで止まる**ので，マーカーで読み飛ばせるようにしてある。

    `pip freeze` はマーカーを出さないので，**CIの出力を貼ると消える**。
    付け直しを忘れやすい一手間なので，ここで固定する（手順は
    requirements.lock の先頭にも書いてある）。
    """
    lock = (REPO_ROOT / "requirements.lock").read_text(encoding="utf-8")

    line = next(
        (l for l in lock.splitlines() if l.strip().startswith("uvloop==")), None
    )
    assert line is not None, "uvloop がロックに無い"
    assert "sys_platform" in line, (
        f"uvloop にマーカーが付いていない: {line!r}。"
        'CIの出力を貼ったあと `; sys_platform != "win32"` を付け直すこと'
    )


def test_lock_includes_the_indirect_dependencies_it_exists_for():
    """ロックが間接依存まで含んでいること（D-27の目的そのもの）.

    直接書いたものと同じ数しか入っていなければ、それは `requirements.txt` の
    写しであって、ロックの役目を果たしていない。名前で確かめるのは
    **starlette**：D-27で手元とCIのずれが見つかった当事者で、FastAPIの土台。
    """
    direct = _parse(REPO_ROOT / "requirements.txt")
    locked = _parse(REPO_ROOT / "requirements.lock")

    assert "starlette" in locked, "間接依存が入っていない（ロックの作り方が違う）"
    assert len(locked) > len(direct), "ロックが requirements.txt と同じ範囲しか持っていない"
