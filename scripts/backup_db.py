"""DBのバックアップを取り，その場で検証する．

    python -m scripts.backup_db

SQLite は単一ファイルなので `cp` で済みそうに見えるが，**アプリが動いている
最中にコピーすると書き込み途中の状態を掴んで壊れたコピーになることがある**．
`VACUUM INTO` は一貫したスナップショットを取るので，アプリを止めずに実行できる．

取るだけでは足りない．**復元できないバックアップはバックアップではない**ので，
このスクリプトは取った直後に

- `PRAGMA integrity_check`（ファイルとして壊れていないか）
- 全テーブルの行数を元のDBと突き合わせる（中身が揃っているか）

まで行う．どちらかが通らなければ終了コード1で落ちる．

**バックアップの中身は本番と同じ**で，全出席記録とパスワードハッシュが入っている．
アプリは認可で守っているが，**ファイルをコピーした時点でその守りは外れる**．
置き場所を選ぶこと．リポジトリには入れない（`.gitignore` の `*.db` で弾いている）．

復元の手順は docs/deployment-guide.md に書いてある．
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

from app import models
from app.config import DISPLAY_TIMEZONE, get_settings

_SQLITE_PREFIX = "sqlite:///"


def source_path() -> Path:
    """設定からDBファイルの場所を取る．SQLite以外は扱わない."""
    url = get_settings().database_url
    if not url.startswith(_SQLITE_PREFIX):
        raise SystemExit(
            f"SQLite のDBだけを対象にしています（今の設定: {url.split('://')[0]}）。\n"
            "他のDBでは、その製品のバックアップ手段を使ってください。"
        )
    return Path(url[len(_SQLITE_PREFIX):]).resolve()


def default_destination(now: datetime | None = None) -> Path:
    """`backups/attendance-YYYYmmdd-HHMMSS.db`.

    ファイル名は人が見るものなので表示用のタイムゾーン（JST）で付ける．
    DBの中の時刻がUTCなのとは別の話．
    """
    stamp = (now or datetime.now(DISPLAY_TIMEZONE)).strftime("%Y%m%d-%H%M%S")
    return Path("backups") / f"attendance-{stamp}.db"


def _row_counts(path: Path) -> dict[str, int]:
    """全テーブルの行数．テーブル名はモデル定義から取る（数え漏れを防ぐため）."""
    counts: dict[str, int] = {}
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
        for table in models.Base.metadata.sorted_tables:
            try:
                counts[table.name] = conn.execute(
                    f"SELECT COUNT(*) FROM {table.name}").fetchone()[0]
            except sqlite3.OperationalError:
                # まだ作られていないテーブルは数えない（古いDBを想定）
                continue
    return counts


def verify(destination: Path, expected: dict[str, int]) -> dict[str, int]:
    """バックアップが開けて，中身が元と揃っているかを確かめる．

    取る処理とは分けてある．ここが本体なので，単体で試せるようにしておきたい．
    """
    try:
        with sqlite3.connect(f"file:{destination}?mode=ro", uri=True) as conn:
            result = conn.execute("PRAGMA integrity_check").fetchone()[0]
    except sqlite3.DatabaseError as error:
        # ファイルとして壊れていると、そもそもDBとして開けない
        raise SystemExit(f"バックアップを開けません: {error}") from error
    if result != "ok":
        raise SystemExit(f"バックアップが壊れています: {result}")

    actual = _row_counts(destination)
    if actual != expected:
        diff = {k: (expected.get(k), actual.get(k))
                for k in set(expected) | set(actual)
                if expected.get(k) != actual.get(k)}
        raise SystemExit(f"件数が一致しません（元, バックアップ）: {diff}")
    return actual


def backup(source: Path, destination: Path) -> dict[str, int]:
    """バックアップを取って検証する．問題があれば例外を投げる."""
    if not source.is_file():
        raise SystemExit(f"DBが見つかりません: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        # VACUUM INTO は既存ファイルを上書きしない．黙って失敗させず理由を出す．
        raise SystemExit(f"同じ名前のファイルが既にあります: {destination}")

    before = _row_counts(source)
    with sqlite3.connect(source) as conn:
        # VACUUM INTO はパラメータを受け付けないので、文字列を組み立てる。
        # 引用符を二重にしてエスケープする（パスに ' が含まれる場合に備える）。
        escaped = str(destination.resolve()).replace("'", "''")
        conn.execute(f"VACUUM INTO '{escaped}'")

    return verify(destination, before)


def main() -> int:
    parser = argparse.ArgumentParser(description="DBのバックアップを取り、検証する")
    parser.add_argument("--out", type=Path, default=None,
                        help="出力先（省略時は backups/attendance-日時.db）")
    args = parser.parse_args()

    source = source_path()
    destination = args.out or default_destination()
    counts = backup(source, destination)

    size = destination.stat().st_size
    print(f"バックアップを作成しました: {destination}")
    print(f"  元のDB   : {source}")
    print(f"  サイズ   : {size:,} バイト")
    print("  検証     : integrity_check=ok、件数一致")
    print()
    for name, n in sorted(counts.items()):
        print(f"  {name:<22} {n:>6} 件")
    print()
    print("  このファイルには全出席記録とパスワードハッシュが入っています。")
    print("  置き場所に注意し、リポジトリには入れないでください。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
