# SPDX-FileCopyrightText: 2026 田中晴康
# SPDX-License-Identifier: Apache-2.0

"""タイミング攻撃への対策が実際に効いているかを測る．

`security.py` には応答時間の差から情報が漏れないようにした箇所がある．
コードを読めば「そう書いてある」ことは分かるが，**実際に差が出ていないか**は
測らないと分からない．これはそれを確認するためのスクリプト．

CIには入れない．共有ランナー上の時間計測は他の処理の影響を受けて不安定で，
ランダムに落ちるテストは無いより悪いため．手元で実行して結果を
docs/test-report.md に記録する．

使い方:
    python scripts/measure_timing.py
    python scripts/measure_timing.py --samples 200
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import security  # noqa: E402


def measure(func, samples: int) -> list[float]:
    """func を samples 回呼んで，1回あたりの所要時間（ミリ秒）を返す."""
    timings = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        func()
        timings.append((time.perf_counter_ns() - start) / 1_000_000)
    return timings


def compare(label_a: str, func_a, label_b: str, func_b, samples: int):
    """2つの処理を交互に測る.

    交互に測るのは，CPUの状態やGCの影響が片方だけに乗るのを避けるため．
    まとめて片方ずつ測ると，測定順の違いが差として現れてしまう．
    """
    # ウォームアップ（初回はimportやキャッシュの影響が乗る）
    for _ in range(5):
        func_a()
        func_b()

    a_times, b_times = [], []
    for _ in range(samples):
        a_times.extend(measure(func_a, 1))
        b_times.extend(measure(func_b, 1))

    a_med = statistics.median(a_times)
    b_med = statistics.median(b_times)
    diff = abs(a_med - b_med)
    # 「差」が「ばらつき」に埋もれているかを見る．
    # ばらつきより差が小さければ，その差は観測できない＝攻撃に使えない．
    spread = max(statistics.pstdev(a_times), statistics.pstdev(b_times))

    print(f"  {label_a:<34} 中央値 {a_med:8.3f} ms  （ばらつき ±{statistics.pstdev(a_times):.3f}）")
    print(f"  {label_b:<34} 中央値 {b_med:8.3f} ms  （ばらつき ±{statistics.pstdev(b_times):.3f}）")
    print(f"  差: {diff:.3f} ms")

    if spread == 0:
        verdict = "判定不能（測定精度が足りない）"
    elif diff < spread:
        verdict = "OK — 差はばらつきに埋もれており，観測できない"
    elif diff < spread * 3:
        verdict = "△ — 差はばらつきと同程度．試行を増やして再確認したい"
    else:
        verdict = "!! 差が観測できる．対策が効いていない可能性がある"
    print(f"  判定: {verdict}")
    print()
    return {"a": a_med, "b": b_med, "diff": diff, "spread": spread, "verdict": verdict}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=100,
                        help="各パターンの試行回数（既定100）")
    args = parser.parse_args()

    print("=" * 68)
    print("タイミング攻撃への対策の実測")
    print(f"試行回数: 各 {args.samples} 回（交互に測定）")
    print("=" * 68)
    print()

    # ------------------------------------------------------------------
    print("[1] パスワード照合：アカウントの存在が応答時間から分かるか")
    print("    存在しないIDへのログイン試行でも，ダミーハッシュに対して照合を")
    print("    実行している．早期リターンすると『即座に失敗＝そのIDは無い』と")
    print("    分かってしまうため．")
    print()

    real_hash = security.hash_password("correct-horse-battery-staple")

    compare(
        "実在アカウント（パスワード誤り）",
        lambda: security.verify_password("wrong-password", real_hash),
        "存在しないアカウント",
        lambda: security.verify_password("wrong-password", None),
        args.samples,
    )

    # ------------------------------------------------------------------
    print("[2] トークン検証：不一致の位置が応答時間から分かるか")
    print("    compare_digest を使い，一致してもループを抜けない実装にしている．")
    print()
    print("    ※ この項目は Python レベルでは判定できない．compare_digest が")
    print("      守っているのはナノ秒〜数十ナノ秒の差だが，Python の関数呼び出し")
    print("      自体のばらつきがそれより桁違いに大きいため，測定に埋もれる．")
    print("      ここで『差が出ない』ことは対策の証明にはならない．保証は")
    print("      アルゴリズム（定数時間比較）側から来ている．参考値として記録する．")
    print()

    salt = security.new_token_salt()
    valid = security.generate_token(1, salt)
    wrong_first = ("0" if valid[0] != "0" else "1") + valid[1:]
    wrong_last = valid[:-1] + ("0" if valid[-1] != "0" else "1")

    compare(
        "先頭1文字が違うトークン",
        lambda: security.verify_token(1, salt, wrong_first),
        "末尾1文字が違うトークン",
        lambda: security.verify_token(1, salt, wrong_last),
        args.samples,
    )

    print("=" * 68)
    print("注意：この結果は測定した環境に依存する．結論を書くときは，")
    print("      実行した端末・Pythonのバージョン・試行回数も一緒に残すこと．")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
