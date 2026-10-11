"""静的ファイルのキャッシュ対策（cache busting）．

scan.js のエラーメッセージを直して配信したのに，ブラウザが古い版を
キャッシュから出し続けて不具合が残ったままになったことがある．
Cache-Control も Expires も無いと，ブラウザは Last-Modified から
勝手に「しばらく新しいはず」と判断して，問い合わせずに使うことがある．

対策は2つ．
1. URL に中身のハッシュを付ける．中身が変われば URL が変わるので，
   古い版がキャッシュに残っていても使われない．
2. ハッシュ付きで取りに来たものだけ長期キャッシュを許可する．
   ハッシュ無しの URL は毎回確認させる（no-cache）．
   こうしておけば，どこかで付け忘れても古いまま固定されることはない．
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

STATIC_DIR = Path(__file__).resolve().parent / "static"

_VERSION_LENGTH = 8
# path -> (更新時刻, サイズ, ハッシュ)．中身を読み直す回数を減らすため．
_cache: dict[str, tuple[int, int, str]] = {}


def asset_version(path: str) -> str:
    """static 配下のファイルの中身から短いハッシュを作る．

    ファイルが無いときや static の外を指しているときは空文字を返す．
    画面が落ちるより，クエリが付かないだけで動くほうがよい．
    """
    candidate = (STATIC_DIR / path).resolve()
    try:
        candidate.relative_to(STATIC_DIR)
    except ValueError:
        # ".." などで static の外へ出ようとしたもの
        return ""
    if not candidate.is_file():
        return ""

    stat = candidate.stat()
    cached = _cache.get(path)
    if cached is not None and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
        return cached[2]

    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()[:_VERSION_LENGTH]
    _cache[path] = (stat.st_mtime_ns, stat.st_size, digest)
    return digest


def static_url(path: str) -> str:
    """テンプレートから使う URL．

    url_for('static', ...) ではなく自前で組むのは，
    プロキシ越しでも自分のホスト名を書かない相対パスにしたいため．
    """
    version = asset_version(path)
    return f"/static/{path}?v={version}" if version else f"/static/{path}"


class VersionedStaticFiles(StaticFiles):
    """ハッシュ付きで来たものだけ長期キャッシュを許可する StaticFiles．"""

    def file_response(
        self,
        full_path: str | os.PathLike[str],
        stat_result: os.stat_result,
        scope: Scope,
        status_code: int = 200,
    ) -> Response:
        response = super().file_response(full_path, stat_result, scope, status_code)
        query = scope.get("query_string", b"")
        if b"v=" in query:
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        else:
            response.headers["Cache-Control"] = "no-cache"
        return response
