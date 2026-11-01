"""HTTPレスポンスのセキュリティヘッダー（A-10）．

`security.py` はHTTPから切り離す方針（security-interface.md）なので，
`Request` / `Response` を触るこの処理は `app/auth.py` と同じく別モジュールに置く．

**エンドポイントごとではなくミドルウェアで付ける．** `CsrfMiddleware` と同じ理由で，
「1箇所の書き忘れがそのまま穴になる」形を避ける．静的ファイルの応答にも付く．

## CSPが成立する理由

テンプレートに**インラインの `<script>` / `<style>` / `onclick` が1つも無い**ので，
`'unsafe-inline'` なしのCSPがそのまま通る．
**インラインスクリプトを足すとCSPが壊れる．** 新しいJSは必ず
`app/static/js/` のファイルにして `static_url()` で読み込むこと．

## 外部から読んでいるもの

QRの生成と読み取りの2つだけをCDNから読んでいる（どちらもSRI付き）．

- `cdnjs.cloudflare.com` … qrcodejs（教員画面のQR生成）
- `unpkg.com` … html5-qrcode（学生画面のQR読み取り）

`img-src` に `data:` を許しているのは，qrcodejs が環境によって
`canvas.toDataURL()` の結果を `<img>` に入れるため．
`media-src` の `blob:` と `worker-src` は html5-qrcode の内部実装のための保険．

## カメラの権限

`Permissions-Policy` で**カメラだけ自分のオリジンに許可**し，他は閉じる．
`camera=()` にすると読み取り画面が動かなくなるので注意．
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.config import get_settings

# 外部スクリプトの配信元．増やすときはSRIも必ず付けること．
_SCRIPT_SOURCES = ("'self'", "https://cdnjs.cloudflare.com", "https://unpkg.com")

_CSP_DIRECTIVES = (
    ("default-src", ("'self'",)),
    # <base> によるURL書き換えを封じる
    ("base-uri", ("'none'",)),
    ("object-src", ("'none'",)),
    # クリックジャッキング対策。X-Frame-Options の後継
    ("frame-ancestors", ("'none'",)),
    # フォームの送信先を自分のオリジンに限定する
    ("form-action", ("'self'",)),
    ("script-src", _SCRIPT_SOURCES),
    ("style-src", ("'self'",)),
    ("img-src", ("'self'", "data:")),
    ("font-src", ("'self'",)),
    ("connect-src", ("'self'",)),
    ("media-src", ("'self'", "blob:")),
    ("worker-src", ("'self'", "blob:")),
)

CSP = "; ".join(f"{name} {' '.join(values)}" for name, values in _CSP_DIRECTIVES)

# カメラ以外は閉じる。読み取り画面が使うので camera だけ 'self' に許す。
PERMISSIONS_POLICY = ", ".join((
    "camera=(self)",
    "microphone=()",
    "geolocation=()",
    "payment=()",
    "usb=()",
    "accelerometer=()",
    "gyroscope=()",
    "magnetometer=()",
))

HSTS = "max-age=31536000; includeSubDomains"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """全ての応答にセキュリティヘッダーを付ける.

    使い方（main.py）:

        app.add_middleware(SecurityHeadersMiddleware)
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        headers = response.headers

        csp_header = (
            "Content-Security-Policy-Report-Only"
            if get_settings().csp_report_only
            else "Content-Security-Policy"
        )
        headers[csp_header] = CSP

        # MIMEタイプの推測を止める。JSONをHTMLとして実行されるのを防ぐ
        headers["X-Content-Type-Options"] = "nosniff"
        # frame-ancestors と重複するが、CSPを解さない古い環境向けに残す
        headers["X-Frame-Options"] = "DENY"
        # 外部にURL（セッションIDなどは載せていないが、授業IDは載る）を渡さない
        headers["Referrer-Policy"] = "same-origin"
        headers["Permissions-Policy"] = PERMISSIONS_POLICY

        # HSTSはHTTPSでのみ意味がある。localhost のHTTP開発に付けると
        # ブラウザがそのホストをHTTPSに固定してしまい、開発が止まる。
        if request.url.scheme == "https":
            headers["Strict-Transport-Security"] = HSTS

        return response
