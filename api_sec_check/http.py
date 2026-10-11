"""리다이렉트를 따라가지 않는 짧은 HTTP 조회."""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.cookiejar import CookieJar

from api_sec_check import __version__

USER_AGENT = f"api-sec-check/{__version__}"
BODY_LIMIT = 65536
TIMEOUT = 15


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

    def http_error_301(self, req, fp, code, msg, headers):
        return fp

    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, list[str]]
    body: bytes
    location: str = ""

    def header(self, name: str) -> str:
        values = self.headers.get(name.lower(), [])
        return values[0] if values else ""


@dataclass
class Client:
    timeout: int = TIMEOUT
    jar: CookieJar | None = None
    _opener: urllib.request.OpenerDirector = field(init=False)

    def __post_init__(self) -> None:
        handlers: list[urllib.request.BaseHandler] = [_NoRedirect()]
        if self.jar is not None:
            handlers.append(urllib.request.HTTPCookieProcessor(self.jar))
        self._opener = urllib.request.build_opener(*handlers)

    def request(
        self,
        method: str,
        url: str,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        merged = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if headers:
            merged.update(headers)
        req = urllib.request.Request(url, data=data, headers=merged, method=method)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return _from_fp(resp)
        except urllib.error.HTTPError as exc:
            body = exc.read(BODY_LIMIT)
            return _pack(exc.code, exc.headers, body)


def _from_fp(resp: object) -> HttpResponse:
    body = resp.read(BODY_LIMIT)  # type: ignore[attr-defined]
    status = getattr(resp, "status", None)
    if status is None:
        status = resp.getcode()  # type: ignore[attr-defined]
    return _pack(int(status), resp.headers, body)  # type: ignore[attr-defined]


def _pack(status: int, headers: object, body: bytes) -> HttpResponse:
    grouped: dict[str, list[str]] = {}
    items = headers.items() if hasattr(headers, "items") else []
    for key, value in items:
        grouped.setdefault(str(key).lower(), []).append(str(value))
    location = ""
    if grouped.get("location"):
        location = grouped["location"][0]
    return HttpResponse(status=status, headers=grouped, body=body, location=location)
