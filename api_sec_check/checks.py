"""검토 보고서의 조치 후 기준으로 응답을 판정함."""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass

FONT_HOSTS = frozenset(
    {"https://fonts.googleapis.com", "https://fonts.gstatic.com"}
)
IMG_REQUIRED = ("'self'", "data:", "blob:", "https://raw.githubusercontent.com")
SCRIPT_KEYWORDS = frozenset(
    {
        "'self'",
        "'none'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "'strict-dynamic'",
        "'report-sample'",
        "'wasm-unsafe-eval'",
    }
)
CSRF_TARGETS = (
    ("/admin/logout", None, ""),
    ("/admin/posts/1/delete", b"", "application/x-www-form-urlencoded"),
    ("/admin/categories/reorder", b'{"items":[]}', "application/json"),
)
CSRF_PATTERN = re.compile(
    r"""name=["']csrf_token["'][^>]*value=["']([^"']+)["']"""
    r"""|value=["']([^"']+)["'][^>]*name=["']csrf_token["']""",
    re.IGNORECASE,
)
LABEL = {"pass": "충족", "warn": "주의", "fail": "미충족", "skip": "건너뜀"}


@dataclass
class Item:
    group: str
    name: str
    status: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {
            "구분": self.group,
            "이름": self.name,
            "판정": LABEL[self.status],
            "내용": self.detail,
        }


def summary(items: list[Item]) -> dict[str, int]:
    counts = {"충족": 0, "주의": 0, "미충족": 0, "건너뜀": 0}
    for item in items:
        counts[LABEL[item.status]] += 1
    return counts


def failed(items: list[Item]) -> bool:
    return any(item.status == "fail" for item in items)


def parse_csp(value: str) -> dict[str, list[str]]:
    parsed: dict[str, list[str]] = {}
    for part in value.split(";"):
        bits = part.strip().split()
        if not bits:
            continue
        parsed[bits[0].lower()] = bits[1:]
    return parsed


def header_items(headers: dict[str, list[str]], scheme: str) -> list[Item]:
    group = "보안 헤더"
    csp_raw = _first(headers, "content-security-policy")
    items = [
        _present(group, "Content-Security-Policy", csp_raw, "정책이 있음"),
    ]
    policy = parse_csp(csp_raw)
    items.append(_script_src(policy))
    items.append(_style_src(policy))
    items.append(_img_src(policy))
    items.append(_font_hosts(policy))
    items.append(_upgrade(policy, scheme))
    items.append(
        _exact(
            group,
            "X-Content-Type-Options",
            _first(headers, "x-content-type-options"),
            "nosniff",
        )
    )
    items.append(
        _exact(
            group,
            "X-Frame-Options",
            _first(headers, "x-frame-options"),
            "DENY",
        )
    )
    referrer = _first(headers, "referrer-policy")
    items.append(
        _present(group, "Referrer-Policy", referrer, f"값 {referrer}" if referrer else "")
    )
    permissions = _first(headers, "permissions-policy")
    items.append(
        _present(
            group,
            "Permissions-Policy",
            permissions,
            "헤더가 있음" if permissions else "",
        )
    )
    coop = _first(headers, "cross-origin-opener-policy")
    items.append(
        _present(
            group,
            "Cross-Origin-Opener-Policy",
            coop,
            f"값 {coop}" if coop else "",
        )
    )
    items.append(
        _exact(
            group,
            "X-Permitted-Cross-Domain-Policies",
            _first(headers, "x-permitted-cross-domain-policies"),
            "none",
        )
    )
    items.append(_hsts(headers, scheme))
    return items


def admin_items(headers: dict[str, list[str]]) -> list[Item]:
    group = "관리 응답"
    cache = _first(headers, "cache-control").lower()
    robots = _first(headers, "x-robots-tag").lower()
    referrer = _first(headers, "referrer-policy").lower()
    cache_ok = "no-store" in cache
    robots_ok = "noindex" in robots and "nofollow" in robots
    return [
        Item(
            group,
            "Cache-Control",
            "pass" if cache_ok else "fail",
            "no-store 가 있음" if cache_ok else f"관찰값 {cache or '없음'}",
        ),
        Item(
            group,
            "Referrer-Policy",
            "pass" if referrer == "no-referrer" else "fail",
            "no-referrer" if referrer == "no-referrer" else f"관찰값 {referrer or '없음'}",
        ),
        Item(
            group,
            "X-Robots-Tag",
            "pass" if robots_ok else "fail",
            "noindex, nofollow" if robots_ok else f"관찰값 {robots or '없음'}",
        ),
    ]


def cookie_items(set_cookies: list[str], scheme: str) -> list[Item]:
    group = "쿠키"
    parsed = [_parse_cookie(raw) for raw in set_cookies]
    match = next((item for item in parsed if item["name"] == "blog_session"), None)
    if match is None:
        names = ", ".join(item["name"] for item in parsed) or "없음"
        missing = "Set-Cookie 에 blog_session 이 없음. 관찰: " + names
        return [
            Item(group, "이름", "fail", missing),
            Item(group, "HttpOnly", "fail", "blog_session 이 없음"),
            Item(group, "SameSite", "fail", "blog_session 이 없음"),
            Item(group, "Secure", "skip" if scheme != "https" else "fail", missing),
        ]
    flags = match["flags"]
    samesite = match["attrs"].get("samesite", "")
    secure = "secure" in flags
    httponly = "httponly" in flags
    samesite_ok = samesite.lower() == "lax"
    if scheme == "https":
        secure_status = "pass" if secure else "fail"
        secure_detail = "Secure 가 있음" if secure else "HTTPS 인데 Secure 가 없음"
    else:
        secure_status = "skip"
        secure_detail = "HTTP 대상이라 Secure 는 판정하지 않음"
    return [
        Item(group, "이름", "pass", "blog_session"),
        Item(
            group,
            "HttpOnly",
            "pass" if httponly else "fail",
            "HttpOnly 가 있음" if httponly else "HttpOnly 가 없음",
        ),
        Item(
            group,
            "SameSite",
            "pass" if samesite_ok else "fail",
            "SameSite=Lax" if samesite_ok else f"관찰값 {samesite or '없음'}",
        ),
        Item(group, "Secure", secure_status, secure_detail),
    ]


def version_items(pages: list[tuple[str, dict[str, list[str]], bytes]]) -> list[Item]:
    group = "버전 노출"
    servers = [
        (value, path)
        for path, headers, _body in pages
        for value in headers.get("server", [])
    ]
    powered = [
        (value, path)
        for path, headers, _body in pages
        for value in headers.get("x-powered-by", [])
    ]
    health = next((body for path, _headers, body in pages if path == "/health"), b"")
    return [
        _server_item(group, servers),
        _powered_item(group, powered),
        _health_item(group, health),
    ]


def csrf_item(path: str, status: int, location: str) -> Item:
    rejected = _is_rejection(status, location)
    if rejected:
        where = location or "본문 없음"
        detail = f"{status} 로 거부함. Location: {where}" if location else f"{status} 로 거부함"
        state = "pass"
    else:
        detail = f"{status} 라 변경 요청이 거부되지 않음"
        state = "fail"
    return Item("CSRF", path, state, detail)


def login_skip_item() -> Item:
    return Item(
        "로그인 속도 제한",
        "429",
        "skip",
        "--login-test 가 없어 로그인 요청을 보내지 않음",
    )


def login_result_item(statuses: list[int], retry_after: str) -> Item:
    group = "로그인 속도 제한"
    if 429 in statuses:
        at = statuses.index(429) + 1
        if retry_after == "60":
            return Item(
                group,
                "429",
                "pass",
                f"오답 {at}회째에 429, Retry-After: 60",
            )
        if retry_after:
            return Item(
                group,
                "429",
                "warn",
                f"오답 {at}회째에 429. Retry-After 관찰값 {retry_after}. 검토 기준은 60임",
            )
        return Item(
            group,
            "429",
            "warn",
            f"오답 {at}회째에 429. Retry-After 가 없음",
        )
    return Item(
        group,
        "429",
        "fail",
        f"오답 {len(statuses)}회 안에 429 가 없음. 관찰: {', '.join(str(s) for s in statuses)}",
    )


def extract_csrf(body: bytes) -> str:
    match = CSRF_PATTERN.search(body.decode("utf-8", errors="replace"))
    if not match:
        return ""
    return next(part for part in match.groups() if part)


def _script_src(policy: dict[str, list[str]]) -> Item:
    tokens = policy.get("script-src", [])
    if not tokens:
        return Item("보안 헤더", "script-src", "fail", "script-src 가 없음")
    has_self = "'self'" in tokens
    has_nonce = any(token.startswith("'nonce-") or token.startswith("nonce-") for token in tokens)
    unsafe = [token for token in ("'unsafe-inline'", "'unsafe-eval'") if token in tokens]
    hosts = [token for token in tokens if _is_host_token(token)]
    problems = []
    if not has_self:
        problems.append("'self' 가 없음")
    if not has_nonce:
        problems.append("요청별 nonce 가 없음")
    if unsafe:
        problems.append("스크립트에 " + ", ".join(unsafe) + " 이 있음")
    if hosts:
        problems.append("CDN 등 외부 출처 " + " ".join(hosts))
    if problems:
        return Item("보안 헤더", "script-src", "fail", "; ".join(problems))
    return Item(
        "보안 헤더",
        "script-src",
        "pass",
        "'self' 와 nonce 가 있고 unsafe-inline·unsafe-eval·외부 출처는 없음",
    )


def _style_src(policy: dict[str, list[str]]) -> Item:
    tokens = policy.get("style-src", [])
    if "'unsafe-inline'" in tokens:
        return Item(
            "보안 헤더",
            "style-src",
            "warn",
            "style-src 에 'unsafe-inline' 이 있음. 검토가 Quill 잔여로 남긴 항목이며 스크립트 쪽 기준은 아님",
        )
    if not tokens:
        return Item("보안 헤더", "style-src", "pass", "style-src 가 없고 인라인 스타일 허용도 없음")
    return Item("보안 헤더", "style-src", "pass", "style-src 에 'unsafe-inline' 이 없음")


def _img_src(policy: dict[str, list[str]]) -> Item:
    tokens = policy.get("img-src", [])
    missing = [token for token in IMG_REQUIRED if token not in tokens]
    observed = " ".join(tokens) if tokens else "없음"
    if missing:
        return Item(
            "보안 헤더",
            "img-src",
            "fail",
            "없는 출처: " + " ".join(missing) + ". 관찰: " + observed,
        )
    return Item(
        "보안 헤더",
        "img-src",
        "pass",
        "'self' data: blob: https://raw.githubusercontent.com 이 있음",
    )


def _font_hosts(policy: dict[str, list[str]]) -> Item:
    hosts = []
    for name in ("style-src", "font-src"):
        for token in policy.get(name, []):
            if _is_host_token(token):
                hosts.append(token)
    extra = sorted({host for host in hosts if host not in FONT_HOSTS})
    if extra:
        return Item(
            "보안 헤더",
            "글꼴 호스트",
            "fail",
            "허용 밖 호스트 " + " ".join(extra),
        )
    listed = " ".join(sorted(set(hosts))) or "없음"
    return Item(
        "보안 헤더",
        "글꼴 호스트",
        "pass",
        "외부 호스트는 fonts.googleapis.com 과 fonts.gstatic.com 뿐임. 관찰: " + listed,
    )


def _upgrade(policy: dict[str, list[str]], scheme: str) -> Item:
    if scheme != "https":
        return Item(
            "보안 헤더",
            "upgrade-insecure-requests",
            "skip",
            "HTTP 대상이라 확인하지 않음",
        )
    if "upgrade-insecure-requests" in policy:
        return Item("보안 헤더", "upgrade-insecure-requests", "pass", "지시문이 있음")
    return Item("보안 헤더", "upgrade-insecure-requests", "fail", "HTTPS 인데 지시문이 없음")


def _hsts(headers: dict[str, list[str]], scheme: str) -> Item:
    if scheme != "https":
        return Item(
            "보안 헤더",
            "Strict-Transport-Security",
            "skip",
            "HTTP 대상이라 확인하지 않음",
        )
    raw = _first(headers, "strict-transport-security")
    if _hsts_ok(raw):
        return Item(
            "보안 헤더",
            "Strict-Transport-Security",
            "pass",
            "max-age=31536000; includeSubDomains",
        )
    return Item(
        "보안 헤더",
        "Strict-Transport-Security",
        "fail",
        f"관찰값 {raw or '없음'}",
    )


def _hsts_ok(value: str) -> bool:
    max_age = None
    includes = False
    for part in value.split(";"):
        token = part.strip().lower()
        if token.startswith("max-age="):
            try:
                max_age = int(token.split("=", 1)[1].strip().strip('"'))
            except ValueError:
                return False
        elif token == "includesubdomains":
            includes = True
    return max_age is not None and max_age >= 31536000 and includes


def _server_item(group: str, servers: list[tuple[str, str]]) -> Item:
    leaked = []
    fly = []
    for value, path in servers:
        if not value:
            continue
        kind = _server_kind(value)
        if kind == "leak":
            leaked.append(f"{path} Server: {value}")
        elif kind == "fly":
            fly.append(f"{path} Server: {value}")
    if leaked:
        return Item(group, "Server", "fail", "; ".join(leaked))
    if fly:
        sample = fly[0].split(" Server: ", 1)[1]
        return Item(
            group,
            "Server",
            "warn",
            f"Server: {sample}. Fly 가장자리 빌드 표기이며 애플리케이션 버전은 아님",
        )
    return Item(group, "Server", "pass", "애플리케이션 버전 헤더가 없음")


def _server_kind(value: str) -> str:
    text = value.strip()
    lowered = text.lower()
    if lowered.startswith("fly/"):
        return "fly"
    if lowered in {"web", "web/"}:
        return "plain"
    if "werkzeug" in lowered or "gunicorn" in lowered:
        return "leak"
    if re.search(r"\d+\.\d+", text):
        return "leak"
    return "plain"


def _powered_item(group: str, powered: list[tuple[str, str]]) -> Item:
    found = [f"{path} X-Powered-By: {value}" for value, path in powered if value]
    if found:
        return Item(group, "X-Powered-By", "fail", "; ".join(found))
    return Item(group, "X-Powered-By", "pass", "헤더가 없음")


def _health_item(group: str, body: bytes) -> Item:
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return Item(group, "/health", "fail", "JSON 이 아님")
    if data == {"status": "ok"}:
        return Item(group, "/health", "pass", '{"status":"ok"} 만 반환함')
    return Item(group, "/health", "fail", "버전 없는 status 객체가 아님. 관찰: " + body.decode("utf-8", errors="replace")[:180])


def _is_rejection(status: int, location: str) -> bool:
    if status in {400, 401, 403}:
        return True
    if status in {301, 302, 303, 307, 308}:
        path = location
        if "://" in location:
            path = urllib.parse.urlparse(location).path
        path = path.split("?", 1)[0].rstrip("/")
        return path == "/admin/login"
    return False


def _is_host_token(token: str) -> bool:
    if token in SCRIPT_KEYWORDS:
        return False
    if token.startswith("'") or token.endswith(":"):
        return False
    if token.startswith(("nonce-", "'nonce-", "sha256-", "sha384-", "sha512-")):
        return False
    return True


def _parse_cookie(raw: str) -> dict[str, object]:
    parts = [part.strip() for part in raw.split(";") if part.strip()]
    name, _, _value = parts[0].partition("=")
    flags = set()
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            attrs[key.strip().lower()] = value.strip()
        else:
            flags.add(part.strip().lower())
    return {"name": name.strip(), "flags": flags, "attrs": attrs}


def _first(headers: dict[str, list[str]], name: str) -> str:
    values = headers.get(name.lower(), [])
    return values[0].strip() if values else ""


def _present(group: str, name: str, value: str, ok_detail: str) -> Item:
    if value:
        return Item(group, name, "pass", ok_detail or "헤더가 있음")
    return Item(group, name, "fail", "헤더가 없음")


def _exact(group: str, name: str, value: str, expected: str) -> Item:
    if value.lower() == expected.lower():
        return Item(group, name, "pass", expected)
    return Item(group, name, "fail", f"관찰값 {value or '없음'}")
