"""대상 URL에 기본 조회와, 플래그가 있을 때만 로그인 잠금 확인을 보냄."""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from http.cookiejar import CookieJar

from api_sec_check.checks import (
    CSRF_TARGETS,
    Item,
    admin_items,
    cookie_items,
    csrf_item,
    extract_csrf,
    failed,
    header_items,
    login_result_item,
    login_skip_item,
    summary,
    version_items,
)
from api_sec_check.http import Client, HttpResponse

LOGIN_USER = "rate-limit-probe"
LOGIN_PASSWORD = "invalid-password"


@dataclass
class Report:
    target: str
    login_test: bool
    items: list[Item]

    @property
    def summary(self) -> dict[str, int]:
        return summary(self.items)

    @property
    def ok(self) -> bool:
        return not failed(self.items)


def run(target: str, login_test: bool = False, login_attempts: int = 9) -> Report:
    base = target.rstrip("/")
    scheme = urllib.parse.urlparse(base).scheme
    pages = {
        "/": _get(base, "/"),
        "/health": _get(base, "/health"),
        "/admin/login": _get(base, "/admin/login"),
    }
    items: list[Item] = []
    home = pages["/"]
    items.extend(header_items(home.headers, scheme))
    items.extend(admin_items(pages["/admin/login"].headers))
    items.extend(
        cookie_items(pages["/admin/login"].headers.get("set-cookie", []), scheme)
    )
    items.extend(
        version_items(
            [(path, response.headers, response.body) for path, response in pages.items()]
        )
    )
    for path, data, content_type in CSRF_TARGETS:
        response = _post(base, path, data, content_type)
        items.append(csrf_item(path, response.status, response.location))
    if login_test:
        statuses, retry_after, problem = _login_attempts(base, login_attempts)
        if problem:
            items.append(
                Item(
                    "로그인 속도 제한",
                    "429",
                    "fail",
                    "로그인 폼에서 csrf_token 을 찾지 못해 시도하지 않음",
                )
            )
        else:
            items.append(login_result_item(statuses, retry_after))
    else:
        items.append(login_skip_item())
    return Report(target=base, login_test=login_test, items=items)


def _get(base: str, path: str) -> HttpResponse:
    return Client().request("GET", base + path)


def _post(base: str, path: str, data: bytes | None, content_type: str) -> HttpResponse:
    headers = {"Content-Type": content_type} if content_type else {}
    return Client().request("POST", base + path, data=data, headers=headers)


def _login_attempts(base: str, attempts: int) -> tuple[list[int], str, str]:
    client = Client(jar=CookieJar())
    page = client.request("GET", base + "/admin/login")
    token = extract_csrf(page.body)
    statuses: list[int] = []
    retry_after = ""
    if not token:
        return statuses, retry_after, "missing-token"
    for _ in range(attempts):
        body = urllib.parse.urlencode(
            {
                "username": LOGIN_USER,
                "password": LOGIN_PASSWORD,
                "csrf_token": token,
                "next": "/admin/",
            }
        ).encode()
        response = client.request(
            "POST",
            base + "/admin/login",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        statuses.append(response.status)
        refreshed = extract_csrf(response.body)
        if refreshed:
            token = refreshed
        if response.status == 429:
            retry_after = response.header("retry-after")
            break
    return statuses, retry_after, ""
