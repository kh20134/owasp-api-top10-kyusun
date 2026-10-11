import json

import pytest

from api_sec_check.checks import cookie_items, header_items
from api_sec_check.cli import main
from tests.fixture_app import create_app, serve


@pytest.fixture()
def hardened():
    app = create_app()
    server = serve(app)
    base = f"http://127.0.0.1:{server.server_port}"
    yield app, base
    server.shutdown()


@pytest.fixture()
def opened():
    app = create_app(profile="open")
    server = serve(app)
    base = f"http://127.0.0.1:{server.server_port}"
    yield app, base
    server.shutdown()


def _json_block(text: str) -> dict:
    return json.loads(text.split("--- json ---", 1)[1])


def test_default_checks_pass_and_do_not_post_login(hardened, capsys):
    app, base = hardened
    code = main([base])
    out = capsys.readouterr().out
    assert code == 0
    assert app.extensions["login_post_count"] == 0
    assert "로그인 속도 제한은 건너뜀" in out
    data = _json_block(out)
    assert data["로그인_검사"] is False
    assert data["요약"]["미충족"] == 0
    assert data["요약"]["건너뜀"] >= 1
    names = [item["이름"] for item in data["항목"]]
    assert "/admin/posts/1/delete" in names
    assert "/health" in names


def test_login_test_stops_on_429(hardened, capsys):
    _app, base = hardened
    code = main([base, "--login-test", "--login-attempts", "4"])
    out = capsys.readouterr().out
    assert code == 0
    assert "429" in out
    assert "Retry-After: 60" in out
    data = _json_block(out)
    assert data["로그인_검사"] is True
    login = next(item for item in data["항목"] if item["구분"] == "로그인 속도 제한")
    assert login["판정"] == "충족"
    assert "invalid-password" not in out
    assert "rate-limit-probe" not in out


def test_open_profile_fails(opened, capsys):
    app, base = opened
    code = main([base])
    out = capsys.readouterr().out
    assert code == 1
    assert app.extensions["login_post_count"] == 0
    data = _json_block(out)
    assert data["요약"]["미충족"] > 0
    by_name = {item["이름"]: item["판정"] for item in data["항목"]}
    assert by_name["Server"] == "미충족"
    assert by_name["/health"] == "미충족"
    assert by_name["/admin/logout"] == "미충족"
    assert by_name["img-src"] == "미충족"


def test_https_header_rules_cover_hsts_and_secure_cookie():
    headers = {
        "content-security-policy": [
            "default-src 'self'; script-src 'self' 'nonce-abc'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: blob: https://raw.githubusercontent.com; "
            "upgrade-insecure-requests"
        ],
        "x-content-type-options": ["nosniff"],
        "x-frame-options": ["DENY"],
        "referrer-policy": ["strict-origin-when-cross-origin"],
        "permissions-policy": ["camera=()"],
        "cross-origin-opener-policy": ["same-origin"],
        "x-permitted-cross-domain-policies": ["none"],
        "strict-transport-security": ["max-age=31536000; includeSubDomains"],
    }
    items = {item.name: item for item in header_items(headers, "https")}
    assert items["Strict-Transport-Security"].status == "pass"
    assert items["upgrade-insecure-requests"].status == "pass"
    assert items["style-src"].status == "warn"
    assert items["img-src"].status == "pass"
    cookies = {
        item.name: item
        for item in cookie_items(
            ["blog_session=abc; Secure; HttpOnly; Path=/; SameSite=Lax"],
            "https",
        )
    }
    assert cookies["Secure"].status == "pass"
    assert cookies["HttpOnly"].status == "pass"


def test_https_missing_hsts_and_secure_fail():
    headers = {
        "content-security-policy": ["script-src 'self' 'nonce-abc'; img-src 'self'"],
        "x-content-type-options": ["nosniff"],
        "x-frame-options": ["DENY"],
        "referrer-policy": ["strict-origin-when-cross-origin"],
        "permissions-policy": ["camera=()"],
        "cross-origin-opener-policy": ["same-origin"],
        "x-permitted-cross-domain-policies": ["none"],
    }
    items = {item.name: item for item in header_items(headers, "https")}
    assert items["Strict-Transport-Security"].status == "fail"
    assert items["img-src"].status == "fail"
    assert items["upgrade-insecure-requests"].status == "fail"
    cookies = {item.name: item for item in cookie_items(["blog_session=abc; HttpOnly; SameSite=Lax"], "https")}
    assert cookies["Secure"].status == "fail"


def test_login_attempts_require_flag_and_stay_low(capsys):
    assert main(["http://127.0.0.1:9", "--login-attempts", "3"]) == 2
    assert main(["http://127.0.0.1:9", "--login-test", "--login-attempts", "13"]) == 2
    assert main(["http://127.0.0.1:9", "--login-test", "--login-attempts", "0"]) == 2
    assert main(["ftp://example.com"]) == 2
    err = capsys.readouterr().err
    assert "12" in err
    assert "http 또는 https" in err


def test_fly_server_header_is_a_warning_not_a_failure():
    from api_sec_check.checks import version_items

    items = {
        item.name: item
        for item in version_items(
            [
                (
                    "/",
                    {"server": ["Fly/268b58352a (2026-10-09)"]},
                    b"",
                ),
                ("/health", {"server": ["Fly/268b58352a (2026-10-09)"]}, b'{"status":"ok"}'),
            ]
        )
    }
    assert items["Server"].status == "warn"
    assert "애플리케이션 버전은 아님" in items["Server"].detail
    assert items["/health"].status == "pass"
