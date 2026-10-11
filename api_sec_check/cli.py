"""명령행 진입점."""

from __future__ import annotations

import argparse
import sys
import urllib.parse

from api_sec_check.report import render
from api_sec_check.runner import run

MAX_LOGIN_ATTEMPTS = 12
DEFAULT_LOGIN_ATTEMPTS = 9


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="api-sec-check",
        description=(
            "보안 헤더, CSP, HSTS, 쿠키, 버전 노출, "
            "CSRF 없는 관리 POST의 거부를 읽기 전용으로 확인함. "
            "로그인 429는 --login-test 일 때만, 최대 12회까지 봄."
        ),
    )
    parser.add_argument("url", help="점검할 http 또는 https 주소")
    parser.add_argument(
        "--login-test",
        action="store_true",
        help="없는 계정과 고정 오답으로 로그인 429를 확인함",
    )
    parser.add_argument(
        "--login-attempts",
        type=int,
        default=None,
        help=f"로그인 시도 상한. 기본 {DEFAULT_LOGIN_ATTEMPTS}, 최대 {MAX_LOGIN_ATTEMPTS}",
    )
    args = parser.parse_args(argv)
    scheme = urllib.parse.urlparse(args.url).scheme
    if scheme not in {"http", "https"}:
        print("http 또는 https 주소만 받음", file=sys.stderr)
        return 2
    if args.login_attempts is not None and not args.login_test:
        print("로그인 시도 횟수는 --login-test 와 함께만 씀", file=sys.stderr)
        return 2
    attempts = DEFAULT_LOGIN_ATTEMPTS if args.login_attempts is None else args.login_attempts
    if args.login_test and not 1 <= attempts <= MAX_LOGIN_ATTEMPTS:
        print(
            f"로그인 시도 횟수는 1 이상 {MAX_LOGIN_ATTEMPTS} 이하여야 함",
            file=sys.stderr,
        )
        return 2
    report = run(args.url, login_test=args.login_test, login_attempts=attempts)
    sys.stdout.write(render(report))
    return 0 if report.ok else 1
