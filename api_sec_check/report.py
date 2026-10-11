"""한국어 보고서와 JSON."""

from __future__ import annotations

import json

from api_sec_check.checks import LABEL
from api_sec_check.runner import Report


def _width(text: str) -> int:
    return sum(2 if ord(char) > 0x2E80 else 1 for char in text)


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _width(text))


def render_text(report: Report) -> str:
    lines = [
        "api-sec-check",
        f"대상: {report.target}",
        "기준: OWASP API Security Top 10 (2023) 조치 후. 읽기와 거부 확인만 함",
    ]
    if report.login_test:
        lines.append("모드: 기본 검사와 로그인 속도 제한")
    else:
        lines.append("모드: 기본 검사. 로그인 속도 제한은 건너뜀")
    lines.append("")
    current = ""
    for item in report.items:
        if item.group != current:
            current = item.group
            lines.append(f"[{current}]")
        lines.append(f"  {_pad(LABEL[item.status], 6)}  {item.name}")
        lines.append(f"        {item.detail}")
    counts = report.summary
    lines.append("")
    lines.append(
        "요약: 충족 {충족}, 주의 {주의}, 미충족 {미충족}, 건너뜀 {건너뜀}".format(**counts)
    )
    return "\n".join(lines) + "\n"


def render_json(report: Report) -> str:
    payload = {
        "대상": report.target,
        "로그인_검사": report.login_test,
        "항목": [item.as_dict() for item in report.items],
        "요약": report.summary,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def render(report: Report) -> str:
    return render_text(report) + "--- json ---\n" + render_json(report)
