from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

REINJECT_SERVICE_RE = re.compile(r"127\.0\.0\.1:10025\b")


def _run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=15)
    return (result.stdout or result.stderr or "").strip()


def _master_cf_text() -> str:
    path = Path("/etc/postfix/master.cf")
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _reinjection_has_content_filter_cleared(content: str) -> bool | None:
    """None = служба 10025 не найдена."""
    lines = content.splitlines()
    in_service = False
    saw_service = False
    for line in lines:
        if REINJECT_SERVICE_RE.search(line) and "inet" in line:
            in_service = True
            saw_service = True
            continue
        if in_service:
            stripped = line.strip()
            if stripped and not line.startswith((" ", "\t")):
                break
            if re.search(r"^\s*-o\s+content_filter=\s*$", line):
                return True
            if stripped == "-o content_filter=":
                return True
    if not saw_service:
        return None
    return False


def mail_delivery_diagnostics() -> dict[str, Any]:
    issues: list[dict[str, str]] = []
    hints: list[str] = []

    master_cf = _master_cf_text()
    reinject_ok = _reinjection_has_content_filter_cleared(master_cf) if master_cf else None
    if reinject_ok is False:
        issues.append(
            {
                "level": "error",
                "title": "Зацикливание Amavis",
                "message": (
                    "У службы 127.0.0.1:10025 в /etc/postfix/master.cf не отключён content_filter. "
                    "Письма после Amavis снова попадают в фильтр и зависают в очереди "
                    "(ошибка «too many hops»)."
                ),
                "fix": (
                    "sudo grep -A20 '10025' /etc/postfix/master.cf\n"
                    "# В блоке 127.0.0.1:10025 должна быть строка:\n"
                    "#   -o content_filter=\n"
                    "# Если её нет — добавьте вручную и выполните:\n"
                    "sudo postfix check && sudo postfix reload"
                ),
            }
        )
    elif reinject_ok is None and master_cf:
        issues.append(
            {
                "level": "warning",
                "title": "Служба reinject",
                "message": "Не найдена служба 127.0.0.1:10025 в master.cf — проверьте конфигурацию Postfix вручную.",
                "fix": "sudo grep -n 10025 /etc/postfix/master.cf",
            }
        )

    content_filter = _run(["postconf", "-h", "content_filter"])
    if content_filter and content_filter != "(none)":
        hints.append(f"Глобальный content_filter: {content_filter}")

    clamd_socket = Path("/var/run/clamd.amavisd/clamd.socket")
    if not clamd_socket.exists():
        hints.append(
            "ClamAV не установлен — Amavis работает без антивируса (это нормально для вашей системы). "
            "Предупреждения AV: ALL VIRUS SCANNERS FAILED в логах можно игнорировать."
        )

    amavis_active = _run(["systemctl", "is-active", "amavisd"])
    if amavis_active != "active":
        issues.append(
            {
                "level": "error",
                "title": "Amavis не запущен",
                "message": f"systemctl is-active amavisd → {amavis_active or 'unknown'}",
                "fix": "sudo systemctl restart amavisd",
            }
        )

    policy_path = Path("/etc/mailpanel/antispam_policy.yaml")
    if policy_path.exists():
        text = policy_path.read_text(encoding="utf-8", errors="replace")
        if "scan_internal_mail: true" in text.lower():
            hints.append(
                "Включена проверка внутренней почты через Amavis (Антиспам → политика). "
                "Для диагностики можно временно отключить."
            )

    return {
        "ok": not any(item["level"] == "error" for item in issues),
        "issues": issues,
        "hints": hints,
    }
