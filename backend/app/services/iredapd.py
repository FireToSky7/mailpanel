from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from app.config import get_config
from app.services import wblist_sql
from app.services.wblist_sql import classify_address


class IredapdError(RuntimeError):
    pass


SCRIPT_CANDIDATES: dict[str, tuple[str, ...]] = {
    "wblist_admin.py": (
        "/opt/iredapd/tools/wblist_admin.py",
        "/opt/www/iRedAPD/tools/wblist_admin.py",
    ),
    "greylisting_admin.py": (
        "/opt/iredapd/tools/greylisting_admin.py",
        "/opt/www/iRedAPD/tools/greylisting_admin.py",
    ),
}


def _resolve_script(configured: str, default_name: str) -> Path:
    path = Path(configured)
    if path.is_file():
        return path
    for candidate in SCRIPT_CANDIDATES.get(default_name, ()):
        candidate_path = Path(candidate)
        if candidate_path.is_file():
            return candidate_path
    raise IredapdError(
        f"Скрипт не найден: {configured}. "
        f"Проверьте paths.wblist_script / greylisting_script в config.yaml"
    )


def _run_script(script: str, args: list[str], default_name: str) -> str:
    script_path = _resolve_script(script, default_name)
    cwd = str(script_path.parent)
    attempts: list[list[str]] = [["python3", script_path.name, *args]]
    if os.geteuid() != 0:
        attempts.append(["sudo", "python3", script_path.name, *args])

    last_error = "Command failed"
    for cmd in attempts:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            cwd=cwd,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        last_error = result.stderr.strip() or result.stdout.strip() or "Command failed"
        if "Permission denied" not in last_error and cmd[0] != "sudo":
            break

    raise IredapdError(
        f"{last_error}\n"
        f"Проверьте на сервере: cd {cwd} && sudo python3 {script_path.name} {' '.join(args)}"
    )


def list_wblist(list_type: str, account: str | None = None) -> list[str]:
    return wblist_sql.list_wblist(list_type, account)


def add_wblist(list_type: str, senders: list[str], account: str | None = None, outbound: bool = False) -> None:
    if outbound:
        raise IredapdError("Исходящие списки пока не поддерживаются в панели")
    wblist_sql.add_wblist(list_type, senders, account)


def delete_wblist(list_type: str, senders: list[str], account: str | None = None) -> None:
    wblist_sql.delete_wblist(list_type, senders, account)


def list_greylisting() -> str:
    return _run_script(get_config().paths.greylisting_script, ["--list"], "greylisting_admin.py")


def list_greylisting_whitelist_domains() -> str:
    return _run_script(
        get_config().paths.greylisting_script,
        ["--list-whitelist-domains"],
        "greylisting_admin.py",
    )


def greylisting_disable(to_addr: str, from_addr: str | None = None) -> None:
    args = ["--disable", "--to", to_addr]
    if from_addr:
        args.extend(["--from", from_addr])
    _run_script(get_config().paths.greylisting_script, args, "greylisting_admin.py")


def greylisting_enable(to_addr: str, from_addr: str | None = None) -> None:
    args = ["--enable", "--to", to_addr]
    if from_addr:
        args.extend(["--from", from_addr])
    _run_script(get_config().paths.greylisting_script, args, "greylisting_admin.py")


def greylisting_whitelist_domain(domain: str) -> None:
    _run_script(
        get_config().paths.greylisting_script,
        ["--whitelist-domain", "--from", domain],
        "greylisting_admin.py",
    )


def hash_mailbox_password(password: str, scheme: str = "SSHA512") -> str:
    result = subprocess.run(
        ["doveadm", "pw", "-s", scheme, "-p", password],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_wblist_entry(value: str) -> str:
    value = value.strip().lower()
    if classify_address(value):
        return value
    raise ValueError("Некорректная запись: укажите email, @domain.ru, @.domain.ru или IP-адрес")
