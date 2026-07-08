from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

from app.config import get_config


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
    result = subprocess.run(
        ["python3", script_path.name, *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(script_path.parent),
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "Command failed"
        raise IredapdError(detail)
    return result.stdout.strip()


def list_wblist(list_type: str, account: str | None = None) -> list[str]:
    cfg = get_config()
    args = ["--list", f"--{list_type}"]
    if account:
        args.extend(["--account", account])
    output = _run_script(cfg.paths.wblist_script, args, "wblist_admin.py")
    if not output:
        return []
    return [line.strip() for line in output.splitlines() if line.strip() and not line.startswith("*")]


def add_wblist(list_type: str, senders: list[str], account: str | None = None, outbound: bool = False) -> None:
    cfg = get_config()
    args = ["--add", f"--{list_type}", *senders]
    if account:
        args.extend(["--account", account])
    if outbound:
        args.append("--outbound")
    _run_script(cfg.paths.wblist_script, args, "wblist_admin.py")


def delete_wblist(list_type: str, senders: list[str], account: str | None = None) -> None:
    cfg = get_config()
    args = ["--delete", f"--{list_type}", *senders]
    if account:
        args.extend(["--account", account])
    _run_script(cfg.paths.wblist_script, args, "wblist_admin.py")


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
    value = value.strip()
    if value.startswith("@") or re.match(r"^\d+\.\d+\.\d+\.\d+", value) or EMAIL_RE.match(value):
        return value
    raise ValueError("Некорректная запись: укажите email, @domain.ru или IP-адрес")
