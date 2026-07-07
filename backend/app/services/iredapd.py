from __future__ import annotations

import re
import subprocess
from typing import Any

from app.config import get_config


class IredapdError(RuntimeError):
    pass


def _run_script(script: str, args: list[str]) -> str:
    result = subprocess.run(
        ["python3", script, *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise IredapdError(result.stderr.strip() or result.stdout.strip() or "Command failed")
    return result.stdout.strip()


def list_wblist(list_type: str, account: str | None = None) -> list[str]:
    cfg = get_config()
    args = ["--list", f"--{list_type}"]
    if account:
        args.extend(["--account", account])
    output = _run_script(cfg.paths.wblist_script, args)
    return [line.strip() for line in output.splitlines() if line.strip() and not line.startswith("*")]


def add_wblist(list_type: str, senders: list[str], account: str | None = None, outbound: bool = False) -> None:
    cfg = get_config()
    args = ["--add", f"--{list_type}", *senders]
    if account:
        args.extend(["--account", account])
    if outbound:
        args.append("--outbound")
    _run_script(cfg.paths.wblist_script, args)


def delete_wblist(list_type: str, senders: list[str], account: str | None = None) -> None:
    cfg = get_config()
    args = ["--delete", f"--{list_type}", *senders]
    if account:
        args.extend(["--account", account])
    _run_script(cfg.paths.wblist_script, args)


def list_greylisting() -> str:
    return _run_script(get_config().paths.greylisting_script, ["--list"])


def list_greylisting_whitelist_domains() -> str:
    return _run_script(get_config().paths.greylisting_script, ["--list-whitelist-domains"])


def greylisting_disable(to_addr: str, from_addr: str | None = None) -> None:
    args = ["--disable", "--to", to_addr]
    if from_addr:
        args.extend(["--from", from_addr])
    _run_script(get_config().paths.greylisting_script, args)


def greylisting_enable(to_addr: str, from_addr: str | None = None) -> None:
    args = ["--enable", "--to", to_addr]
    if from_addr:
        args.extend(["--from", from_addr])
    _run_script(get_config().paths.greylisting_script, args)


def greylisting_whitelist_domain(domain: str) -> None:
    _run_script(get_config().paths.greylisting_script, ["--whitelist-domain", "--from", domain])


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
    raise ValueError("Invalid entry: use email, @domain.com or IP")
