"""Fail2ban status, settings, and mailbox auto-disable on ban."""

from __future__ import annotations

import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from app.config import get_config
from app.services import mail_ops

DEFAULT_BANTIME = 3600
DEFAULT_MAXRETRY = 5
DEFAULT_FINDTIME = 600

MAIL_JAILS = (
    "dovecot",
    "postfix",
    "postfix-sasl",
    "postfix-auth",
    "postfix-rbl",
    "sshd",
)

USER_RE = re.compile(
    r"(?:user[=:<\s]+|for user\s+|login[=:\s]+)"
    r"[\"']?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[\"']?",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")


class Fail2banError(RuntimeError):
    pass


def _policy_path() -> Path:
    default = Path("/etc/mailpanel/fail2ban_policy.yaml")
    return Path(getattr(get_config().paths, "fail2ban_policy_file", str(default)))


def _disabled_log_path() -> Path:
    default = Path("/etc/mailpanel/fail2ban_disabled_mailboxes.yaml")
    return Path(getattr(get_config().paths, "fail2ban_disabled_log_file", str(default)))


def _jail_defaults_path() -> Path:
    return Path("/etc/fail2ban/jail.d/00-mailpanel-defaults.local")


def _action_conf_path() -> Path:
    return Path("/etc/fail2ban/action.d/mailpanel-mailbox.conf")


def _jail_action_path() -> Path:
    return Path("/etc/fail2ban/jail.d/mailpanel-mailbox.local")


def _on_ban_script() -> Path:
    return Path(__file__).resolve().parents[3] / "scripts" / "fail2ban-on-ban.py"


def _read_policy() -> dict[str, Any]:
    path = _policy_path()
    if not path.is_file():
        return {
            "bantime": DEFAULT_BANTIME,
            "maxretry": DEFAULT_MAXRETRY,
            "findtime": DEFAULT_FINDTIME,
            "disable_mailbox_on_ban": False,
        }
    data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
    return {
        "bantime": int(data.get("bantime", DEFAULT_BANTIME)),
        "maxretry": int(data.get("maxretry", DEFAULT_MAXRETRY)),
        "findtime": int(data.get("findtime", DEFAULT_FINDTIME)),
        "disable_mailbox_on_ban": bool(data.get("disable_mailbox_on_ban", False)),
    }


def _write_policy(policy: dict[str, Any]) -> None:
    path = _policy_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(
            {
                "bantime": int(policy["bantime"]),
                "maxretry": int(policy["maxretry"]),
                "findtime": int(policy["findtime"]),
                "disable_mailbox_on_ban": bool(policy["disable_mailbox_on_ban"]),
            },
            allow_unicode=True,
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def _run(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def _jail_names() -> list[str]:
    result = _run(["fail2ban-client", "status"])
    if result.returncode != 0:
        return []
    for line in result.stdout.splitlines():
        if "Jail list:" in line:
            tail = line.split("Jail list:")[-1].strip()
            return [j.strip() for j in tail.split(",") if j.strip()]
    return []


def _parse_banned(status_out: str) -> list[str]:
    for line in status_out.splitlines():
        if "Banned IP list:" in line:
            tail = line.split("Banned IP list:")[-1].strip()
            return [ip.strip() for ip in tail.split() if ip.strip()]
    return []


def fail2ban_status() -> list[dict[str, Any]]:
    jails: list[dict[str, Any]] = []
    for jail in _jail_names():
        detail = _run(["fail2ban-client", "status", jail])
        jails.append({"jail": jail, "banned_ips": _parse_banned(detail.stdout)})
    return jails


def fail2ban_banned_table() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in fail2ban_status():
        for ip in item["banned_ips"]:
            rows.append({"ip": ip, "jail": item["jail"]})
    rows.sort(key=lambda r: (r["jail"], r["ip"]))
    return rows


def fail2ban_unban(jail: str, ip: str) -> None:
    result = _run(["fail2ban-client", "set", jail, "unbanip", ip])
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unban failed").strip()
        raise Fail2banError(detail)


def _get_jail_int(jail: str, key: str, default: int) -> int:
    result = _run(["fail2ban-client", "get", jail, key])
    if result.returncode != 0:
        return default
    text = (result.stdout or "").strip().splitlines()
    if not text:
        return default
    try:
        return int(text[-1].strip())
    except ValueError:
        return default


def read_settings() -> dict[str, Any]:
    policy = _read_policy()
    jails = _jail_names()
    sample = next((j for j in jails if j in MAIL_JAILS), jails[0] if jails else None)
    live_bantime = _get_jail_int(sample, "bantime", policy["bantime"]) if sample else policy["bantime"]
    live_maxretry = _get_jail_int(sample, "maxretry", policy["maxretry"]) if sample else policy["maxretry"]
    live_findtime = _get_jail_int(sample, "findtime", policy["findtime"]) if sample else policy["findtime"]
    return {
        "bantime": live_bantime,
        "maxretry": live_maxretry,
        "findtime": live_findtime,
        "disable_mailbox_on_ban": policy["disable_mailbox_on_ban"],
        "jails": jails,
        "sample_jail": sample or "",
        "recent_disabled": _read_disabled_log()[:20],
        "notes": [
            "Параметры bantime / maxretry / findtime применяются ко всем jail через jail.d MailPanel.",
            "Галочка «отключать ящик» срабатывает при бане Fail2ban: ищется ящик по логам auth для этого IP.",
            "Отключённый ящик можно снова включить во вкладке «Ящики».",
        ],
    }


def _write_jail_defaults(bantime: int, maxretry: int, findtime: int) -> None:
    path = _jail_defaults_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "# Generated by MailPanel. Do not edit manually.\n"
        "[DEFAULT]\n"
        f"bantime = {bantime}\n"
        f"maxretry = {maxretry}\n"
        f"findtime = {findtime}\n",
        encoding="utf-8",
    )


def _python_bin() -> str:
    venv = Path("/opt/mailpanel/venv/bin/python")
    if venv.is_file():
        return str(venv)
    return "python3"


def _ensure_mailbox_action_files() -> None:
    script = _on_ban_script()
    action = _action_conf_path()
    action.parent.mkdir(parents=True, exist_ok=True)
    action.write_text(
        "# Generated by MailPanel. Do not edit manually.\n"
        "[Definition]\n"
        "actionstart =\n"
        "actionstop =\n"
        "actioncheck =\n"
        f'actionban = {_python_bin()} {script.as_posix()} --ip "<ip>" --jail "<name>"\n'
        "actionunban =\n",
        encoding="utf-8",
    )

    jails = [j for j in _jail_names() if j in MAIL_JAILS] or list(MAIL_JAILS[:3])
    blocks = [
        "# Generated by MailPanel. Do not edit manually.\n"
        "# Adds mailbox auto-disable hook; IP ban stays via %(action_)s.\n"
    ]
    for jail in jails:
        blocks.append(
            f"[{jail}]\n"
            "action = %(action_)s\n"
            "         mailpanel-mailbox[name=%(__name__)s]\n"
        )
    _jail_action_path().write_text("\n".join(blocks) + "\n", encoding="utf-8")


def _reload_fail2ban() -> None:
    result = _run(["fail2ban-client", "reload"], timeout=60)
    if result.returncode != 0:
        # Fallback: restart service
        restart = _run(["systemctl", "restart", "fail2ban"], timeout=60)
        if restart.returncode != 0:
            detail = (result.stderr or result.stdout or restart.stderr or "reload failed").strip()
            raise Fail2banError(f"Не удалось перезагрузить fail2ban: {detail[:400]}")


def _apply_live_settings(bantime: int, maxretry: int, findtime: int) -> None:
    for jail in _jail_names():
        _run(["fail2ban-client", "set", jail, "bantime", str(bantime)])
        _run(["fail2ban-client", "set", jail, "maxretry", str(maxretry)])
        _run(["fail2ban-client", "set", jail, "findtime", str(findtime)])


def write_settings(
    *,
    bantime: int,
    maxretry: int,
    findtime: int,
    disable_mailbox_on_ban: bool,
) -> dict[str, Any]:
    if bantime < 60 or bantime > 86400 * 30:
        raise Fail2banError("bantime: укажите от 60 секунд до 30 дней")
    if maxretry < 1 or maxretry > 100:
        raise Fail2banError("maxretry: укажите от 1 до 100")
    if findtime < 60 or findtime > 86400:
        raise Fail2banError("findtime: укажите от 60 секунд до 1 суток")

    policy = {
        "bantime": int(bantime),
        "maxretry": int(maxretry),
        "findtime": int(findtime),
        "disable_mailbox_on_ban": bool(disable_mailbox_on_ban),
    }
    _write_policy(policy)
    _write_jail_defaults(policy["bantime"], policy["maxretry"], policy["findtime"])

    # Action always installed; script no-ops when disable_mailbox_on_ban is false.
    if not _on_ban_script().is_file():
        raise Fail2banError(f"Скрипт не найден: {_on_ban_script()}")
    _ensure_mailbox_action_files()

    _reload_fail2ban()
    _apply_live_settings(policy["bantime"], policy["maxretry"], policy["findtime"])
    return read_settings()


def _read_disabled_log() -> list[dict[str, str]]:
    path = _disabled_log_path()
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
    entries = data.get("entries") or []
    result: list[dict[str, str]] = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        mailbox = str(item.get("mailbox") or "").strip()
        if not mailbox:
            continue
        result.append(
            {
                "mailbox": mailbox,
                "ip": str(item.get("ip") or ""),
                "jail": str(item.get("jail") or ""),
                "at": str(item.get("at") or ""),
            }
        )
    return result


def _append_disabled_log(mailbox: str, ip: str, jail: str) -> None:
    entries = _read_disabled_log()
    entries.insert(
        0,
        {
            "mailbox": mailbox,
            "ip": ip,
            "jail": jail,
            "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    )
    path = _disabled_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump({"entries": entries[:100]}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def _log_paths() -> list[Path]:
    cfg = get_config().paths
    paths = [
        Path(getattr(cfg, "maillog", "/var/log/maillog")),
        Path(getattr(cfg, "dovecot_log", "/var/log/dovecot/dovecot.log")),
        Path("/var/log/maillog"),
        Path("/var/log/mail.log"),
        Path("/var/log/secure"),
    ]
    seen: set[str] = set()
    result: list[Path] = []
    for path in paths:
        key = str(path)
        if key in seen or not path.is_file():
            continue
        seen.add(key)
        result.append(path)
    return result


def _tail_file(path: Path, max_bytes: int = 512_000) -> str:
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
            return fh.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _extract_mailboxes_for_ip(ip: str) -> list[str]:
    found: set[str] = set()
    for path in _log_paths():
        text = _tail_file(path)
        for line in text.splitlines():
            if ip not in line:
                continue
            lower = line.lower()
            if not any(
                token in lower
                for token in (
                    "auth",
                    "login",
                    "password",
                    "sasl",
                    "authentication failure",
                    "failed",
                    "mismatch",
                )
            ):
                continue
            for match in USER_RE.finditer(line):
                found.add(match.group(1).lower())
            if "sasl" in lower or "dovecot" in lower or "auth" in lower:
                for match in EMAIL_RE.finditer(line):
                    email = match.group(1).lower()
                    if email.endswith((".ru", ".com", ".org", ".net")) or "@" in email:
                        found.add(email)
    return sorted(found)


def disable_mailboxes_for_banned_ip(ip: str, jail: str) -> list[str]:
    policy = _read_policy()
    if not policy.get("disable_mailbox_on_ban"):
        return []
    disabled: list[str] = []
    for mailbox in _extract_mailboxes_for_ip(ip):
        try:
            mail_ops.update_mailbox_active(mailbox, False)
            _append_disabled_log(mailbox, ip, jail)
            disabled.append(mailbox)
        except Exception:
            continue
    return disabled
