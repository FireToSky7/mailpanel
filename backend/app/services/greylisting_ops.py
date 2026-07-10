from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from app.services import iredapd
from app.services.mail_journal_search import _parse_journal_line, _run_journalctl

GREYLISTING_SETTING_KEYS = (
    "GREYLISTING_TRAINING_MODE",
    "GREYLISTING_MESSAGE",
    "GREYLISTING_BLOCK_EXPIRE",
    "GREYLISTING_AUTH_TRIPLET_EXPIRE",
    "GREYLISTING_UNAUTH_TRIPLET_EXPIRE",
    "GREYLISTING_BYPASS_SPF",
)

SETTING_DEFAULTS: dict[str, Any] = {
    "GREYLISTING_TRAINING_MODE": False,
    "GREYLISTING_MESSAGE": "Intentional policy rejection, please try again later",
    "GREYLISTING_BLOCK_EXPIRE": 15,
    "GREYLISTING_AUTH_TRIPLET_EXPIRE": 30,
    "GREYLISTING_UNAUTH_TRIPLET_EXPIRE": 2,
    "GREYLISTING_BYPASS_SPF": True,
}

IREDAPD_SETTINGS_CANDIDATES = (
    Path("/opt/iredapd/settings.py"),
    Path("/opt/www/iRedAPD/settings.py"),
)

IREDAPD_DEFAULTS_CANDIDATES = (
    Path("/opt/iredapd/libs/default_settings.py"),
    Path("/opt/www/iRedAPD/libs/default_settings.py"),
)

GREYLIST_JOURNAL_GREP = (
    r"Intentional policy rejection|greylist|Greylist|policy rejection, please try again"
)

CLIENT_IP_RE = re.compile(r"\b(?:client=|from )([0-9a-fA-F:.]+)(?:\[|\s|$)")
FROM_ADDR_RE = re.compile(r"from=<([^>]*)>", re.I)
TO_ADDR_RE = re.compile(r"to=<([^>]*)>", re.I)


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_setting_value(raw: str) -> Any:
    text = raw.strip()
    if text.startswith(("'", '"')) and text.endswith(("'", '"')):
        return text[1:-1]
    lowered = text.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    try:
        if "." in text:
            return float(text)
        return int(text)
    except ValueError:
        return text


def _read_python_settings(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    found: dict[str, Any] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for key in GREYLISTING_SETTING_KEYS:
            if not stripped.startswith(f"{key} "):
                continue
            match = re.match(rf"{re.escape(key)}\s*=\s*(.+?)\s*(?:#.*)?$", stripped)
            if match:
                found[key] = _parse_setting_value(match.group(1))
    return found


def read_greylisting_timing() -> dict[str, Any]:
    values = dict(SETTING_DEFAULTS)
    for path in IREDAPD_DEFAULTS_CANDIDATES:
        values.update(_read_python_settings(path))
    for path in IREDAPD_SETTINGS_CANDIDATES:
        values.update(_read_python_settings(path))
    return {
        "training_mode": bool(values["GREYLISTING_TRAINING_MODE"]),
        "rejection_message": str(values["GREYLISTING_MESSAGE"]),
        "block_expire_minutes": int(values["GREYLISTING_BLOCK_EXPIRE"]),
        "auth_triplet_expire_days": int(values["GREYLISTING_AUTH_TRIPLET_EXPIRE"]),
        "unauth_triplet_expire_days": int(values["GREYLISTING_UNAUTH_TRIPLET_EXPIRE"]),
        "bypass_spf": bool(values["GREYLISTING_BYPASS_SPF"]),
        "settings_file": next(
            (str(path) for path in IREDAPD_SETTINGS_CANDIDATES if path.is_file()),
            "",
        ),
    }


def _parse_lines(raw: str) -> list[str]:
    return [line.strip() for line in raw.splitlines() if line.strip() and not line.strip().startswith("#")]


def _parse_settings_table(raw: str) -> list[dict[str, Any]]:
    lines = _parse_lines(raw)
    if len(lines) < 2:
        return []
    delimiter = "\t" if "\t" in lines[0] else None
    if delimiter:
        headers = [cell.strip().lower() for cell in lines[0].split("\t") if cell.strip()]
        rows: list[dict[str, Any]] = []
        for line in lines[1:]:
            cells = [cell.strip() for cell in line.split("\t")]
            if not any(cells):
                continue
            item: dict[str, Any] = {}
            for index, header in enumerate(headers):
                if index < len(cells):
                    item[header] = cells[index]
            action = (item.get("action") or item.get("status") or cells[0]).lower()
            from_addr = item.get("from") or item.get("sender") or (cells[1] if len(cells) > 1 else "@.")
            to_addr = item.get("to") or item.get("recipient") or (cells[2] if len(cells) > 2 else "@.")
            priority = item.get("priority")
            if priority is None and len(cells) > 3:
                priority = cells[3]
            rows.append(
                {
                    "action": action,
                    "from_addr": from_addr or "@.",
                    "to_addr": to_addr or "@.",
                    "priority": priority,
                }
            )
        return rows

    rows = []
    for line in lines:
        parts = line.split()
        if not parts:
            continue
        action = parts[0].lower()
        if action not in {"enabled", "disabled"}:
            continue
        from_addr = parts[1] if len(parts) > 1 else "@."
        to_addr = parts[2] if len(parts) > 2 else "@."
        priority = parts[3] if len(parts) > 3 else None
        rows.append(
            {
                "action": action,
                "from_addr": from_addr,
                "to_addr": to_addr,
                "priority": priority,
            }
        )
    return rows


def _parse_whitelist_domains(raw: str) -> list[str]:
    domains: list[str] = []
    for line in _parse_lines(raw):
        token = line.split()[0].strip()
        if token.startswith("@"):
            domains.append(token)
    return sorted(set(domains))


def _parse_whitelist_addresses(raw: str) -> list[str]:
    items: list[str] = []
    for line in _parse_lines(raw):
        if "\t" in line:
            cells = [cell.strip() for cell in line.split("\t") if cell.strip()]
            if cells:
                items.append(cells[0])
            continue
        token = line.split()[0].strip()
        if token and not token.lower().startswith(("sender", "account", "priority")):
            items.append(token)
    return sorted(set(items))


def _infer_global_enabled(rules: list[dict[str, Any]]) -> bool:
    for rule in rules:
        if rule.get("from_addr") == "@." and rule.get("to_addr") == "@.":
            return rule.get("action") == "enabled"
    return True


def greylisting_stats(hours: int = 24, limit: int = 20) -> dict[str, Any]:
    hours = max(1, min(hours, 168))
    since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    lines = _run_journalctl(since, None, GREYLIST_JOURNAL_GREP, max_lines=8000)
    sender_counts: dict[str, int] = {}
    recent: list[dict[str, Any]] = []
    for line in reversed(lines):
        row = _parse_journal_line(line)
        if not row:
            continue
        message = row.get("message") or ""
        if not re.search(GREYLIST_JOURNAL_GREP, message, re.I):
            continue
        mail_from = row.get("mail_from")
        if not mail_from:
            match = FROM_ADDR_RE.search(message)
            mail_from = match.group(1) if match else None
        mail_to = row.get("mail_to")
        if not mail_to:
            match = TO_ADDR_RE.search(message)
            mail_to = match.group(1) if match else None
        client_ip = None
        match = CLIENT_IP_RE.search(message)
        if match:
            client_ip = match.group(1)
        if mail_from:
            sender_counts[mail_from] = sender_counts.get(mail_from, 0) + 1
        if len(recent) < limit:
            recent.append(
                {
                    "logged_at": row.get("logged_at"),
                    "service": row.get("service"),
                    "mail_from": mail_from,
                    "mail_to": mail_to,
                    "client_ip": client_ip,
                    "message": message[:500],
                }
            )
    top_senders = [
        {"address": address, "count": count}
        for address, count in sorted(sender_counts.items(), key=lambda item: (-item[1], item[0]))[:10]
    ]
    return {
        "hours": hours,
        "rejections": sum(sender_counts.values()) or len(recent),
        "top_senders": top_senders,
        "recent": list(reversed(recent)),
    }


def get_greylisting_overview() -> dict[str, Any]:
    settings_raw = iredapd.list_greylisting()
    domains_raw = iredapd.list_greylisting_whitelist_domains()
    whitelists_raw = iredapd.list_greylisting_whitelists()
    rules = _parse_settings_table(settings_raw)
    whitelist_domains = _parse_whitelist_domains(domains_raw)
    whitelist_addresses = _parse_whitelist_addresses(whitelists_raw)
    timing = read_greylisting_timing()
    stats = greylisting_stats()
    return {
        "global_enabled": _infer_global_enabled(rules),
        "timing": timing,
        "rules": rules,
        "whitelist_domains": whitelist_domains,
        "whitelist_addresses": whitelist_addresses,
        "stats": stats,
        "raw": {
            "settings": settings_raw,
            "whitelist_domains": domains_raw,
            "whitelist_addresses": whitelists_raw,
        },
        "notes": [
            "Greylisting откладывает первую попытку доставки; легитимные серверы повторяют отправку.",
            "Домены в SPF-whitelist пропускаются без задержки после обновления IP из DNS.",
            "Отключение для ящика или пары «отправитель → получатель» не влияет на Amavis и белые списки.",
            f"Повторная доставка разрешена не ранее чем через {timing['block_expire_minutes']} мин.",
            f"Успешные отправители запоминаются на {timing['auth_triplet_expire_days']} дн.",
        ],
    }
