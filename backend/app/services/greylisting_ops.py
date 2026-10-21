from __future__ import annotations

import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pymysql
from pymysql.cursors import DictCursor

from app.services import iredapd
from app.services.mail_journal_search import _parse_journal_line, _run_journalctl
from app.services.wblist_sql import classify_address

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

IP_OR_CIDR_RE = re.compile(
    r"^(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?"
    r"|"
    r"[0-9a-fA-F:]+(?:/\d{1,3})?"
    r")$"
)


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


def _looks_like_ip(value: str) -> bool:
    text = (value or "").strip().lower()
    if not text or text.startswith("@"):
        return False
    if IP_OR_CIDR_RE.match(text):
        return True
    return classify_address(text) == "ip"


def normalize_ip_or_cidr(value: str) -> str:
    text = (value or "").strip().lower()
    if not _looks_like_ip(text):
        raise ValueError(f"Укажите IP или CIDR, например 192.168.1.10 или 10.0.0.0/24: {value}")
    # Простая проверка октетов IPv4
    if "." in text.split("/")[0]:
        host = text.split("/")[0]
        parts = host.split(".")
        if len(parts) != 4 or any(not p.isdigit() or int(p) > 255 for p in parts):
            raise ValueError(f"Некорректный IPv4: {value}")
        if "/" in text:
            prefix = int(text.split("/")[1])
            if prefix < 0 or prefix > 32:
                raise ValueError(f"Некорректный префикс CIDR: {value}")
    return text


def _settings_py_path() -> Path:
    for path in IREDAPD_SETTINGS_CANDIDATES:
        if path.is_file():
            return path
    raise FileNotFoundError("Не найден /opt/iredapd/settings.py")


def _render_setting_value(value: Any) -> str:
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace("'", "\\'")
        return f"'{escaped}'"
    if isinstance(value, float):
        return str(value)
    return str(int(value))


def _write_text_sudo(path: Path, content: str) -> None:
    try:
        path.write_text(content, encoding="utf-8")
        return
    except PermissionError:
        pass
    result = subprocess.run(
        ["sudo", "tee", str(path)],
        input=content,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "tee failed").strip()
        raise RuntimeError(f"Не удалось записать {path}: {detail}")


def _upsert_settings(updates: dict[str, Any]) -> Path:
    path = _settings_py_path()
    content = path.read_text(encoding="utf-8", errors="replace")
    for key, value in updates.items():
        line = f"{key} = {_render_setting_value(value)}"
        pattern = rf"^{re.escape(key)}\s*=\s*.*$"
        if re.search(pattern, content, flags=re.M):
            content = re.sub(pattern, line, content, count=1, flags=re.M)
        else:
            content = content.rstrip() + f"\n\n# Managed by MailPanel\n{line}\n"
    _write_text_sudo(path, content)
    return path


def _restart_iredapd() -> None:
    from app.services import mail_ops

    try:
        mail_ops.restart_service("iredapd")
        return
    except Exception:
        pass
    result = subprocess.run(
        ["systemctl", "restart", "iredapd"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        result = subprocess.run(
            ["sudo", "systemctl", "restart", "iredapd"],
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "restart failed").strip()
        raise RuntimeError(f"Настройки записаны, но не удалось перезапустить iredapd: {detail}")


def update_greylisting_timing(payload: dict[str, Any]) -> dict[str, Any]:
    updates: dict[str, Any] = {}
    if "training_mode" in payload and payload["training_mode"] is not None:
        updates["GREYLISTING_TRAINING_MODE"] = bool(payload["training_mode"])
    if "rejection_message" in payload and payload["rejection_message"] is not None:
        message = str(payload["rejection_message"]).strip()
        if not message:
            raise ValueError("Сообщение отклонения не может быть пустым")
        if len(message) > 200:
            raise ValueError("Сообщение отклонения слишком длинное (макс. 200)")
        updates["GREYLISTING_MESSAGE"] = message
    if "block_expire_minutes" in payload and payload["block_expire_minutes"] is not None:
        minutes = int(payload["block_expire_minutes"])
        if minutes < 1 or minutes > 1440:
            raise ValueError("Задержка перед повтором: от 1 до 1440 минут")
        updates["GREYLISTING_BLOCK_EXPIRE"] = minutes
    if "auth_triplet_expire_days" in payload and payload["auth_triplet_expire_days"] is not None:
        days = int(payload["auth_triplet_expire_days"])
        if days < 1 or days > 365:
            raise ValueError("Запоминание успешных: от 1 до 365 дней")
        updates["GREYLISTING_AUTH_TRIPLET_EXPIRE"] = days
    if "unauth_triplet_expire_days" in payload and payload["unauth_triplet_expire_days"] is not None:
        days = int(payload["unauth_triplet_expire_days"])
        if days < 1 or days > 90:
            raise ValueError("Хранение неуспешных: от 1 до 90 дней")
        updates["GREYLISTING_UNAUTH_TRIPLET_EXPIRE"] = days
    if "bypass_spf" in payload and payload["bypass_spf"] is not None:
        updates["GREYLISTING_BYPASS_SPF"] = bool(payload["bypass_spf"])
    if not updates:
        raise ValueError("Нет полей для обновления")
    path = _upsert_settings(updates)
    _restart_iredapd()
    timing = read_greylisting_timing()
    timing["settings_file"] = str(path)
    return timing


def _allowed_ips_from_rules(rules: list[dict[str, Any]]) -> list[str]:
    result: list[str] = []
    for rule in rules:
        if rule.get("action") != "disabled":
            continue
        from_addr = str(rule.get("from_addr") or "").strip().lower()
        if _looks_like_ip(from_addr):
            result.append(from_addr)
    return sorted(set(result))


def list_allowed_ips(rules: list[dict[str, Any]] | None = None, whitelist_addresses: list[str] | None = None) -> list[str]:
    if rules is None:
        rules = _parse_settings_table(iredapd.list_greylisting())
    if whitelist_addresses is None:
        whitelist_addresses = _parse_whitelist_addresses(iredapd.list_greylisting_whitelists())
    combined = set(_allowed_ips_from_rules(rules))
    for item in whitelist_addresses:
        if _looks_like_ip(item):
            combined.add(item.strip().lower())
    return sorted(combined)


def add_allowed_ip(ip: str) -> None:
    value = normalize_ip_or_cidr(ip)
    # Официальный способ iRedMail: отключить greylist для IP
    iredapd.greylisting_disable("@.", value)


def remove_allowed_ip(ip: str) -> None:
    value = normalize_ip_or_cidr(ip)
    errors: list[str] = []
    try:
        iredapd.greylisting_delete("@.", value)
    except Exception as exc:
        errors.append(str(exc))
    removed_sql = _delete_greylist_whitelist_sender(value)
    if not removed_sql and errors:
        raise RuntimeError(
            f"Не удалось удалить {value}. "
            + "; ".join(errors)
        )


def _read_iredapd_db_settings() -> dict[str, Any] | None:
    path = None
    for candidate in IREDAPD_SETTINGS_CANDIDATES:
        if candidate.is_file():
            path = candidate
            break
    if not path:
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    keys = {
        "host": ("iredapd_db_server", "vmail_db_server"),
        "port": ("iredapd_db_port", "vmail_db_port"),
        "user": ("iredapd_db_user",),
        "password": ("iredapd_db_password",),
        "database": ("iredapd_db_name",),
    }
    found: dict[str, Any] = {}
    for target, names in keys.items():
        for name in names:
            match = re.search(rf"^{name}\s*=\s*(.+?)\s*(?:#.*)?$", text, flags=re.M)
            if not match:
                continue
            found[target] = _parse_setting_value(match.group(1))
            break
    if "user" not in found or "password" not in found:
        return None
    found.setdefault("host", "127.0.0.1")
    found.setdefault("port", 3306)
    found.setdefault("database", "iredapd")
    try:
        found["port"] = int(found["port"])
    except (TypeError, ValueError):
        found["port"] = 3306
    return found


def _delete_greylist_whitelist_sender(sender: str) -> bool:
    cfg = _read_iredapd_db_settings()
    if not cfg:
        return False
    removed = False
    try:
        conn = pymysql.connect(
            host=str(cfg["host"]),
            port=int(cfg["port"]),
            user=str(cfg["user"]),
            password=str(cfg["password"]),
            database=str(cfg["database"]),
            charset="utf8mb4",
            cursorclass=DictCursor,
            autocommit=True,
        )
    except Exception:
        return False
    try:
        with conn.cursor() as cur:
            for table in ("greylisting_whitelists", "greylisting_whitelist_domain_spf"):
                try:
                    cur.execute(f"DELETE FROM {table} WHERE LOWER(sender) = LOWER(%s)", (sender,))
                    if cur.rowcount:
                        removed = True
                except Exception:
                    continue
    finally:
        conn.close()
    return removed


def list_banned_ips() -> list[dict[str, str]]:
    entries = iredapd.list_wblist("blacklist")
    result: list[dict[str, str]] = []
    for item in entries:
        address = str(item.get("address") or item.get("email") or "").strip().lower()
        if not address or not _looks_like_ip(address):
            continue
        result.append(
            {
                "address": address,
                "comment": str(item.get("comment") or ""),
            }
        )
    result.sort(key=lambda row: row["address"])
    return result


def add_banned_ip(ip: str, comment: str = "") -> None:
    value = normalize_ip_or_cidr(ip)
    iredapd.add_wblist("blacklist", [value], None, comment=comment or None)


def remove_banned_ip(ip: str) -> None:
    value = normalize_ip_or_cidr(ip)
    iredapd.delete_wblist("blacklist", [value], None)


def get_greylisting_overview() -> dict[str, Any]:
    settings_raw = iredapd.list_greylisting()
    domains_raw = iredapd.list_greylisting_whitelist_domains()
    whitelists_raw = iredapd.list_greylisting_whitelists()
    rules = _parse_settings_table(settings_raw)
    whitelist_domains = _parse_whitelist_domains(domains_raw)
    whitelist_addresses = _parse_whitelist_addresses(whitelists_raw)
    allowed_ips = list_allowed_ips(rules, whitelist_addresses)
    try:
        banned_ips = list_banned_ips()
    except Exception:
        banned_ips = []
    timing = read_greylisting_timing()
    try:
        stats = greylisting_stats()
    except Exception:
        stats = {
            "hours": 24,
            "rejections": 0,
            "top_senders": [],
            "recent": [],
        }
    return {
        "global_enabled": _infer_global_enabled(rules),
        "timing": timing,
        "rules": rules,
        "whitelist_domains": whitelist_domains,
        "whitelist_addresses": whitelist_addresses,
        "allowed_ips": allowed_ips,
        "banned_ips": banned_ips,
        "stats": stats,
        "raw": {
            "settings": settings_raw,
            "whitelist_domains": domains_raw,
            "whitelist_addresses": whitelists_raw,
        },
        "notes": [
            "Greylisting откладывает первую попытку доставки; легитимные серверы повторяют отправку.",
            "Разрешённые IP — обход greylist (письмо принимается без задержки).",
            "Забаненные IP — чёрный список iRedAPD/Amavis: письма с этих адресов отклоняются.",
            "Домены в SPF-whitelist пропускаются без задержки после обновления IP из DNS.",
            f"Повторная доставка разрешена не ранее чем через {timing['block_expire_minutes']} мин.",
            f"Успешные отправители запоминаются на {timing['auth_triplet_expire_days']} дн.",
        ],
    }
