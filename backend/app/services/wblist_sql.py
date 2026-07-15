from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from app.config import get_config
from app.database import amavisd_conn, execute, fetch_all, fetch_one

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
IP_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+")

MAILADDR_PRIORITIES = {
    "email": 10,
    "ip": 9,
    "domain": 5,
    "subdomain": 3,
    "catchall": 0,
}

COMMENT_MAX_LEN = 200


def classify_address(addr: str) -> str:
    addr = addr.strip().lower()
    if addr == "@.":
        return "catchall"
    if EMAIL_RE.match(addr):
        return "email"
    if IP_RE.match(addr):
        return "ip"
    if addr.startswith("@."):
        return "subdomain"
    if addr.startswith("@"):
        return "domain"
    return ""


def normalize_wblist_account(account: str | None) -> str:
    if not account or not account.strip():
        return "@."
    account = account.strip().lower()
    if account == "@.":
        return "@."
    if account.startswith("@."):
        return account
    if account.startswith("@"):
        return account
    return f"@{account}"


def _comments_path() -> Path:
    default = Path("/etc/mailpanel/wblist_comments.yaml")
    return Path(getattr(get_config().paths, "wblist_comments_file", str(default)))


def _normalize_comment(comment: str | None) -> str:
    text = (comment or "").strip()
    if len(text) > COMMENT_MAX_LEN:
        raise ValueError(f"Комментарий слишком длинный (макс. {COMMENT_MAX_LEN} символов)")
    return text


def _read_comments_file() -> dict[str, dict[str, str]]:
    path = _comments_path()
    if not path.exists():
        return {"whitelist": {}, "blacklist": {}}
    data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
    result: dict[str, dict[str, str]] = {"whitelist": {}, "blacklist": {}}
    for list_type in ("whitelist", "blacklist"):
        raw = data.get(list_type) or {}
        if isinstance(raw, dict):
            result[list_type] = {
                str(key).strip().lower(): str(value).strip()
                for key, value in raw.items()
                if str(key).strip() and str(value).strip()
            }
    return result


def _write_comments_file(data: dict[str, dict[str, str]]) -> None:
    path = _comments_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "whitelist": dict(sorted((data.get("whitelist") or {}).items())),
        "blacklist": dict(sorted((data.get("blacklist") or {}).items())),
    }
    path.write_text(
        yaml.safe_dump(payload, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def _set_comment(list_type: str, address: str, comment: str) -> None:
    data = _read_comments_file()
    bucket = data.setdefault(list_type, {})
    key = address.strip().lower()
    if comment:
        bucket[key] = comment
    else:
        bucket.pop(key, None)
    _write_comments_file(data)


def _remove_comments(list_type: str, addresses: list[str]) -> None:
    data = _read_comments_file()
    bucket = data.setdefault(list_type, {})
    changed = False
    for address in addresses:
        key = address.strip().lower()
        if key in bucket:
            del bucket[key]
            changed = True
    if changed:
        _write_comments_file(data)


def _user_ids_for_account(conn, account: str) -> list[int]:
    rows = fetch_all(conn, "SELECT id FROM users WHERE email = %s ORDER BY id", (account,))
    return [int(row["id"]) for row in rows]


def _decode_email(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _ensure_user(conn, account: str) -> int:
    user_ids = _user_ids_for_account(conn, account)
    if len(user_ids) > 1:
        primary_id = user_ids[0]
        for other_id in user_ids[1:]:
            execute(conn, "UPDATE wblist SET rid = %s WHERE rid = %s", (primary_id, other_id))
            execute(conn, "DELETE FROM users WHERE id = %s", (other_id,))
        return primary_id
    if user_ids:
        return user_ids[0]
    addr_type = classify_address(account)
    if not addr_type:
        raise ValueError(f"Некорректный аккаунт списка: {account}")
    priority = MAILADDR_PRIORITIES[addr_type]
    execute(
        conn,
        "INSERT INTO users (policy_id, email, priority) VALUES (0, %s, %s)",
        (account, priority),
    )
    user_ids = _user_ids_for_account(conn, account)
    if not user_ids:
        raise ValueError(f"Не удалось создать аккаунт списка: {account}")
    return user_ids[0]


def _ensure_mailaddr(conn, address: str) -> int:
    row = fetch_one(conn, "SELECT id FROM mailaddr WHERE email = %s LIMIT 1", (address,))
    if row:
        return int(row["id"])
    addr_type = classify_address(address)
    if not addr_type:
        raise ValueError(f"Некорректный адрес: {address}")
    priority = MAILADDR_PRIORITIES[addr_type]
    execute(
        conn,
        "INSERT INTO mailaddr (email, priority) VALUES (%s, %s)",
        (address, priority),
    )
    row = fetch_one(conn, "SELECT id FROM mailaddr WHERE email = %s LIMIT 1", (address,))
    if not row:
        raise ValueError(f"Не удалось добавить адрес: {address}")
    return int(row["id"])


def list_wblist(list_type: str, account: str | None = None) -> list[dict[str, str]]:
    wb_flag = "W" if list_type == "whitelist" else "B"
    wb_account = normalize_wblist_account(account)
    comments = _read_comments_file().get(list_type, {})
    with amavisd_conn() as conn:
        user_ids = _user_ids_for_account(conn, wb_account)
        if not user_ids:
            return []
        placeholders = ", ".join(["%s"] * len(user_ids))
        rows = fetch_all(
            conn,
            f"SELECT DISTINCT m.email "
            f"FROM wblist w "
            f"JOIN mailaddr m ON w.sid = m.id "
            f"WHERE w.rid IN ({placeholders}) AND w.wb = %s "
            f"ORDER BY m.email",
            (*user_ids, wb_flag),
        )
    result: list[dict[str, str]] = []
    for row in rows:
        address = _decode_email(row["email"])
        result.append(
            {
                "address": address,
                "comment": comments.get(address.strip().lower(), ""),
            }
        )
    return result


def add_wblist(
    list_type: str,
    senders: list[str],
    account: str | None = None,
    comment: str | None = None,
) -> None:
    wb_flag = "W" if list_type == "whitelist" else "B"
    opposite_flag = "B" if wb_flag == "W" else "W"
    opposite_label = "чёрном" if list_type == "whitelist" else "белом"
    same_label = "белом" if list_type == "whitelist" else "чёрном"
    wb_account = normalize_wblist_account(account)
    normalized = [s.strip().lower() for s in senders if s.strip()]
    if not normalized:
        raise ValueError("Укажите запись для добавления в список")
    normalized_comment = _normalize_comment(comment)

    with amavisd_conn() as conn:
        user_id = _ensure_user(conn, wb_account)
        for sender in normalized:
            if not classify_address(sender):
                raise ValueError(f"Некорректный адрес: {sender}")
            sender_id = _ensure_mailaddr(conn, sender)
            opposite = fetch_one(
                conn,
                "SELECT 1 FROM wblist WHERE rid = %s AND sid = %s AND wb = %s LIMIT 1",
                (user_id, sender_id, opposite_flag),
            )
            if opposite:
                raise ValueError(
                    f"«{sender}» уже в {opposite_label} списке. Сначала удалите запись оттуда."
                )
            existing = fetch_one(
                conn,
                "SELECT 1 FROM wblist WHERE rid = %s AND sid = %s AND wb = %s LIMIT 1",
                (user_id, sender_id, wb_flag),
            )
            if existing:
                raise ValueError(f"«{sender}» уже в {same_label} списке.")
            execute(
                conn,
                "INSERT INTO wblist (rid, sid, wb) VALUES (%s, %s, %s)",
                (user_id, sender_id, wb_flag),
            )

    for sender in normalized:
        _set_comment(list_type, sender, normalized_comment)


def delete_wblist(list_type: str, senders: list[str], account: str | None = None) -> None:
    wb_flag = "W" if list_type == "whitelist" else "B"
    wb_account = normalize_wblist_account(account)
    normalized = [s.strip().lower() for s in senders if s.strip()]
    if not normalized:
        raise ValueError("Укажите запись для удаления")

    with amavisd_conn() as conn:
        user_id = _ensure_user(conn, wb_account)
        for sender in normalized:
            row = fetch_one(conn, "SELECT id FROM mailaddr WHERE email = %s LIMIT 1", (sender,))
            if not row:
                continue
            execute(
                conn,
                "DELETE FROM wblist WHERE rid = %s AND sid = %s AND wb = %s",
                (user_id, int(row["id"]), wb_flag),
            )
    _remove_comments(list_type, normalized)
