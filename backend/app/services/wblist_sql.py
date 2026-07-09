from __future__ import annotations

import re
from typing import Any

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


def list_wblist(list_type: str, account: str | None = None) -> list[str]:
    wb_flag = "W" if list_type == "whitelist" else "B"
    wb_account = normalize_wblist_account(account)
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
    return [_decode_email(row["email"]) for row in rows]


def add_wblist(list_type: str, senders: list[str], account: str | None = None) -> None:
    wb_flag = "W" if list_type == "whitelist" else "B"
    wb_account = normalize_wblist_account(account)
    normalized = [s.strip().lower() for s in senders if s.strip()]
    if not normalized:
        raise ValueError("Укажите запись для добавления в список")

    with amavisd_conn() as conn:
        user_id = _ensure_user(conn, wb_account)
        for sender in normalized:
            if not classify_address(sender):
                raise ValueError(f"Некорректный адрес: {sender}")
            sender_id = _ensure_mailaddr(conn, sender)
            execute(
                conn,
                "DELETE FROM wblist WHERE rid = %s AND sid = %s AND wb = %s",
                (user_id, sender_id, wb_flag),
            )
            execute(
                conn,
                "INSERT INTO wblist (rid, sid, wb) VALUES (%s, %s, %s)",
                (user_id, sender_id, wb_flag),
            )


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
