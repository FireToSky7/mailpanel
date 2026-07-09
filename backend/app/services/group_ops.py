from __future__ import annotations

from typing import Any

from app.database import execute, fetch_all, fetch_one, panel_conn, vmail_conn


def _ensure_groups_table() -> None:
    with panel_conn() as conn:
        execute(
            conn,
            "CREATE TABLE IF NOT EXISTS mail_groups ("
            "address VARCHAR(255) PRIMARY KEY, "
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
            ")",
        )


def _dest_domain(email: str) -> str:
    return email.lower().split("@", 1)[1]


def _group_addresses(domain: str | None = None) -> set[str]:
    _ensure_groups_table()
    with panel_conn() as conn:
        if domain:
            rows = fetch_all(
                conn,
                "SELECT address FROM mail_groups WHERE LOWER(address) LIKE %s",
                (f"%@{domain.lower()}",),
            )
        else:
            rows = fetch_all(conn, "SELECT address FROM mail_groups")
    return {row["address"].lower() for row in rows}


def is_group_address(address: str) -> bool:
    _ensure_groups_table()
    with panel_conn() as conn:
        row = fetch_one(
            conn,
            "SELECT address FROM mail_groups WHERE LOWER(address) = LOWER(%s)",
            (address,),
        )
    return bool(row)


def list_groups(domain: str | None = None) -> list[dict[str, Any]]:
    _ensure_groups_table()
    group_addrs = _group_addresses(domain)
    if not group_addrs:
        return []

    placeholders = ", ".join(["%s"] * len(group_addrs))
    query = (
        "SELECT a.address, "
        "GROUP_CONCAT(f.forwarding ORDER BY f.forwarding SEPARATOR ', ') AS members, "
        "a.domain, a.active "
        "FROM alias a "
        "LEFT JOIN forwardings f ON f.address = a.address AND f.is_list = 1 "
        f"WHERE LOWER(a.address) IN ({placeholders}) "
        "GROUP BY a.address, a.domain, a.active "
        "ORDER BY a.address"
    )
    with vmail_conn() as conn:
        return fetch_all(conn, query, tuple(group_addrs))


def _read_group_members(conn, address: str) -> list[str]:
    rows = fetch_all(
        conn,
        "SELECT forwarding FROM forwardings WHERE LOWER(address) = LOWER(%s) AND is_list = 1",
        (address,),
    )
    return sorted({str(row["forwarding"]).strip().lower() for row in rows if row.get("forwarding")})


def _validate_members(conn, members: list[str]) -> list[str]:
    clean = sorted({member.lower().strip() for member in members if member.strip()})
    if not clean:
        raise ValueError("Добавьте хотя бы одного участника")
    for member in clean:
        if not fetch_one(
            conn,
            "SELECT username FROM mailbox WHERE LOWER(username) = LOWER(%s) AND active = 1",
            (member,),
        ):
            raise ValueError(f"Ящик не найден или неактивен: {member}")
    return clean


def _write_group_members(conn, address: str, members: list[str]) -> None:
    domain = _dest_domain(address)
    execute(conn, "DELETE FROM forwardings WHERE LOWER(address) = LOWER(%s) AND is_list = 1", (address,))
    for member in members:
        dest_domain = _dest_domain(member)
        execute(
            conn,
            "INSERT INTO forwardings (address, forwarding, domain, dest_domain, is_list, active) "
            "VALUES (%s, %s, %s, %s, 1, 1)",
            (address, member, domain, dest_domain),
        )


def create_group(address: str, members: list[str]) -> None:
    address = address.lower().strip()
    domain = _dest_domain(address)
    _ensure_groups_table()

    with vmail_conn() as conn:
        if fetch_one(conn, "SELECT address FROM alias WHERE LOWER(address) = LOWER(%s)", (address,)):
            raise ValueError(f"Адрес уже существует: {address}")
        if fetch_one(conn, "SELECT username FROM mailbox WHERE LOWER(username) = LOWER(%s)", (address,)):
            raise ValueError(f"Этот адрес уже занят ящиком: {address}")
        clean_members = _validate_members(conn, members)
        execute(conn, "INSERT INTO alias (address, domain, active) VALUES (%s, %s, 1)", (address, domain))
        _write_group_members(conn, address, clean_members)

    with panel_conn() as conn:
        execute(conn, "INSERT INTO mail_groups (address) VALUES (%s)", (address,))


def delete_group(address: str) -> None:
    address = address.lower().strip()
    if not is_group_address(address):
        raise ValueError(f"Группа не найдена: {address}")

    with vmail_conn() as conn:
        execute(conn, "DELETE FROM forwardings WHERE LOWER(address) = LOWER(%s)", (address,))
        execute(conn, "DELETE FROM alias WHERE LOWER(address) = LOWER(%s)", (address,))

    with panel_conn() as conn:
        execute(conn, "DELETE FROM mail_groups WHERE LOWER(address) = LOWER(%s)", (address,))


def add_group_member(address: str, member: str) -> list[str]:
    address = address.lower().strip()
    member = member.lower().strip()
    if not is_group_address(address):
        raise ValueError(f"Группа не найдена: {address}")

    with vmail_conn() as conn:
        _validate_members(conn, [member])
        members = _read_group_members(conn, address)
        if member in members:
            raise ValueError(f"Участник уже в группе: {member}")
        members.append(member)
        _write_group_members(conn, address, members)
        return members


def remove_group_member(address: str, member: str) -> list[str]:
    address = address.lower().strip()
    member = member.lower().strip()
    if not is_group_address(address):
        raise ValueError(f"Группа не найдена: {address}")

    with vmail_conn() as conn:
        members = _read_group_members(conn, address)
        if member not in members:
            raise ValueError(f"Участник не найден в группе: {member}")
        if len(members) <= 1:
            raise ValueError("В группе должен остаться хотя бы один участник")
        members = [item for item in members if item != member]
        _write_group_members(conn, address, members)
        return members
