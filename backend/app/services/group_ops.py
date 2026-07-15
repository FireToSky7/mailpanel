from __future__ import annotations

from typing import Any

from app.database import execute, fetch_all, fetch_one, panel_conn, vmail_conn

EVERYONE_TOKEN = "everyone"


def _ensure_groups_table() -> None:
    with panel_conn() as conn:
        execute(
            conn,
            "CREATE TABLE IF NOT EXISTS mail_groups ("
            "address VARCHAR(255) PRIMARY KEY, "
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
            ")",
        )
        # Мягкая миграция для существующих установок
        cols = {
            str(row["Field"]).lower()
            for row in fetch_all(conn, "SHOW COLUMNS FROM mail_groups")
        }
        if "include_everyone" not in cols:
            execute(
                conn,
                "ALTER TABLE mail_groups "
                "ADD COLUMN include_everyone TINYINT(1) NOT NULL DEFAULT 0",
            )


def _dest_domain(email: str) -> str:
    return email.lower().split("@", 1)[1]


def _is_everyone_token(value: str, domain: str | None = None) -> bool:
    token = value.strip().lower()
    if token == EVERYONE_TOKEN:
        return True
    if domain and token == f"{EVERYONE_TOKEN}@{domain.lower()}":
        return True
    return False


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


def _get_group_meta(address: str) -> dict[str, Any] | None:
    _ensure_groups_table()
    with panel_conn() as conn:
        return fetch_one(
            conn,
            "SELECT address, include_everyone FROM mail_groups WHERE LOWER(address) = LOWER(%s)",
            (address,),
        )


def _domain_mailboxes(conn, domain: str) -> list[str]:
    rows = fetch_all(
        conn,
        "SELECT username FROM mailbox WHERE LOWER(domain) = LOWER(%s) AND active = 1 "
        "ORDER BY username",
        (domain.lower(),),
    )
    return [str(row["username"]).strip().lower() for row in rows]


def _read_group_members(conn, address: str) -> list[str]:
    rows = fetch_all(
        conn,
        "SELECT forwarding FROM forwardings WHERE LOWER(address) = LOWER(%s) AND is_list = 1",
        (address,),
    )
    return sorted({str(row["forwarding"]).strip().lower() for row in rows if row.get("forwarding")})


def _validate_members(conn, members: list[str], *, allow_empty: bool = False) -> list[str]:
    clean = sorted({member.lower().strip() for member in members if member.strip()})
    if not clean and not allow_empty:
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


def _set_access_policy(conn, address: str, domain_only: bool) -> None:
    # iRedAPD sql_alias_access_policy: domain = только ящики того же домена
    policy = "domain" if domain_only else ""
    execute(
        conn,
        "UPDATE alias SET accesspolicy = %s WHERE LOWER(address) = LOWER(%s)",
        (policy, address),
    )


def _parse_member_tokens(raw_members: list[str], domain: str) -> tuple[list[str], bool]:
    """Разделить обычные email и токен everyone."""
    emails: list[str] = []
    include_everyone = False
    for item in raw_members:
        value = item.strip().lower()
        if not value:
            continue
        if _is_everyone_token(value, domain):
            include_everyone = True
            continue
        emails.append(value)
    return emails, include_everyone


def _resolve_members(conn, domain: str, emails: list[str], include_everyone: bool) -> list[str]:
    if include_everyone:
        resolved = _domain_mailboxes(conn, domain)
        if not resolved:
            raise ValueError("В домене нет активных ящиков для токена everyone")
        return resolved
    return _validate_members(conn, emails)


def list_groups(domain: str | None = None) -> list[dict[str, Any]]:
    _ensure_groups_table()
    group_addrs = _group_addresses(domain)
    if not group_addrs:
        return []

    with panel_conn() as conn:
        meta_rows = fetch_all(
            conn,
            "SELECT address, include_everyone FROM mail_groups",
        )
    meta = {
        str(row["address"]).lower(): bool(row.get("include_everyone"))
        for row in meta_rows
    }

    placeholders = ", ".join(["%s"] * len(group_addrs))
    query = (
        "SELECT a.address, a.domain, a.active, "
        "COALESCE(a.accesspolicy, '') AS accesspolicy, "
        "GROUP_CONCAT(f.forwarding ORDER BY f.forwarding SEPARATOR ', ') AS members "
        "FROM alias a "
        "LEFT JOIN forwardings f ON f.address = a.address AND f.is_list = 1 "
        f"WHERE LOWER(a.address) IN ({placeholders}) "
        "GROUP BY a.address, a.domain, a.active, a.accesspolicy "
        "ORDER BY a.address"
    )
    with vmail_conn() as conn:
        rows = fetch_all(conn, query, tuple(group_addrs))

    result: list[dict[str, Any]] = []
    for row in rows:
        address = str(row["address"]).lower()
        include_everyone = meta.get(address, False)
        accesspolicy = str(row.get("accesspolicy") or "").strip().lower()
        # domain / membersonly (старое значение панели) — ограничение включено
        domain_only = accesspolicy in ("domain", "membersonly")
        members_display = row.get("members") or ""
        if include_everyone:
            members_display = EVERYONE_TOKEN
            concrete = row.get("members") or ""
            if concrete:
                members_display = f"{EVERYONE_TOKEN} ({concrete})"
        result.append(
            {
                "address": row["address"],
                "domain": row["domain"],
                "active": row["active"],
                "members": members_display,
                "include_everyone": include_everyone,
                "domain_only": domain_only,
                "members_only": domain_only,  # совместимость со старым фронтом
                "accesspolicy": accesspolicy,
            }
        )
    return result


def create_group(
    address: str,
    members: list[str],
    *,
    domain_only: bool = False,
    members_only: bool | None = None,
) -> None:
    address = address.lower().strip()
    domain = _dest_domain(address)
    _ensure_groups_table()
    emails, include_everyone = _parse_member_tokens(members, domain)
    if members_only is not None:
        domain_only = members_only

    with vmail_conn() as conn:
        if fetch_one(conn, "SELECT address FROM alias WHERE LOWER(address) = LOWER(%s)", (address,)):
            raise ValueError(f"Адрес уже существует: {address}")
        if fetch_one(conn, "SELECT username FROM mailbox WHERE LOWER(username) = LOWER(%s)", (address,)):
            raise ValueError(f"Этот адрес уже занят ящиком: {address}")
        clean_members = _resolve_members(conn, domain, emails, include_everyone)
        execute(
            conn,
            "INSERT INTO alias (address, domain, active, accesspolicy) VALUES (%s, %s, 1, %s)",
            (address, domain, "domain" if domain_only else ""),
        )
        _write_group_members(conn, address, clean_members)

    with panel_conn() as conn:
        execute(
            conn,
            "INSERT INTO mail_groups (address, include_everyone) VALUES (%s, %s)",
            (address, 1 if include_everyone else 0),
        )


def delete_group(address: str) -> None:
    address = address.lower().strip()
    if not is_group_address(address):
        raise ValueError(f"Группа не найдена: {address}")

    with vmail_conn() as conn:
        execute(conn, "DELETE FROM forwardings WHERE LOWER(address) = LOWER(%s)", (address,))
        execute(conn, "DELETE FROM alias WHERE LOWER(address) = LOWER(%s)", (address,))

    with panel_conn() as conn:
        execute(conn, "DELETE FROM mail_groups WHERE LOWER(address) = LOWER(%s)", (address,))


def update_group_domain_only(address: str, domain_only: bool) -> dict[str, Any]:
    address = address.lower().strip()
    if not is_group_address(address):
        raise ValueError(f"Группа не найдена: {address}")
    with vmail_conn() as conn:
        _set_access_policy(conn, address, domain_only)
        row = fetch_one(
            conn,
            "SELECT accesspolicy FROM alias WHERE LOWER(address) = LOWER(%s)",
            (address,),
        )
    policy = str((row or {}).get("accesspolicy") or "").strip().lower()
    if domain_only and policy != "domain":
        raise ValueError(
            "Не удалось записать accesspolicy=domain в alias. "
            "Проверьте таблицу vmail.alias и права БД."
        )
    return {"address": address, "domain_only": domain_only, "members_only": domain_only}


def update_group_members_only(address: str, members_only: bool) -> dict[str, Any]:
    """Совместимость со старым API."""
    return update_group_domain_only(address, members_only)


def add_group_member(address: str, member: str) -> list[str]:
    address = address.lower().strip()
    member = member.lower().strip()
    meta = _get_group_meta(address)
    if not meta:
        raise ValueError(f"Группа не найдена: {address}")

    domain = _dest_domain(address)
    if _is_everyone_token(member, domain):
        with panel_conn() as conn:
            execute(
                conn,
                "UPDATE mail_groups SET include_everyone = 1 WHERE LOWER(address) = LOWER(%s)",
                (address,),
            )
        with vmail_conn() as conn:
            members = _resolve_members(conn, domain, [], True)
            _write_group_members(conn, address, members)
            return members

    with vmail_conn() as conn:
        if meta.get("include_everyone"):
            raise ValueError(
                "Группа уже включает всех (everyone). Отдельных участников добавлять не нужно — "
                "новые ящики попадут автоматически."
            )
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
    meta = _get_group_meta(address)
    if not meta:
        raise ValueError(f"Группа не найдена: {address}")

    domain = _dest_domain(address)
    if _is_everyone_token(member, domain) or (
        meta.get("include_everyone") and member == EVERYONE_TOKEN
    ):
        raise ValueError(
            "Нельзя убрать everyone поштучно. Удалите группу или создайте новую без everyone."
        )

    with vmail_conn() as conn:
        if meta.get("include_everyone"):
            raise ValueError(
                "Группа с everyone синхронизируется со всеми ящиками. "
                "Чтобы исключить кого-то, уберите everyone и задайте явный список."
            )
        members = _read_group_members(conn, address)
        if member not in members:
            raise ValueError(f"Участник не найден в группе: {member}")
        if len(members) <= 1:
            raise ValueError("В группе должен остаться хотя бы один участник")
        members = [item for item in members if item != member]
        _write_group_members(conn, address, members)
        return members


def sync_everyone_groups(domain: str | None = None) -> int:
    """Пересобрать forwardings для групп с include_everyone=1 (после создания/удаления ящика)."""
    _ensure_groups_table()
    with panel_conn() as conn:
        if domain:
            rows = fetch_all(
                conn,
                "SELECT address FROM mail_groups "
                "WHERE include_everyone = 1 AND LOWER(address) LIKE %s",
                (f"%@{domain.lower()}",),
            )
        else:
            rows = fetch_all(
                conn,
                "SELECT address FROM mail_groups WHERE include_everyone = 1",
            )
    updated = 0
    with vmail_conn() as conn:
        for row in rows:
            address = str(row["address"]).lower()
            group_domain = _dest_domain(address)
            members = _domain_mailboxes(conn, group_domain)
            if members:
                _write_group_members(conn, address, members)
                updated += 1
    return updated
