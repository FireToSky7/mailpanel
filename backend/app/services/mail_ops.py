from __future__ import annotations

import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from app.auth import PanelUser, hash_password
from app.config import Role, get_config
from app.database import amavisd_conn, execute, fetch_all, fetch_one, panel_conn, vmail_conn
from app.services.iredapd import hash_mailbox_password


def list_panel_users() -> list[dict[str, Any]]:
    with panel_conn() as conn:
        return fetch_all(
            conn,
            "SELECT id, username, role, mailbox, display_name, active, created_at "
            "FROM panel_users ORDER BY username",
        )


def create_panel_user(
    username: str,
    password: str,
    role: Role,
    display_name: str = "",
    mailbox: str | None = None,
) -> None:
    if role == Role.USER and not mailbox:
        raise ValueError("User role requires linked mailbox email")
    with panel_conn() as conn:
        execute(
            conn,
            "INSERT INTO panel_users (username, password_hash, role, mailbox, display_name) "
            "VALUES (%s, %s, %s, %s, %s)",
            (username, hash_password(password), role.value, mailbox, display_name or username),
        )


def update_panel_user_password(user_id: int, password: str) -> None:
    with panel_conn() as conn:
        execute(
            conn,
            "UPDATE panel_users SET password_hash = %s WHERE id = %s",
            (hash_password(password), user_id),
        )


def delete_panel_user(user_id: int) -> None:
    with panel_conn() as conn:
        execute(conn, "DELETE FROM panel_users WHERE id = %s", (user_id,))


STORAGE_BASE_DIRECTORY = "/var/vmail/vmail1"
CREATE_MAIL_USER_SCRIPT_CANDIDATES: tuple[str, ...] = (
    "/opt/www/iredadmin/tools/create_mail_user_SQL.sh",
    "/var/www/iredadmin/tools/create_mail_user_SQL.sh",
    "/usr/share/apache2/iredadmin/tools/create_mail_user_SQL.sh",
)


def _find_create_mail_user_script() -> Path | None:
    for path_str in CREATE_MAIL_USER_SCRIPT_CANDIDATES:
        path = Path(path_str)
        if path.is_file():
            return path
    for path in Path("/root").glob("iRedMail*/tools/create_mail_user_SQL.sh"):
        if path.is_file():
            return path
    return None


def _storage_paths() -> tuple[str, str]:
    base_dir = Path(STORAGE_BASE_DIRECTORY)
    return str(base_dir.parent), base_dir.name


def _iredmail_maildir(local: str, domain: str) -> str:
    """Same layout as iRedMail tools/create_mail_user_SQL.sh (hashed style)."""
    date = datetime.now().strftime("%Y.%m.%d.%H.%M.%S")
    str1 = local[0]
    str2 = local[1] if len(local) > 1 else str1
    str3 = local[2] if len(local) > 2 else str2
    return f"{domain}/{str1}/{str2}/{str3}/{local}-{date}/"


def _run_generated_mail_user_sql(sql: str) -> None:
    statements = [part.strip() for part in sql.split(";") if part.strip()]
    with vmail_conn() as conn:
        for statement in statements:
            execute(conn, statement)


def _create_mailbox_via_script(script: Path, username: str, password: str, name: str, quota: int) -> None:
    result = subprocess.run(
        ["bash", str(script), username.lower(), password],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "create_mail_user_SQL.sh failed")
    _run_generated_mail_user_sql(result.stdout)
    with vmail_conn() as conn:
        execute(
            conn,
            "UPDATE mailbox SET name = %s, quota = %s, passwordlastchange = NOW() WHERE username = %s",
            (name, quota, username.lower()),
        )


def mailbox_exists(username: str) -> bool:
    email = username.lower()
    with vmail_conn() as conn:
        return fetch_one(conn, "SELECT username FROM mailbox WHERE username = %s", (email,)) is not None


def list_mailboxes(domain: str | None = None) -> list[dict[str, Any]]:
    query = (
        "SELECT m.username, m.name, m.domain, m.quota, m.active, m.created, m.modified, "
        "COALESCE(u.bytes, 0) AS bytes_used, COALESCE(u.messages, 0) AS messages "
        "FROM mailbox m "
        "LEFT JOIN used_quota u ON m.username = u.username"
    )
    params: tuple[Any, ...] = ()
    if domain:
        query += " WHERE m.domain = %s"
        params = (domain.lower(),)
    query += " ORDER BY m.username"
    with vmail_conn() as conn:
        rows = fetch_all(conn, query, params)
    for row in rows:
        bytes_used = int(row.get("bytes_used") or 0)
        row["used_mb"] = round(bytes_used / (1024 * 1024), 1)
    return rows


def create_mailbox(username: str, password: str, name: str, quota: int = 1024) -> None:
    email = username.lower()
    if mailbox_exists(email):
        raise ValueError(f"Ящик уже существует: {email}")
    if fetch_alias_address(email):
        raise ValueError(f"Этот адрес уже занят алиасом: {email}")

    script = _find_create_mail_user_script()
    if script:
        _create_mailbox_via_script(script, email, password, name, quota)
        return

    local, domain = email.split("@", 1)
    maildir = _iredmail_maildir(local, domain)
    hashed = hash_mailbox_password(password)
    storage_base, storage_node = _storage_paths()
    with vmail_conn() as conn:
        execute(
            conn,
            "INSERT INTO mailbox ("
            "username, password, name, storagebasedirectory, storagenode, maildir, "
            "quota, domain, mailboxformat, mailboxfolder, active, passwordlastchange, created"
            ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'maildir', 'Maildir', 1, NOW(), NOW())",
            (email, hashed, name, storage_base, storage_node, maildir, quota, domain),
        )
        execute(
            conn,
            "INSERT INTO forwardings (address, forwarding, domain, dest_domain, is_forwarding, active) "
            "VALUES (%s, %s, %s, %s, 1, 1)",
            (email, email, domain, domain),
        )


def update_mailbox_quota(username: str, quota: int) -> None:
    email = username.lower()
    if quota < 0:
        raise ValueError("Квота не может быть отрицательной")
    with vmail_conn() as conn:
        if not fetch_one(conn, "SELECT username FROM mailbox WHERE username = %s", (email,)):
            raise ValueError(f"Ящик не найден: {email}")
        execute(conn, "UPDATE mailbox SET quota = %s WHERE username = %s", (quota, email))


def update_mailbox_active(username: str, active: bool) -> None:
    email = username.lower()
    flag = 1 if active else 0
    with vmail_conn() as conn:
        if not fetch_one(conn, "SELECT username FROM mailbox WHERE username = %s", (email,)):
            raise ValueError(f"Ящик не найден: {email}")
        execute(conn, "UPDATE mailbox SET active = %s WHERE username = %s", (flag, email))
        execute(conn, "UPDATE forwardings SET active = %s WHERE address = %s", (flag, email))


def fetch_alias_address(address: str) -> bool:
    with vmail_conn() as conn:
        return fetch_one(conn, "SELECT address FROM alias WHERE address = %s", (address.lower(),)) is not None


def delete_mailbox(username: str) -> None:
    email = username.lower()
    with vmail_conn() as conn:
        execute(conn, "DELETE FROM forwardings WHERE address = %s", (email,))
        execute(conn, "DELETE FROM mailbox WHERE username = %s", (email,))


def update_mailbox_password(username: str, password: str) -> None:
    hashed = hash_mailbox_password(password)
    with vmail_conn() as conn:
        execute(conn, "UPDATE mailbox SET password = %s WHERE username = %s", (hashed, username.lower()))


def _dest_domain(email: str) -> str:
    return email.lower().split("@", 1)[1]


def list_aliases(domain: str | None = None) -> list[dict[str, Any]]:
    query = (
        "SELECT a.address, "
        "GROUP_CONCAT(f.forwarding ORDER BY f.forwarding SEPARATOR ', ') AS goto, "
        "a.domain, a.active "
        "FROM alias a "
        "LEFT JOIN forwardings f ON f.address = a.address AND f.is_list = 1 "
    )
    params: tuple[Any, ...] = ()
    if domain:
        query += " WHERE a.domain = %s"
        params = (domain.lower(),)
    query += " GROUP BY a.address, a.domain, a.active ORDER BY a.address"
    with vmail_conn() as conn:
        return fetch_all(conn, query, params)


def create_alias(address: str, goto: str) -> None:
    address = address.lower()
    goto = goto.lower()
    domain = _dest_domain(address)
    dest_domain = _dest_domain(goto)
    with vmail_conn() as conn:
        if fetch_one(conn, "SELECT address FROM alias WHERE address = %s", (address,)):
            raise ValueError(f"Алиас уже существует: {address}")
        if mailbox_exists(address):
            raise ValueError(f"Этот адрес уже занят ящиком: {address}")
        if not fetch_one(conn, "SELECT username FROM mailbox WHERE username = %s AND active = 1", (goto,)):
            raise ValueError(f"Ящик назначения не найден или неактивен: {goto}")
        execute(conn, "INSERT INTO alias (address, domain, active) VALUES (%s, %s, 1)", (address, domain))
        execute(
            conn,
            "INSERT INTO forwardings (address, forwarding, domain, dest_domain, is_list, active) "
            "VALUES (%s, %s, %s, %s, 1, 1)",
            (address, goto, domain, dest_domain),
        )


def delete_alias(address: str) -> None:
    address = address.lower()
    with vmail_conn() as conn:
        execute(conn, "DELETE FROM forwardings WHERE address = %s", (address,))
        execute(conn, "DELETE FROM alias WHERE address = %s", (address,))


def get_forwarding(username: str) -> str | None:
    username = username.lower()
    with vmail_conn() as conn:
        rows = fetch_all(
            conn,
            "SELECT forwarding FROM forwardings "
            "WHERE address = %s AND is_forwarding = 1 AND forwarding != %s "
            "ORDER BY forwarding",
            (username, username),
        )
    if not rows:
        return None
    return ", ".join(row["forwarding"] for row in rows)


def set_forwarding(username: str, goto: str) -> None:
    username = username.lower()
    goto = goto.lower()
    domain = _dest_domain(username)
    dest_domain = _dest_domain(goto)
    with vmail_conn() as conn:
        execute(
            conn,
            "DELETE FROM forwardings WHERE address = %s AND is_forwarding = 1 AND forwarding != %s",
            (username, username),
        )
        execute(
            conn,
            "INSERT INTO forwardings (address, forwarding, domain, dest_domain, is_forwarding, active) "
            "VALUES (%s, %s, %s, %s, 1, 1)",
            (username, goto, domain, dest_domain),
        )


def clear_forwarding(username: str) -> None:
    username = username.lower()
    with vmail_conn() as conn:
        execute(
            conn,
            "DELETE FROM forwardings WHERE address = %s AND is_forwarding = 1 AND forwarding != %s",
            (username, username),
        )


def dashboard_stats() -> dict[str, Any]:
    domain = get_config().panel.mail_domain
    with vmail_conn() as conn:
        mailboxes = fetch_all(conn, "SELECT COUNT(*) AS cnt FROM mailbox WHERE domain = %s", (domain,))[0]["cnt"]
        aliases = fetch_all(conn, "SELECT COUNT(*) AS cnt FROM alias WHERE domain = %s", (domain,))[0]["cnt"]
    quarantine = 0
    try:
        with amavisd_conn() as conn:
            quarantine = fetch_all(conn, "SELECT COUNT(*) AS cnt FROM quarantine")[0]["cnt"]
    except Exception:
        quarantine = -1
    with panel_conn() as conn:
        audit_today = fetch_all(
            conn,
            "SELECT COUNT(*) AS cnt FROM audit_log WHERE DATE(created_at) = CURDATE()",
        )[0]["cnt"]
    return {
        "domain": domain,
        "mailboxes": mailboxes,
        "aliases": aliases,
        "quarantine": quarantine,
        "audit_today": audit_today,
    }


def list_quarantine(limit: int = 50, recipient: str | None = None) -> list[dict[str, Any]]:
    with amavisd_conn() as conn:
        return fetch_all(
            conn,
            "SELECT id, mail_id, secret_id, time_iso FROM quarantine ORDER BY id DESC LIMIT %s",
            (limit,),
        )


def delete_quarantine_item(item_id: int) -> None:
    with amavisd_conn() as conn:
        execute(conn, "DELETE FROM quarantine WHERE id = %s", (item_id,))


def read_spam_config() -> dict[str, str]:
    path = Path(get_config().paths.spamassassin_config)
    if not path.exists():
        return {"raw": "", "required_score": "5.0"}
    raw = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"^required_score\s+([\d.]+)", raw, re.MULTILINE)
    return {"raw": raw, "required_score": match.group(1) if match else "5.0"}


def write_spam_config(required_score: float, extra_rules: str = "") -> None:
    path = Path(get_config().paths.spamassassin_config)
    lines = ["# Managed by MailPanel", f"required_score {required_score}", ""]
    if extra_rules.strip():
        lines.extend([extra_rules.strip(), ""])
    path.write_text("\n".join(lines), encoding="utf-8")
    subprocess.run(["systemctl", "restart", "amavisd"], check=False)


def service_status(name: str) -> dict[str, str]:
    result = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, check=False)
    return {"name": name, "status": result.stdout.strip() or "unknown"}


def restart_service(name: str) -> dict[str, str]:
    allowed = set(get_config().services)
    if name not in allowed:
        raise ValueError("Service not allowed")
    subprocess.run(["systemctl", "restart", name], check=True)
    return service_status(name)


def fail2ban_status() -> list[dict[str, Any]]:
    jails: list[dict[str, Any]] = []
    result = subprocess.run(["fail2ban-client", "status"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return jails
    jail_names = []
    for line in result.stdout.splitlines():
        if "Jail list:" in line:
            tail = line.split("Jail list:")[-1].strip()
            jail_names = [j.strip() for j in tail.split(",") if j.strip()]
    for jail in jail_names:
        detail = subprocess.run(
            ["fail2ban-client", "status", jail], capture_output=True, text=True, check=False
        )
        banned = []
        for line in detail.stdout.splitlines():
            if "Banned IP list:" in line:
                tail = line.split("Banned IP list:")[-1].strip()
                banned = [ip.strip() for ip in tail.split() if ip.strip()]
        jails.append({"jail": jail, "banned_ips": banned})
    return jails


def fail2ban_unban(jail: str, ip: str) -> None:
    subprocess.run(["fail2ban-client", "set", jail, "unbanip", ip], check=True)


def tail_log_file(path: str, lines: int = 200) -> list[str]:
    file_path = Path(path)
    if not file_path.exists():
        return [f"Log file not found: {path}"]
    content = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return content[-lines:]


def search_logs(
    service: str | None = None,
    query: str | None = None,
    queue_id: str | None = None,
    mail_from: str | None = None,
    mail_to: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    conditions = ["1=1"]
    params: list[Any] = []
    if service:
        conditions.append("service = %s")
        params.append(service)
    if queue_id:
        conditions.append("queue_id = %s")
        params.append(queue_id)
    if mail_from:
        conditions.append("mail_from LIKE %s")
        params.append(f"%{mail_from}%")
    if mail_to:
        conditions.append("mail_to LIKE %s")
        params.append(f"%{mail_to}%")
    if query:
        conditions.append("message LIKE %s")
        params.append(f"%{query}%")
    where = " AND ".join(conditions)
    with panel_conn() as conn:
        total = fetch_all(conn, f"SELECT COUNT(*) AS cnt FROM mail_log_entries WHERE {where}", tuple(params))[0]["cnt"]
        rows = fetch_all(
            conn,
            f"SELECT id, logged_at, service, level, queue_id, mail_from, mail_to, status, "
            f"spam_score, message FROM mail_log_entries WHERE {where} "
            f"ORDER BY logged_at DESC LIMIT %s OFFSET %s",
            tuple(params) + (limit, offset),
        )
    return {"total": total, "items": rows}


def trace_queue_id(queue_id: str) -> list[dict[str, Any]]:
    with panel_conn() as conn:
        return fetch_all(
            conn,
            "SELECT id, logged_at, service, level, queue_id, mail_from, mail_to, status, "
            "spam_score, message FROM mail_log_entries WHERE queue_id = %s ORDER BY logged_at",
            (queue_id,),
        )


def list_audit_log(limit: int = 100) -> list[dict[str, Any]]:
    with panel_conn() as conn:
        return fetch_all(
            conn,
            "SELECT id, username, action, resource, details, ip_address, created_at "
            "FROM audit_log ORDER BY id DESC LIMIT %s",
            (limit,),
        )


def user_wblist_account(user: PanelUser) -> str:
    if user.role != Role.USER:
        raise ValueError("Not a mailbox user")
    if not user.mailbox:
        raise ValueError("Mailbox not linked")
    return user.mailbox
