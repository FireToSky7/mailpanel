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


def list_mailboxes(domain: str | None = None) -> list[dict[str, Any]]:
    query = (
        "SELECT username, name, domain, quota, active, created, modified FROM mailbox"
    )
    params: tuple[Any, ...] = ()
    if domain:
        query += " WHERE domain = %s"
        params = (domain.lower(),)
    query += " ORDER BY username"
    with vmail_conn() as conn:
        return fetch_all(conn, query, params)


def create_mailbox(username: str, password: str, name: str, quota: int = 1024) -> None:
    local, domain = username.lower().split("@", 1)
    maildir = f"{domain}/{local[-1]}/{local[-2:]}/{local}/"
    hashed = hash_mailbox_password(password)
    with vmail_conn() as conn:
        execute(
            conn,
            "INSERT INTO mailbox (username, password, name, maildir, quota, domain, active) "
            "VALUES (%s, %s, %s, %s, %s, %s, 1)",
            (username.lower(), hashed, name, maildir, quota, domain),
        )


def delete_mailbox(username: str) -> None:
    with vmail_conn() as conn:
        execute(conn, "DELETE FROM mailbox WHERE username = %s", (username.lower(),))


def update_mailbox_password(username: str, password: str) -> None:
    hashed = hash_mailbox_password(password)
    with vmail_conn() as conn:
        execute(conn, "UPDATE mailbox SET password = %s WHERE username = %s", (hashed, username.lower()))


def list_aliases(domain: str | None = None) -> list[dict[str, Any]]:
    query = "SELECT address, goto, domain, active FROM alias"
    params: tuple[Any, ...] = ()
    if domain:
        query += " WHERE domain = %s"
        params = (domain.lower(),)
    query += " ORDER BY address"
    with vmail_conn() as conn:
        return fetch_all(conn, query, params)


def create_alias(address: str, goto: str) -> None:
    domain = address.split("@", 1)[1].lower()
    with vmail_conn() as conn:
        execute(
            conn,
            "INSERT INTO alias (address, goto, domain, active) VALUES (%s, %s, %s, 1)",
            (address.lower(), goto.lower(), domain),
        )


def delete_alias(address: str) -> None:
    with vmail_conn() as conn:
        execute(conn, "DELETE FROM alias WHERE address = %s", (address.lower(),))


def get_forwarding(username: str) -> str | None:
    with vmail_conn() as conn:
        row = fetch_one(conn, "SELECT goto FROM alias WHERE address = %s", (username.lower(),))
    return row["goto"] if row else None


def set_forwarding(username: str, goto: str) -> None:
    with vmail_conn() as conn:
        existing = fetch_one(conn, "SELECT address FROM alias WHERE address = %s", (username.lower(),))
        if existing:
            execute(conn, "UPDATE alias SET goto = %s WHERE address = %s", (goto.lower(), username.lower()))
        else:
            domain = username.split("@", 1)[1].lower()
            execute(
                conn,
                "INSERT INTO alias (address, goto, domain, active) VALUES (%s, %s, %s, 1)",
                (username.lower(), goto.lower(), domain),
            )


def clear_forwarding(username: str) -> None:
    with vmail_conn() as conn:
        execute(conn, "DELETE FROM alias WHERE address = %s", (username.lower(),))


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
