from __future__ import annotations

import email
import email.policy
import re
import shutil
import socket
import subprocess
from datetime import datetime
from email.header import decode_header, make_header
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from app.config import get_config
from app.database import amavisd_conn, execute, fetch_all, fetch_one

MAIL_ID_RE = re.compile(r"^[A-Za-z0-9_-]{6,16}$")
AMAVIS_PDP_PORT_RE = re.compile(
    r"\$interface_policy\{'(\d+)'\}\s*=\s*'AM\.PDP",
    re.IGNORECASE,
)

CONTENT_LABELS = {
    "V": "Вирус",
    "B": "Запрещённый файл",
    "S": "Спам",
    "U": "Не проверено",
    "H": "Плохие заголовки",
    "M": "Пропущенный спам",
    "C": "Очищено",
    "Y": "Спам (помечено)",
}


class QuarantineError(RuntimeError):
    pass


def _decode_field(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        for encoding in ("utf-8", "latin-1"):
            try:
                return value.decode(encoding).strip("\x00")
            except UnicodeDecodeError:
                continue
        return value.decode("utf-8", errors="replace").strip("\x00")
    if isinstance(value, datetime):
        return value.isoformat(sep=" ", timespec="seconds")
    return str(value).strip("\x00")


def _decode_subject(value: Any) -> str:
    text = _decode_field(value)
    if not text:
        return "—"
    try:
        return str(make_header(decode_header(text)))
    except Exception:
        return text


def _validate_mail_id(mail_id: str) -> str:
    mail_id = mail_id.strip()
    if not MAIL_ID_RE.fullmatch(mail_id):
        raise ValueError("Некорректный mail_id")
    return mail_id


def _normalize_partition_tag(partition_tag: str | None) -> str:
    if partition_tag is None:
        return ""
    return partition_tag.strip()


def _row_to_item(row: dict[str, Any]) -> dict[str, Any]:
    content = _decode_field(row.get("content"))
    spam_level = float(row["spam_level"]) if row.get("spam_level") is not None else None
    if content == "C" and spam_level is not None and spam_level >= 100:
        content_label = "Спам"
    else:
        content_label = CONTENT_LABELS.get(content, content or "—")
    return {
        "mail_id": _decode_field(row.get("mail_id")),
        "secret_id": _decode_field(row.get("secret_id")),
        "partition_tag": _decode_field(row.get("partition_tag")),
        "time_iso": _decode_field(row.get("time_iso")),
        "time_num": int(row.get("time_num") or 0),
        "content": content,
        "content_label": content_label,
        "subject": _decode_subject(row.get("subject")),
        "from_addr": _decode_field(row.get("from_addr")) or "—",
        "spam_level": spam_level,
        "size": int(row.get("size") or 0),
        "recipients": [part.strip() for part in _decode_field(row.get("recipients")).split(",") if part.strip()],
    }


def _recipient_filter_sql(recipient: str | None) -> tuple[str, list[Any]]:
    if not recipient:
        return "", []
    return " AND rcp.email = %s ", [recipient.lower()]


def _content_filter_sql(content: str | None) -> tuple[str, list[Any]]:
    if not content:
        return "", []
    normalized = content.upper()
    if normalized == "S":
        # MailPanel content-filter quarantine is stored as content=C with spam_level>=100.
        return (
            " AND (m.content = %s OR m.content = %s OR (m.content = %s AND m.spam_level >= %s)) ",
            ["S", "Y", "C", 100],
        )
    return " AND m.content = %s ", [normalized]


def count_quarantine() -> int:
    with amavisd_conn() as conn:
        row = fetch_one(
            conn,
            "SELECT COUNT(DISTINCT m.mail_id) AS cnt "
            "FROM msgs m "
            "WHERE m.quar_type = 'Q'",
        )
    return int(row["cnt"]) if row else 0


def list_quarantine(
    limit: int = 50,
    offset: int = 0,
    recipient: str | None = None,
    content: str | None = None,
) -> dict[str, Any]:
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    recipient_sql, recipient_params = _recipient_filter_sql(recipient)
    content_sql, content_params = _content_filter_sql(content)

    with amavisd_conn() as conn:
        total_row = fetch_one(
            conn,
            "SELECT COUNT(DISTINCT m.mail_id) AS cnt "
            "FROM msgs m "
            "JOIN msgrcpt mr ON mr.mail_id = m.mail_id AND mr.partition_tag = m.partition_tag "
            "JOIN maddr rcp ON rcp.id = mr.rid "
            "WHERE m.quar_type = 'Q' "
            f"{recipient_sql}{content_sql}",
            tuple(recipient_params + content_params),
        )
        rows = fetch_all(
            conn,
            "SELECT "
            "  m.partition_tag, m.mail_id, m.secret_id, m.time_iso, m.time_num, "
            "  m.content, m.subject, m.from_addr, m.spam_level, m.size, "
            "  GROUP_CONCAT(DISTINCT rcp.email ORDER BY rcp.email SEPARATOR ',') AS recipients "
            "FROM msgs m "
            "JOIN msgrcpt mr ON mr.mail_id = m.mail_id AND mr.partition_tag = m.partition_tag "
            "JOIN maddr rcp ON rcp.id = mr.rid "
            "WHERE m.quar_type = 'Q' "
            f"{recipient_sql}{content_sql}"
            "GROUP BY m.mail_id, m.partition_tag "
            "ORDER BY m.time_num DESC "
            "LIMIT %s OFFSET %s",
            tuple(recipient_params + content_params + [limit, offset]),
        )
    return {
        "total": int(total_row["cnt"]) if total_row else 0,
        "items": [_row_to_item(row) for row in rows],
    }


def get_quarantine_item(mail_id: str, partition_tag: str = "") -> dict[str, Any]:
    mail_id = _validate_mail_id(mail_id)
    partition_tag = _normalize_partition_tag(partition_tag)
    with amavisd_conn() as conn:
        row = fetch_one(
            conn,
            "SELECT "
            "  m.partition_tag, m.mail_id, m.secret_id, m.time_iso, m.time_num, "
            "  m.content, m.subject, m.from_addr, m.spam_level, m.size, "
            "  GROUP_CONCAT(DISTINCT rcp.email ORDER BY rcp.email SEPARATOR ',') AS recipients "
            "FROM msgs m "
            "JOIN msgrcpt mr ON mr.mail_id = m.mail_id AND mr.partition_tag = m.partition_tag "
            "JOIN maddr rcp ON rcp.id = mr.rid "
            "WHERE m.quar_type = 'Q' AND m.mail_id = %s AND m.partition_tag = %s "
            "GROUP BY m.mail_id, m.partition_tag",
            (mail_id, partition_tag),
        )
    if not row:
        raise QuarantineError("Письмо не найдено в карантине")
    return _row_to_item(row)


def _fetch_raw_message(mail_id: str, partition_tag: str) -> bytes:
    with amavisd_conn() as conn:
        rows = fetch_all(
            conn,
            "SELECT mail_text FROM quarantine "
            "WHERE mail_id = %s AND partition_tag = %s "
            "ORDER BY chunk_ind ASC",
            (mail_id, partition_tag),
        )
    if not rows:
        raise QuarantineError("Тело письма не найдено")
    return b"".join(row["mail_text"] for row in rows if row.get("mail_text"))


def _extract_body(msg: EmailMessage) -> dict[str, str]:
    text_body = ""
    html_body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                continue
            content_type = part.get_content_type()
            try:
                payload = part.get_content()
            except Exception:
                continue
            if not isinstance(payload, str):
                continue
            if content_type == "text/plain" and not text_body:
                text_body = payload
            elif content_type == "text/html" and not html_body:
                html_body = payload
    else:
        try:
            payload = msg.get_content()
            if isinstance(payload, str):
                if msg.get_content_type() == "text/html":
                    html_body = payload
                else:
                    text_body = payload
        except Exception:
            pass
    return {"text": text_body, "html": html_body}


def get_quarantine_body(mail_id: str, partition_tag: str = "") -> dict[str, Any]:
    mail_id = _validate_mail_id(mail_id)
    partition_tag = _normalize_partition_tag(partition_tag)
    meta = get_quarantine_item(mail_id, partition_tag)
    raw = _fetch_raw_message(mail_id, partition_tag)
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    bodies = _extract_body(msg)
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() != "attachment":
                continue
            attachments.append(
                {
                    "filename": part.get_filename() or "attachment",
                    "content_type": part.get_content_type(),
                    "size": len(part.get_payload(decode=True) or b""),
                }
            )
    return {
        **meta,
        "headers": {key: str(value) for key, value in msg.items()},
        "text_body": bodies["text"],
        "html_body": bodies["html"],
        "attachments": attachments,
        "raw_size": len(raw),
    }


def _amavis_config_path() -> Path:
    return Path(getattr(get_config().paths, "amavisd_config", "/etc/amavisd/amavisd.conf"))


def _discover_release_ports() -> list[int]:
    ports: list[int] = []
    seen: set[int] = set()

    def add(port: int) -> None:
        if port > 0 and port not in seen:
            seen.add(port)
            ports.append(port)

    cfg = get_config()
    add(cfg.amavisd.release_port)
    path = _amavis_config_path()
    if path.is_file():
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in AMAVIS_PDP_PORT_RE.finditer(text):
            add(int(match.group(1)))
    for port in (9998, 10026):
        add(port)
    return ports


def _release_targets() -> list[tuple[str, int]]:
    host = get_config().amavisd.release_host or "127.0.0.1"
    return [(host, port) for port in _discover_release_ports()]


def _build_release_payload(mail_id: str, secret_id: str, partition_tag: str) -> bytes:
    lines = [
        "request=release",
        f"mail_id={mail_id}",
        "quar_type=Q",
    ]
    if secret_id:
        lines.append(f"secret_id={secret_id}")
    if partition_tag:
        lines.append(f"partition_tag={partition_tag}")
    return ("\n".join(lines) + "\n\n").encode("ascii")


def _release_response_ok(responses: list[str]) -> bool:
    if not responses:
        return False
    joined = "\n".join(responses)
    lowered = joined.lower()
    if any(
        token in lowered
        for token in (
            "does not exist",
            "failure",
            "failed",
            "denied",
            "not authorized",
            "no such",
            "can't open",
        )
    ):
        if not any(line.startswith("250") for line in responses):
            return False
    if any(line.startswith("250") for line in responses):
        return True
    if "setreply=250" in lowered:
        return True
    return False


def _amavis_release_tcp(
    host: str, port: int, mail_id: str, secret_id: str, partition_tag: str
) -> list[str]:
    payload = _build_release_payload(mail_id, secret_id, partition_tag)
    with socket.create_connection((host, port), timeout=30) as sock:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    response = b"".join(chunks).decode("utf-8", errors="replace").strip()
    return [line.strip() for line in response.splitlines() if line.strip()]


def _amavis_release_cli(mail_id: str, secret_id: str, partition_tag: str) -> list[str]:
    candidates = [
        "/usr/sbin/amavisd-release",
        "/bin/amavisd-release",
        shutil.which("amavisd-release") or "",
    ]
    cfg = get_config()
    host = cfg.amavisd.release_host or "127.0.0.1"
    port = cfg.amavisd.release_port
    config_path = _amavis_config_path()
    for command in candidates:
        if not command or not Path(command).is_file():
            continue
        args = [command, "-h", host, "-p", str(port)]
        if config_path.is_file():
            args.extend(["-c", str(config_path)])
        args.extend([mail_id, secret_id])
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        output = "\n".join(
            part.strip()
            for part in (result.stdout or "", result.stderr or "")
            if part and part.strip()
        )
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if result.returncode == 0 or _release_response_ok(lines):
            return lines or [output]
    return []


def _amavis_release(mail_id: str, secret_id: str, partition_tag: str) -> list[str]:
    errors: list[str] = []
    for host, port in _release_targets():
        try:
            responses = _amavis_release_tcp(host, port, mail_id, secret_id, partition_tag)
            if _release_response_ok(responses):
                return responses
            if responses:
                errors.append(f"{host}:{port} → {'; '.join(responses)}")
            else:
                errors.append(f"{host}:{port} → пустой ответ Amavis")
        except OSError as exc:
            errors.append(f"{host}:{port} → {exc}")

    cli_responses = _amavis_release_cli(mail_id, secret_id, partition_tag)
    if _release_response_ok(cli_responses):
        return cli_responses
    if cli_responses:
        errors.append(f"amavisd-release → {'; '.join(cli_responses)}")

    ports = ", ".join(str(port) for _, port in _release_targets())
    hint = (
        "Проверьте в amavisd.conf: "
        "$inet_socket_port должен включать 9998; "
        "$interface_policy{'9998'} = 'AM.PDP-INET'; "
        "и policy_bank для AM.PDP с inet_acl 127.0.0.1."
    )
    detail = "; ".join(errors) or f"нет ответа на портах {ports}"
    raise QuarantineError(f"Не удалось освободить письмо: {detail}. {hint}")


def release_quarantine(mail_id: str, partition_tag: str = "") -> dict[str, Any]:
    item = get_quarantine_item(mail_id, partition_tag)
    responses = _amavis_release(item["mail_id"], item["secret_id"], item["partition_tag"])
    delete_quarantine(mail_id, item["partition_tag"])
    return {"ok": True, "responses": responses}


def delete_quarantine(mail_id: str, partition_tag: str = "") -> None:
    mail_id = _validate_mail_id(mail_id)
    partition_tag = _normalize_partition_tag(partition_tag)
    with amavisd_conn() as conn:
        execute(
            conn,
            "DELETE FROM quarantine WHERE mail_id = %s AND partition_tag = %s",
            (mail_id, partition_tag),
        )
        execute(
            conn,
            "DELETE FROM msgrcpt WHERE mail_id = %s AND partition_tag = %s",
            (mail_id, partition_tag),
        )
        execute(
            conn,
            "DELETE FROM msgs WHERE mail_id = %s AND partition_tag = %s",
            (mail_id, partition_tag),
        )


def user_can_access_item(item: dict[str, Any], mailbox: str | None) -> bool:
    if not mailbox:
        return False
    mailbox = mailbox.lower()
    return any(recipient.lower() == mailbox for recipient in item.get("recipients", []))
