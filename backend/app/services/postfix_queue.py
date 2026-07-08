from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime
from typing import Any

QUEUE_ID_RE = re.compile(r"^[A-F0-9]{10,12}$")
HEADER_RE = re.compile(
    r"^([A-F0-9]{10,12})([*!#-]?)\s+(\d+)\s+(\w{3}\s+\w{3}\s+\s?\d+\s+\d+:\d+:\d+)\s+(.*)$"
)
REASON_RE = re.compile(r"^\((.+)\)$")

ALLOWED_BINARIES = {"postqueue", "postsuper", "postcat"}


class PostfixQueueError(RuntimeError):
    pass


def _validate_queue_id(queue_id: str) -> str:
    queue_id = queue_id.strip().upper()
    if not QUEUE_ID_RE.fullmatch(queue_id):
        raise ValueError("Некорректный Queue-ID")
    return queue_id


def _run_postfix(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    if not cmd or cmd[0] not in ALLOWED_BINARIES:
        raise ValueError("Команда не разрешена")
    return subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)


def _status_from_flag(flag: str, queue_name: str | None = None) -> str:
    if queue_name:
        mapping = {
            "active": "active",
            "incoming": "incoming",
            "deferred": "deferred",
            "hold": "hold",
            "corrupt": "corrupt",
        }
        return mapping.get(queue_name, queue_name)
    if flag == "*":
        return "active"
    if flag == "!":
        return "hold"
    if flag == "#":
        return "corrupt"
    return "deferred"


def _parse_arrival_time(value: str) -> str:
    value = re.sub(r"\s+", " ", value.strip())
    try:
        current_year = datetime.now().year
        parsed = datetime.strptime(f"{value} {current_year}", "%b %d %H:%M:%S %Y")
        return parsed.isoformat(sep=" ", timespec="seconds")
    except ValueError:
        return value


def _parse_postqueue_text(output: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue
        if line.startswith("-Queue ID-"):
            continue
        if line.startswith("(") and line.endswith(")") and current is not None:
            current["reason"] = line.strip("()")
            continue
        match = HEADER_RE.match(line)
        if match:
            if current:
                items.append(current)
            queue_id, flag, size, arrival, sender = match.groups()
            current = {
                "queue_id": queue_id,
                "size_bytes": int(size),
                "arrival_time": _parse_arrival_time(arrival),
                "sender": sender.strip() or None,
                "recipients": [],
                "status": _status_from_flag(flag),
                "reason": None,
                "flags": [flag] if flag else [],
            }
            continue
        if current and line.startswith(" "):
            recipient = line.strip()
            if recipient:
                current["recipients"].append(recipient)
    if current:
        items.append(current)
    return items


def _parse_postqueue_json(output: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        recipients = row.get("recipients") or []
        if isinstance(recipients, dict):
            recipients = list(recipients.keys())
        arrival = row.get("arrival_time")
        if isinstance(arrival, int):
            arrival_time = datetime.fromtimestamp(arrival).isoformat(sep=" ", timespec="seconds")
        else:
            arrival_time = str(arrival or "")
        items.append(
            {
                "queue_id": row.get("queue_id", ""),
                "size_bytes": int(row.get("message_size") or 0),
                "arrival_time": arrival_time,
                "sender": row.get("sender") or None,
                "recipients": recipients,
                "status": _status_from_flag("", row.get("queue_name")),
                "reason": row.get("reason") or row.get("delay_reason"),
                "flags": [],
            }
        )
    return [item for item in items if item["queue_id"]]


def list_queue(
    status: str | None = None,
    sender: str | None = None,
    recipient: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    result = _run_postfix(["postqueue", "-j"])
    if result.returncode == 0 and result.stdout.strip():
        items = _parse_postqueue_json(result.stdout)
    else:
        result = _run_postfix(["postqueue", "-p"])
        if result.returncode != 0:
            raise PostfixQueueError(result.stderr.strip() or result.stdout.strip() or "postqueue failed")
        if "Mail queue is empty" in result.stdout:
            items = []
        else:
            items = _parse_postqueue_text(result.stdout)

    if status:
        status = status.lower()
        items = [item for item in items if item["status"] == status]
    if sender:
        sender = sender.lower()
        items = [item for item in items if (item.get("sender") or "").lower().find(sender) >= 0]
    if recipient:
        recipient = recipient.lower()
        items = [
            item
            for item in items
            if any(recipient in (rcpt or "").lower() for rcpt in item.get("recipients", []))
        ]

    total = len(items)
    active = sum(1 for item in items if item["status"] == "active")
    deferred = sum(1 for item in items if item["status"] == "deferred")
    hold = sum(1 for item in items if item["status"] == "hold")
    incoming = sum(1 for item in items if item["status"] == "incoming")
    page = items[offset : offset + limit]
    return {
        "total": total,
        "active": active,
        "deferred": deferred,
        "hold": hold,
        "incoming": incoming,
        "items": page,
    }


def get_queue_message(queue_id: str) -> dict[str, Any]:
    queue_id = _validate_queue_id(queue_id)
    result = _run_postfix(["postcat", "-qhv", queue_id])
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "postcat failed"
        raise PostfixQueueError(detail)
    return {"queue_id": queue_id, "headers": result.stdout}


def delete_message(queue_id: str) -> str:
    queue_id = _validate_queue_id(queue_id)
    result = _run_postfix(["postsuper", "-d", queue_id])
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "postsuper failed"
        raise PostfixQueueError(detail)
    return queue_id


def flush_message(queue_id: str) -> str:
    queue_id = _validate_queue_id(queue_id)
    result = _run_postfix(["postqueue", "-i", queue_id])
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "postqueue failed"
        raise PostfixQueueError(detail)
    return queue_id


def hold_message(queue_id: str) -> str:
    queue_id = _validate_queue_id(queue_id)
    result = _run_postfix(["postsuper", "-h", queue_id])
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "postsuper failed"
        raise PostfixQueueError(detail)
    return queue_id


def release_message(queue_id: str) -> str:
    queue_id = _validate_queue_id(queue_id)
    result = _run_postfix(["postsuper", "-H", queue_id])
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "postsuper failed"
        raise PostfixQueueError(detail)
    return queue_id


def flush_all() -> None:
    result = _run_postfix(["postqueue", "-f"])
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "postqueue failed"
        raise PostfixQueueError(detail)
