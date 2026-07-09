from __future__ import annotations

import re
import subprocess
from datetime import datetime, timedelta
from typing import Any

JOURNAL_UNITS = ["postfix", "amavisd", "dovecot", "iredapd", "rspamd"]

JOURNAL_LINE_RE = re.compile(
    r"^(?P<logged_at>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: \S+)?) "
    r"(?P<host>\S+) "
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)$"
)

QUEUE_RE = re.compile(r"\b([A-F0-9]{10,12})\b")
FROM_RE = re.compile(r"from=<([^>]*)>", re.I)
TO_RE = re.compile(r"to=<([^>]*)>", re.I)
AMAVIS_TO_RE = re.compile(r"->\s*<([^>]+)>", re.I)
STATUS_RE = re.compile(r"status=(\w+)", re.I)
SPAM_RE = re.compile(r"Hits:\s*([\d.]+)", re.I)
MSGID_RE = re.compile(r"message-id=<([^>]+)>", re.I)

OUTCOME_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"stored mail into mailbox", re.I), "Доставлено"),
    (re.compile(r"status=sent \(delivered", re.I), "Доставлено"),
    (re.compile(r"status=sent", re.I), "Отправлено"),
    (re.compile(r"status=deferred", re.I), "Очередь"),
    (re.compile(r"status=hold", re.I), "На удержании"),
    (re.compile(r"undelivered mail returned|status=bounced", re.I), "Отказ"),
    (re.compile(r"Quarantined|quarantine|Moved to .*Spam", re.I), "Карантин"),
    (re.compile(r"Blocked|banned|virus|BANNED", re.I), "Блокировка"),
    (re.compile(r"Passed UNCHECKED|Passed CLEAN|Passed BAD", re.I), "Проверено (Amavis)"),
    (re.compile(r"too many hops", re.I), "Ошибка: петля"),
    (re.compile(r"Connection refused|timed out|Network is unreachable", re.I), "Ошибка сети"),
    (re.compile(r"NOQUEUE: reject|reject:| rejected ", re.I), "Отклонено"),
    (re.compile(r"greylist", re.I), "Greylisting"),
    (re.compile(r"wblist|blacklist", re.I), "Чёрный список"),
    (re.compile(r": removed$", re.I), "Обработано"),
    (re.compile(r"queue active", re.I), "В очереди"),
]


def _normalize_since(value: str | None) -> str:
    if not value:
        return (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    text = value.strip().replace("T", " ")
    if len(text) == 10:
        return f"{text} 00:00:00"
    if len(text) == 16:
        return f"{text}:00"
    return text


def _normalize_until(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip().replace("T", " ")
    if len(text) == 10:
        return f"{text} 23:59:59"
    if len(text) == 16:
        return f"{text}:59"
    return text


def _service_from_process(process: str) -> str:
    lowered = process.lower()
    if lowered.startswith("postfix"):
        return "postfix"
    if "amavis" in lowered:
        return "amavis"
    if "dovecot" in lowered:
        return "dovecot"
    if "iredapd" in lowered:
        return "iredapd"
    return process.split("/")[0].split("[")[0]


def _extract_fields(message: str) -> dict[str, Any]:
    queue_id = None
    match = QUEUE_RE.search(message)
    if match:
        queue_id = match.group(1)
    mail_from = None
    match = FROM_RE.search(message)
    if match:
        mail_from = match.group(1) or None
    mail_to = None
    match = TO_RE.search(message)
    if match:
        mail_to = match.group(1) or None
    if not mail_to:
        match = AMAVIS_TO_RE.search(message)
        if match:
            mail_to = match.group(1)
    status = None
    match = STATUS_RE.search(message)
    if match:
        status = match.group(1)
    spam_score = None
    match = SPAM_RE.search(message)
    if match:
        try:
            spam_score = float(match.group(1))
        except ValueError:
            spam_score = None
    message_id = None
    match = MSGID_RE.search(message)
    if match:
        message_id = match.group(1)
    return {
        "queue_id": queue_id,
        "mail_from": mail_from,
        "mail_to": mail_to,
        "status": status,
        "spam_score": spam_score,
        "message_id": message_id,
    }


def _classify_outcome(message: str) -> str | None:
    for pattern, label in OUTCOME_RULES:
        if pattern.search(message):
            return label
    return None


def _parse_journal_line(line: str) -> dict[str, Any] | None:
    match = JOURNAL_LINE_RE.match(line.strip())
    if not match:
        return None
    message = match.group("message")
    fields = _extract_fields(message)
    return {
        "logged_at": match.group("logged_at"),
        "service": _service_from_process(match.group("process")),
        "level": "error" if re.search(r"error|failed|refused|reject", message, re.I) else "info",
        "queue_id": fields["queue_id"],
        "mail_from": fields["mail_from"],
        "mail_to": fields["mail_to"],
        "status": fields["status"],
        "spam_score": fields["spam_score"],
        "message_id": fields["message_id"],
        "outcome": _classify_outcome(message),
        "message": message[:2000],
        "raw_line": line[:4000],
    }


def _pick_journal_grep(
    *,
    query: str | None,
    queue_id: str | None,
    mail_from: str | None,
    mail_to: str | None,
) -> str | None:
    if queue_id and queue_id.strip():
        return queue_id.strip().upper()
    patterns: list[str] = []
    for value in (mail_to, mail_from, query):
        text = (value or "").strip()
        if not text:
            continue
        if "@" in text or re.fullmatch(r"[A-F0-9]{10,12}", text, re.I):
            patterns.append(re.escape(text))
        elif len(text) >= 4:
            patterns.append(re.escape(text))
    if not patterns:
        return None
    return "|".join(dict.fromkeys(patterns))


def _run_journalctl(
    since: str,
    until: str | None,
    grep: str | None,
    max_lines: int = 15000,
) -> list[str]:
    cmd = ["journalctl", "--no-pager", "-o", "short-precise", "--since", since]
    for unit in JOURNAL_UNITS:
        cmd.extend(["-u", unit])
    if until:
        cmd.extend(["--until", until])
    if grep:
        cmd.extend(["-g", grep])
    else:
        cmd.extend(["-n", str(max_lines)])
    result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=120)
    if result.returncode not in (0, 1):
        detail = (result.stderr or result.stdout or "journalctl failed").strip()
        raise RuntimeError(detail)
    return [line for line in result.stdout.splitlines() if line.strip()]


def _line_matches(
    row: dict[str, Any],
    *,
    query: str | None,
    queue_id: str | None,
    mail_from: str | None,
    mail_to: str | None,
) -> bool:
    haystack = " ".join(
        filter(
            None,
            [
                row.get("message"),
                row.get("raw_line"),
                row.get("mail_from"),
                row.get("mail_to"),
                row.get("queue_id"),
                row.get("message_id"),
            ],
        )
    ).lower()

    if queue_id and queue_id.strip().upper() not in haystack.upper():
        return False
    if mail_from and mail_from.strip().lower() not in haystack:
        return False
    if mail_to and mail_to.strip().lower() not in haystack:
        return False
    if query and query.strip().lower() not in haystack:
        return False
    return True


def search_mail_logs(
    query: str | None = None,
    queue_id: str | None = None,
    mail_from: str | None = None,
    mail_to: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    service: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    since = _normalize_since(date_from)
    until = _normalize_until(date_to)
    grep = _pick_journal_grep(
        query=query,
        queue_id=queue_id,
        mail_from=mail_from,
        mail_to=mail_to,
    )
    has_filters = any(
        value and value.strip()
        for value in (query, queue_id, mail_from, mail_to)
    )
    if not has_filters:
        raise RuntimeError(
            "Укажите отправителя, получателя, Queue-ID или текст для поиска"
        )

    lines = _run_journalctl(since, until, grep)
    parsed: list[dict[str, Any]] = []
    for line in lines:
        row = _parse_journal_line(line)
        if not row:
            continue
        if service and row.get("service") != service:
            continue
        if not _line_matches(row, query=query, queue_id=queue_id, mail_from=mail_from, mail_to=mail_to):
            continue
        parsed.append(row)

    parsed.sort(key=lambda item: item["logged_at"], reverse=True)
    total = len(parsed)
    page = parsed[offset : offset + limit]
    for index, row in enumerate(page, start=offset + 1):
        row["id"] = index
    source_label = "journalctl: postfix, amavisd, dovecot, iredapd, rspamd"
    if not grep:
        source_label += f" (последние {len(lines)} строк за период)"
    return {
        "total": total,
        "items": page,
        "source": "journal",
        "source_label": source_label,
    }


def trace_queue_id(queue_id: str) -> list[dict[str, Any]]:
    queue_id = queue_id.strip().upper()
    since = (datetime.now() - timedelta(days=14)).strftime("%Y-%m-%d %H:%M:%S")
    lines = _run_journalctl(since, None, queue_id, max_lines=5000)
    rows: list[dict[str, Any]] = []
    for line in lines:
        row = _parse_journal_line(line)
        if not row:
            continue
        if queue_id not in (row.get("raw_line") or "").upper():
            continue
        rows.append(row)
    rows.sort(key=lambda item: item["logged_at"])
    for index, row in enumerate(rows, start=1):
        row["id"] = index
    return rows
