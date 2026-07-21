from __future__ import annotations

import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from app.config import get_config

JOURNAL_UNITS = ["postfix", "amavisd", "dovecot", "iredapd", "rspamd"]

JOURNAL_LINE_RE = re.compile(
    r"^(?P<logged_at>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: [+-]\d{4})?) "
    r"(?P<host>\S+) "
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)$"
)

SYSLOG_LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
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


def _normalize_since(value: str | None) -> datetime:
    if not value:
        return datetime.now() - timedelta(hours=24)
    text = value.strip().replace("T", " ")
    if len(text) == 10:
        text = f"{text} 00:00:00"
    elif len(text) == 16:
        text = f"{text}:00"
    try:
        return datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return datetime.now() - timedelta(hours=24)


def _normalize_until(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("T", " ")
    if len(text) == 10:
        text = f"{text} 23:59:59"
    elif len(text) == 16:
        text = f"{text}:59"
    try:
        return datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _since_until_strings(date_from: str | None, date_to: str | None) -> tuple[str, str | None]:
    since_dt = _normalize_since(date_from)
    until_dt = _normalize_until(date_to)
    since = since_dt.strftime("%Y-%m-%d %H:%M:%S")
    until = until_dt.strftime("%Y-%m-%d %H:%M:%S") if until_dt else None
    return since, until


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
    if "rspamd" in lowered:
        return "rspamd"
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


def _syslog_to_datetime(month: str, day: str, time_str: str) -> datetime:
    year = datetime.now().year
    dt = datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
    if dt > datetime.now() + timedelta(days=2):
        dt = dt.replace(year=year - 1)
    return dt


def _parse_logged_at_text(value: str) -> datetime | None:
    text = value.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(text[:26].split("+")[0].strip(), fmt)
        except ValueError:
            continue
    return None


def _row_from_parts(
    logged_at: datetime,
    process: str,
    message: str,
    raw_line: str,
    *,
    default_service: str | None = None,
) -> dict[str, Any]:
    fields = _extract_fields(message)
    service = default_service or _service_from_process(process)
    return {
        "logged_at": logged_at.strftime("%Y-%m-%d %H:%M:%S"),
        "service": service,
        "level": "error" if re.search(r"error|failed|refused|reject", message, re.I) else "info",
        "queue_id": fields["queue_id"],
        "mail_from": fields["mail_from"],
        "mail_to": fields["mail_to"],
        "status": fields["status"],
        "spam_score": fields["spam_score"],
        "message_id": fields["message_id"],
        "outcome": _classify_outcome(message),
        "message": message[:2000],
        "raw_line": raw_line[:4000],
    }


def _parse_journal_line(line: str) -> dict[str, Any] | None:
    match = JOURNAL_LINE_RE.match(line.strip())
    if not match:
        return None
    message = match.group("message")
    logged_at = _parse_logged_at_text(match.group("logged_at"))
    if not logged_at:
        return None
    return _row_from_parts(
        logged_at,
        match.group("process"),
        message,
        line,
    )


def _parse_syslog_line(line: str, default_service: str | None = None) -> dict[str, Any] | None:
    match = SYSLOG_LINE_RE.match(line.strip())
    if not match:
        return None
    message = match.group("message")
    logged_at = _syslog_to_datetime(match.group("month"), match.group("day"), match.group("time"))
    return _row_from_parts(
        logged_at,
        match.group("process"),
        message,
        line,
        default_service=default_service,
    )


def _parse_any_line(line: str, default_service: str | None = None) -> dict[str, Any] | None:
    row = _parse_journal_line(line)
    if row:
        return row
    row = _parse_syslog_line(line, default_service=default_service)
    if row:
        return row
    stripped = line.strip()
    if len(stripped) < 20:
        return None
    return _row_from_parts(
        datetime.now(),
        default_service or "mail",
        stripped,
        stripped,
        default_service=default_service,
    )


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
        elif len(text) >= 3:
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


def _grep_log_file(path: Path, pattern: str) -> list[str]:
    if not path.is_file():
        return []
    result = subprocess.run(
        ["grep", "-i", "-E", pattern, str(path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=90,
    )
    if result.returncode not in (0, 1):
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def _log_file_targets() -> list[tuple[Path, str]]:
    cfg = get_config().paths
    return [
        (Path(cfg.maillog), "postfix"),
        (Path(cfg.iredapd_log), "iredapd"),
        (Path(cfg.dovecot_log), "dovecot"),
        (Path(cfg.messages_log), "system"),
    ]


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


def _in_time_range(row: dict[str, Any], since_dt: datetime, until_dt: datetime | None) -> bool:
    logged = _parse_logged_at_text(str(row.get("logged_at", "")))
    if not logged:
        return True
    if logged < since_dt:
        return False
    if until_dt and logged > until_dt:
        return False
    return True


def _dedupe_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(row.get("logged_at", "")),
        str(row.get("service", "")),
        str(row.get("message", ""))[:240],
    )


def _filter_rows(
    rows: list[dict[str, Any]],
    *,
    query: str | None,
    queue_id: str | None,
    mail_from: str | None,
    mail_to: str | None,
    service: str | None,
    since_dt: datetime,
    until_dt: datetime | None,
) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for row in rows:
        if service and row.get("service") != service:
            continue
        if not _in_time_range(row, since_dt, until_dt):
            continue
        if not _line_matches(row, query=query, queue_id=queue_id, mail_from=mail_from, mail_to=mail_to):
            continue
        filtered.append(row)
    return filtered


def _search_journal_rows(
    since: str,
    until: str | None,
    grep: str | None,
) -> list[dict[str, Any]]:
    lines = _run_journalctl(since, until, grep)
    rows: list[dict[str, Any]] = []
    for line in lines:
        row = _parse_any_line(line)
        if row:
            rows.append(row)
    return rows


def _search_file_rows(grep: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path, default_service in _log_file_targets():
        for line in _grep_log_file(path, grep):
            row = _parse_any_line(line, default_service=default_service)
            if row:
                rows.append(row)
    return rows


def _search_db_rows(
    *,
    query: str | None,
    queue_id: str | None,
    mail_from: str | None,
    mail_to: str | None,
    date_from: str | None,
    date_to: str | None,
    service: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    from app.services import mail_ops

    result = mail_ops.search_logs(
        service=service,
        query=query,
        queue_id=queue_id,
        mail_from=mail_from,
        mail_to=mail_to,
        date_from=date_from,
        date_to=date_to,
        limit=limit,
        offset=0,
    )
    rows: list[dict[str, Any]] = []
    for item in result.get("items", []):
        message = str(item.get("message", ""))
        logged_at = item.get("logged_at")
        if hasattr(logged_at, "strftime"):
            logged_at = logged_at.strftime("%Y-%m-%d %H:%M:%S")
        rows.append(
            {
                "id": item.get("id"),
                "logged_at": logged_at,
                "service": item.get("service"),
                "level": item.get("level"),
                "queue_id": item.get("queue_id"),
                "mail_from": item.get("mail_from"),
                "mail_to": item.get("mail_to"),
                "status": item.get("status"),
                "spam_score": item.get("spam_score"),
                "message_id": None,
                "outcome": _classify_outcome(message) or item.get("status"),
                "message": message,
                "raw_line": message,
            }
        )
    return rows


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
    since_dt = _normalize_since(date_from)
    until_dt = _normalize_until(date_to)
    since, until = _since_until_strings(date_from, date_to)
    grep = _pick_journal_grep(
        query=query,
        queue_id=queue_id,
        mail_from=mail_from,
        mail_to=mail_to,
    )
    has_filters = any(value and value.strip() for value in (query, queue_id, mail_from, mail_to))
    if not has_filters:
        raise RuntimeError(
            "Укажите отправителя, получателя, Queue-ID или текст для поиска"
        )
    if not grep:
        raise RuntimeError(
            "Укажите отправителя, получателя, Queue-ID или текст длиной от 3 символов"
        )

    sources_used: list[str] = []
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}

    def absorb(rows: list[dict[str, Any]], source: str) -> None:
        if not rows:
            return
        sources_used.append(source)
        for row in rows:
            merged[_dedupe_key(row)] = row

    try:
        absorb(_search_journal_rows(since, until, grep), "journalctl")
    except RuntimeError:
        pass

    absorb(_search_file_rows(grep), "файлы логов")

    if len(merged) < limit:
        absorb(
            _search_db_rows(
                query=query,
                queue_id=queue_id,
                mail_from=mail_from,
                mail_to=mail_to,
                date_from=date_from,
                date_to=date_to,
                service=service,
                limit=max(limit * 3, 500),
            ),
            "БД MailPanel",
        )

    parsed = _filter_rows(
        list(merged.values()),
        query=query,
        queue_id=queue_id,
        mail_from=mail_from,
        mail_to=mail_to,
        service=service,
        since_dt=since_dt,
        until_dt=until_dt,
    )
    parsed.sort(key=lambda item: item["logged_at"], reverse=True)
    total = len(parsed)
    page = parsed[offset : offset + limit]
    for index, row in enumerate(page, start=offset + 1):
        row["id"] = index

    if sources_used:
        source_label = ", ".join(dict.fromkeys(sources_used))
    else:
        source_label = "journalctl, файлы логов, БД MailPanel"

    file_paths = ", ".join(str(path) for path, _ in _log_file_targets() if path.is_file())
    if file_paths:
        source_label += f" ({file_paths})"

    return {
        "total": total,
        "items": page,
        "source": "mixed",
        "source_label": source_label,
    }


def trace_queue_id(queue_id: str) -> list[dict[str, Any]]:
    queue_id = queue_id.strip().upper()
    since = (datetime.now() - timedelta(days=14)).strftime("%Y-%m-%d %H:%M:%S")
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}

    def absorb(rows: list[dict[str, Any]]) -> None:
        for row in rows:
            if queue_id not in (row.get("raw_line") or "").upper():
                continue
            merged[_dedupe_key(row)] = row

    try:
        for line in _run_journalctl(since, None, queue_id, max_lines=5000):
            row = _parse_any_line(line)
            if row:
                absorb([row])
    except RuntimeError:
        pass

    for path, default_service in _log_file_targets():
        for line in _grep_log_file(path, queue_id):
            row = _parse_any_line(line, default_service=default_service)
            if row:
                absorb([row])

    from app.services import mail_ops

    for item in mail_ops.trace_queue_id(queue_id):
        message = str(item.get("message", ""))
        logged_at = item.get("logged_at")
        if hasattr(logged_at, "strftime"):
            logged_at = logged_at.strftime("%Y-%m-%d %H:%M:%S")
        absorb(
            [
                {
                    "logged_at": logged_at,
                    "service": item.get("service"),
                    "level": item.get("level"),
                    "queue_id": item.get("queue_id"),
                    "mail_from": item.get("mail_from"),
                    "mail_to": item.get("mail_to"),
                    "status": item.get("status"),
                    "spam_score": item.get("spam_score"),
                    "message_id": None,
                    "outcome": _classify_outcome(message) or item.get("status"),
                    "message": message,
                    "raw_line": message,
                }
            ]
        )

    rows = sorted(merged.values(), key=lambda item: item["logged_at"])
    for index, row in enumerate(rows, start=1):
        row["id"] = index
    return rows
