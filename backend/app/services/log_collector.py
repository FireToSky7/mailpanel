from __future__ import annotations

import re
import time
from datetime import datetime
from pathlib import Path
from typing import TextIO

from app.config import get_config
from app.database import execute, fetch_one, panel_conn

POSTFIX_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)
QUEUE_RE = re.compile(r"\b([A-F0-9]{10,12})\b")
FROM_RE = re.compile(r"from=<([^>]*)>")
TO_RE = re.compile(r"to=<([^>]*)>")
STATUS_RE = re.compile(r"status=(\w+)")
SPAM_RE = re.compile(r"spam-score[= ]([\d.]+)", re.I)


class LogCollector:
    def __init__(self) -> None:
        self._positions: dict[str, int] = {}

    def _open_at(self, path: Path) -> TextIO:
        handle = path.open("r", encoding="utf-8", errors="replace")
        key = str(path)
        pos = self._positions.get(key)
        if pos is None:
            handle.seek(0, 2)
            self._positions[key] = handle.tell()
            return handle
        handle.seek(pos)
        return handle

    def _parse_timestamp(self, month: str, day: str, time_str: str) -> datetime:
        year = datetime.now().year
        return datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")

    def _extract_fields(self, message: str) -> dict:
        queue = None
        m = QUEUE_RE.search(message)
        if m:
            queue = m.group(1)
        mail_from = None
        m = FROM_RE.search(message)
        if m:
            mail_from = m.group(1) or None
        mail_to = None
        m = TO_RE.search(message)
        if m:
            mail_to = m.group(1) or None
        status = None
        m = STATUS_RE.search(message)
        if m:
            status = m.group(1)
        spam_score = None
        m = SPAM_RE.search(message)
        if m:
            spam_score = float(m.group(1))
        return {
            "queue_id": queue,
            "mail_from": mail_from,
            "mail_to": mail_to,
            "status": status,
            "spam_score": spam_score,
        }

    def ingest_file(self, path: str, service: str) -> int:
        file_path = Path(path)
        if not file_path.exists():
            return 0
        count = 0
        handle = self._open_at(file_path)
        for line in handle:
            line = line.rstrip("\n")
            if not line:
                continue
            match = POSTFIX_RE.match(line)
            if match:
                logged_at = self._parse_timestamp(match.group("month"), match.group("day"), match.group("time"))
                message = match.group("message")
                level = "error" if "error" in message.lower() else "info"
            else:
                logged_at = datetime.now()
                message = line
                level = "info"
            fields = self._extract_fields(message)
            with panel_conn() as conn:
                execute(
                    conn,
                    "INSERT INTO mail_log_entries "
                    "(logged_at, service, level, queue_id, mail_from, mail_to, status, spam_score, message, raw_line) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        logged_at,
                        service,
                        level,
                        fields["queue_id"],
                        fields["mail_from"],
                        fields["mail_to"],
                        fields["status"],
                        fields["spam_score"],
                        message[:2000],
                        line[:4000],
                    ),
                )
            count += 1
        self._positions[str(file_path)] = handle.tell()
        handle.close()
        return count

    def cleanup_old(self) -> int:
        cfg = get_config()
        days = cfg.log_collector.retention_days
        with panel_conn() as conn:
            return execute(
                conn,
                "DELETE FROM mail_log_entries WHERE logged_at < DATE_SUB(NOW(), INTERVAL %s DAY)",
                (days,),
            )

    def run_once(self) -> int:
        cfg = get_config()
        total = 0
        total += self.ingest_file(cfg.paths.maillog, "postfix")
        total += self.ingest_file(cfg.paths.iredapd_log, "iredapd")
        total += self.ingest_file(cfg.paths.dovecot_log, "dovecot")
        return total

    def run_loop(self) -> None:
        cfg = get_config()
        while True:
            try:
                self.run_once()
            except Exception:
                pass
            time.sleep(cfg.log_collector.poll_interval_seconds)


def ensure_bootstrap_admin() -> None:
    with panel_conn() as conn:
        row = fetch_one(conn, "SELECT id FROM panel_users WHERE username = 'admin'")
        if row:
            return
        from app.auth import hash_password

        execute(
            conn,
            "INSERT INTO panel_users (username, password_hash, role, display_name) "
            "VALUES (%s, %s, 'superadmin', 'Super Admin')",
            ("admin", hash_password("admin123")),
        )
