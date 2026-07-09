from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any

JOURNAL_UNITS: dict[str, list[str]] = {
    "mail": ["postfix", "amavisd"],
    "dovecot": ["dovecot"],
    "iredapd": ["iredapd"],
    "system": [],
}


def _tail_file(path: str, lines: int) -> list[str]:
    file_path = Path(path)
    if not file_path.exists():
        return [f"Файл лога не найден: {path}"]
    content = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return content[-lines:]


def _file_age_seconds(path: Path) -> float | None:
    if not path.exists():
        return None
    return max(0.0, time.time() - path.stat().st_mtime)


def _tail_journal(units: list[str], lines: int) -> list[str]:
    cmd = ["journalctl", "-n", str(lines), "--no-pager", "-o", "short-precise"]
    if units:
        for unit in units:
            cmd.extend(["-u", unit])
    else:
        cmd.extend(["-p", "mail"])
    result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "journalctl failed").strip()
        return [f"Ошибка journalctl: {detail}"]
    output = [line for line in result.stdout.splitlines() if line.strip()]
    return output or ["Записей в journalctl нет"]


def tail_live_log(log_type: str, file_path: str, lines: int = 200) -> dict[str, Any]:
    lines = max(20, min(lines, 1000))
    units = JOURNAL_UNITS.get(log_type)
    file_age = _file_age_seconds(Path(file_path))

    if units is not None:
        journal_lines = _tail_journal(units, lines)
        journal_ok = journal_lines and not journal_lines[0].startswith("Ошибка journalctl")
        file_stale = file_age is None or file_age > 300
        if journal_ok and (file_stale or log_type == "mail"):
            return {
                "lines": journal_lines,
                "source": "journal",
                "source_label": "journalctl: " + (", ".join(units) if units else "mail"),
                "file_path": file_path,
                "file_age_seconds": file_age,
            }

    file_lines = _tail_file(file_path, lines)
    stale_note = ""
    if file_age is not None and file_age > 300:
        stale_note = f" (файл не обновлялся {int(file_age // 60)} мин — смотрите journalctl)"
    return {
        "lines": file_lines,
        "source": "file",
        "source_label": f"файл {file_path}{stale_note}",
        "file_path": file_path,
        "file_age_seconds": file_age,
    }
