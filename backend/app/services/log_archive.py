from __future__ import annotations

import json
import re
import shutil
import subprocess
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from app.config import get_config

# Типы снимков: имя файла → юниты journalctl (пусто = priority mail / system)
ARCHIVE_SOURCES: dict[str, list[str]] = {
    "mail": ["postfix", "amavisd"],
    "dovecot": ["dovecot"],
    "iredapd": ["iredapd"],
    "system": [],
}

SAFE_ID_RE = re.compile(r"^[0-9]{8}_[0-9]{6}(?:_[a-z0-9-]+)*(?:-\d+)?$")


def _archives_root() -> Path:
    cfg = get_config()
    root = Path(getattr(cfg.paths, "mailpanel_log_dir", None) or "/var/log/mailpanel")
    path = root / "archives"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _parse_dt(value: str | None, fallback: datetime) -> datetime:
    if not value or not value.strip():
        return fallback
    text = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        pass
    text_space = text.replace("T", " ")
    for fmt, length in (("%Y-%m-%d %H:%M:%S", 19), ("%Y-%m-%d %H:%M", 16), ("%Y-%m-%d", 10)):
        try:
            return datetime.strptime(text_space[:length], fmt)
        except ValueError:
            continue
    raise ValueError(f"Некорректная дата: {value}")


def _fmt_journal(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _run_journalctl(units: list[str], since: datetime, until: datetime, max_lines: int = 200000) -> list[str]:
    cmd = [
        "journalctl",
        "--no-pager",
        "-o",
        "short-precise",
        "--since",
        _fmt_journal(since),
        "--until",
        _fmt_journal(until),
        "-n",
        str(max_lines),
    ]
    if units:
        for unit in units:
            cmd.extend(["-u", unit])
    else:
        cmd.extend(["-p", "mail", "-p", "err", "-p", "warning", "-p", "info"])
    result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=180)
    if result.returncode not in (0, 1):
        detail = (result.stderr or result.stdout or "journalctl failed").strip()
        return [f"# Ошибка journalctl: {detail}"]
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    return lines or ["# Записей за период нет"]


def _tail_file_bytes(path: Path, max_bytes: int = 8_000_000) -> list[str]:
    if not path.is_file():
        return [f"# Файл не найден: {path}"]
    size = path.stat().st_size
    with path.open("rb") as handle:
        if size > max_bytes:
            handle.seek(size - max_bytes)
            handle.readline()
        data = handle.read().decode("utf-8", errors="replace")
    lines = [line for line in data.splitlines() if line.strip()]
    return lines or ["# Файл пуст"]


def _collect_source(name: str, units: list[str], since: datetime, until: datetime) -> list[str]:
    lines = _run_journalctl(units, since, until)
    journal_failed = lines and lines[0].startswith("# Ошибка journalctl")
    only_empty = len(lines) == 1 and lines[0].startswith("# Записей")
    if journal_failed or only_empty:
        cfg = get_config().paths
        file_map = {
            "mail": cfg.maillog,
            "dovecot": cfg.dovecot_log,
            "iredapd": cfg.iredapd_log,
            "system": cfg.messages_log,
        }
        file_path = Path(file_map.get(name, ""))
        file_lines = _tail_file_bytes(file_path)
        header = [
            f"# Источник: файл {file_path} (journalctl недоступен или пуст)",
            f"# Период запрошен: {_fmt_journal(since)} — {_fmt_journal(until)}",
            f"# Внимание: из файла взят хвост, без точной обрезки по времени.",
            "",
        ]
        return header + file_lines
    header = [
        f"# Источник: journalctl {', '.join(units) if units else 'system/mail'}",
        f"# Период: {_fmt_journal(since)} — {_fmt_journal(until)}",
        "",
    ]
    return header + lines


def create_archive(
    since: datetime | None = None,
    until: datetime | None = None,
    *,
    label: str = "manual",
) -> dict[str, Any]:
    now = datetime.now()
    until_dt = until or now
    since_dt = since or (until_dt - timedelta(hours=24))
    if since_dt >= until_dt:
        raise ValueError("Начало периода должно быть раньше конца")
    # Защита от слишком больших выгрузок
    if until_dt - since_dt > timedelta(days=7):
        raise ValueError("Максимальный период выгрузки — 7 суток")

    base_id = now.strftime("%Y%m%d_%H%M%S")
    if label and label != "manual":
        safe_label = re.sub(r"[^a-z0-9-]+", "-", label.lower()).strip("-")[:32]
        if safe_label:
            base_id = f"{base_id}_{safe_label}"

    root = _archives_root()
    archive_id = base_id
    folder = root / archive_id
    suffix = 1
    while folder.exists():
        archive_id = f"{base_id}-{suffix}"
        folder = root / archive_id
        suffix += 1
    folder.mkdir(parents=True, exist_ok=False)

    files_meta: list[dict[str, Any]] = []
    for name, units in ARCHIVE_SOURCES.items():
        content_lines = _collect_source(name, units, since_dt, until_dt)
        file_path = folder / f"{name}.log"
        text = "\n".join(content_lines) + "\n"
        file_path.write_text(text, encoding="utf-8")
        files_meta.append(
            {
                "name": file_path.name,
                "bytes": file_path.stat().st_size,
                "lines": max(0, len(content_lines) - 3),
            }
        )

    meta = {
        "id": archive_id,
        "label": label,
        "created_at": now.isoformat(timespec="seconds"),
        "since": since_dt.isoformat(timespec="seconds"),
        "until": until_dt.isoformat(timespec="seconds"),
        "path": str(folder),
        "files": files_meta,
    }
    (folder / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    zip_path = root / f"{archive_id}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in folder.iterdir():
            if item.is_file():
                zf.write(item, arcname=f"{archive_id}/{item.name}")
    meta["zip_path"] = str(zip_path)
    meta["zip_bytes"] = zip_path.stat().st_size
    (folder / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return meta


def create_archive_from_params(since: str | None, until: str | None, label: str = "manual") -> dict[str, Any]:
    now = datetime.now()
    until_dt = _parse_dt(until, now)
    since_dt = _parse_dt(since, until_dt - timedelta(hours=24))
    return create_archive(since_dt, until_dt, label=label)


def list_archives(limit: int = 50) -> list[dict[str, Any]]:
    root = _archives_root()
    items: list[dict[str, Any]] = []
    for folder in sorted(root.iterdir(), reverse=True):
        if not folder.is_dir():
            continue
        meta_file = folder / "meta.json"
        if meta_file.is_file():
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
            except Exception:
                meta = {"id": folder.name, "path": str(folder)}
        else:
            meta = {"id": folder.name, "path": str(folder)}
        zip_path = root / f"{folder.name}.zip"
        meta["has_zip"] = zip_path.is_file()
        if zip_path.is_file():
            meta["zip_bytes"] = zip_path.stat().st_size
            meta["zip_path"] = str(zip_path)
        items.append(meta)
        if len(items) >= limit:
            break
    return items


def get_archive_zip(archive_id: str) -> Path:
    if not SAFE_ID_RE.match(archive_id):
        raise ValueError("Некорректный id архива")
    zip_path = _archives_root() / f"{archive_id}.zip"
    if not zip_path.is_file():
        folder = _archives_root() / archive_id
        if not folder.is_dir():
            raise FileNotFoundError(f"Архив не найден: {archive_id}")
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for item in folder.iterdir():
                if item.is_file():
                    zf.write(item, arcname=f"{archive_id}/{item.name}")
    return zip_path


def cleanup_old_archives(retention_days: int | None = None) -> int:
    cfg = get_config()
    days = retention_days
    if days is None:
        days = int(getattr(cfg.log_collector, "archive_retention_days", 14) or 14)
    cutoff = datetime.now() - timedelta(days=max(1, days))
    root = _archives_root()
    removed = 0
    for item in root.iterdir():
        try:
            mtime = datetime.fromtimestamp(item.stat().st_mtime)
        except OSError:
            continue
        if mtime >= cutoff:
            continue
        if item.is_dir():
            shutil.rmtree(item, ignore_errors=True)
            removed += 1
        elif item.is_file() and item.suffix == ".zip":
            item.unlink(missing_ok=True)
            removed += 1
    return removed


def maybe_auto_archive(last_run: datetime | None) -> tuple[datetime | None, dict[str, Any] | None]:
    """Снимок за прошедший интервал, если пора. Возвращает (новый last_run, meta|None)."""
    cfg = get_config()
    if not getattr(cfg.log_collector, "archive_enabled", True):
        return last_run, None
    interval_h = float(getattr(cfg.log_collector, "archive_interval_hours", 1) or 1)
    interval = timedelta(hours=max(0.25, interval_h))
    now = datetime.now()
    if last_run and now - last_run < interval:
        return last_run, None
    until = now.replace(minute=0, second=0, microsecond=0)
    if until <= now - interval:
        until = now
    since = until - interval
    try:
        meta = create_archive(since, until, label="auto")
        cleanup_old_archives()
        return now, meta
    except Exception:
        return last_run or now, None


def archives_dir_info() -> dict[str, Any]:
    root = _archives_root()
    return {
        "path": str(root),
        "count": len([p for p in root.iterdir() if p.is_dir()]),
    }
