from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import get_config

_STATUS_LOCK = threading.Lock()
_RUN_LOCK = threading.Lock()
_running = False
_last_started: str | None = None
_last_finished: str | None = None
_last_ok: bool | None = None
_last_error: str | None = None
_last_archive: str | None = None

_FORBIDDEN_PREFIXES = (
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib64",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/sys",
    "/tmp",
    "/usr",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _status_path() -> Path:
    return Path("/var/lib/mailpanel/backup_status.json")


def _load_persisted() -> dict[str, Any]:
    path = _status_path()
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _persist() -> None:
    path = _status_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "last_started": _last_started,
            "last_finished": _last_finished,
            "last_ok": _last_ok,
            "last_error": _last_error,
            "last_archive": _last_archive,
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def _ensure_memory_from_disk() -> None:
    global _last_started, _last_finished, _last_ok, _last_error, _last_archive
    if _last_finished is not None or _last_started is not None:
        return
    data = _load_persisted()
    _last_started = data.get("last_started")
    _last_finished = data.get("last_finished")
    _last_ok = data.get("last_ok")
    _last_error = data.get("last_error")
    _last_archive = data.get("last_archive")


def validate_backup_directory(raw: str) -> Path:
    text = (raw or "").strip()
    if not text:
        raise ValueError("Укажите каталог для бэкапов")
    if ".." in text.split("/"):
        raise ValueError("Путь не должен содержать '..'")
    path = Path(text).expanduser()
    if not path.is_absolute():
        raise ValueError("Каталог должен быть абсолютным путём (например /var/backups/mailpanel)")
    resolved = path.resolve(strict=False)
    s = str(resolved)
    if s == "/":
        raise ValueError("Нельзя использовать корень /")
    for prefix in _FORBIDDEN_PREFIXES:
        if s == prefix or s.startswith(prefix + "/"):
            raise ValueError(f"Каталог не должен быть внутри {prefix}")
    if s == "/opt" or s.startswith("/opt/"):
        # /opt/mailpanel нельзя; /opt/backups — ок, но безопаснее запретить весь /opt
        if s == "/opt/mailpanel" or s.startswith("/opt/mailpanel/"):
            raise ValueError("Нельзя писать бэкапы внутрь /opt/mailpanel")
    if not re.fullmatch(r"[A-Za-z0-9_./\-]+", s):
        raise ValueError("В пути допустимы только буквы, цифры, / . _ -")
    return resolved


def ensure_backup_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError(f"Не каталог: {path}")
    if not os.access(path, os.W_OK):
        raise ValueError(f"Нет права записи в {path}")
    return path


def script_path() -> Path:
    candidates = (
        Path("/opt/mailpanel/scripts/mailpanel-backup.sh"),
        Path(__file__).resolve().parents[3] / "scripts" / "mailpanel-backup.sh",
    )
    for p in candidates:
        if p.is_file():
            return p
    raise FileNotFoundError("mailpanel-backup.sh не найден")


def get_runtime_status() -> dict[str, Any]:
    with _STATUS_LOCK:
        _ensure_memory_from_disk()
        return {
            "running": _running,
            "last_started": _last_started,
            "last_finished": _last_finished,
            "last_ok": _last_ok,
            "last_error": _last_error,
            "last_archive": _last_archive,
        }


def list_backups(directory: str | None = None) -> list[dict[str, Any]]:
    cfg = get_config().backup
    root = validate_backup_directory(directory or cfg.directory)
    if not root.is_dir():
        return []
    items: list[dict[str, Any]] = []
    for p in sorted(root.glob("*.tgz"), key=lambda x: x.stat().st_mtime, reverse=True):
        st = p.stat()
        items.append(
            {
                "name": p.name,
                "path": str(p),
                "size_bytes": st.st_size,
                "mtime": datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(timespec="seconds"),
            }
        )
    return items[:100]


def _set_running(value: bool) -> None:
    global _running
    with _STATUS_LOCK:
        _running = value


def run_backup(trigger: str = "manual") -> dict[str, Any]:
    """Синхронный запуск бэкапа. Не вызывать из HTTP без фонового потока при длинных бэкапах."""
    global _last_started, _last_finished, _last_ok, _last_error, _last_archive

    if not _RUN_LOCK.acquire(blocking=False):
        raise RuntimeError("Бэкап уже выполняется")

    cfg = get_config().backup
    try:
        dest = ensure_backup_directory(validate_backup_directory(cfg.directory))
        script = script_path()
        with _STATUS_LOCK:
            _last_started = _now_iso()
            _last_error = None
            _last_ok = None
            _running = True
            _persist()

        env = os.environ.copy()
        env["MAILPANEL_BACKUP_KEEP_DAYS"] = str(int(cfg.retention_days))
        # не копировать huge дерево в home вызывающего — панель root
        env.pop("SUDO_USER", None)

        result = subprocess.run(
            ["bash", str(script), str(dest)],
            capture_output=True,
            text=True,
            check=False,
            timeout=max(600, int(cfg.timeout_seconds)),
            env=env,
        )
        out = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
        archive = None
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("архив:") or "архив:" in line.lower():
                # "  архив:   /path/file.tgz  (1.2G)"
                m = re.search(r"(/[^\s]+\.tgz)", line)
                if m:
                    archive = m.group(1)
            elif line.endswith(".tgz") and line.startswith("/"):
                archive = line.split()[0]

        ok = result.returncode == 0
        with _STATUS_LOCK:
            _last_finished = _now_iso()
            _last_ok = ok
            _last_archive = archive
            if ok:
                _last_error = None
            else:
                tail = out.strip().splitlines()[-8:] if out.strip() else []
                _last_error = (
                    f"exit={result.returncode}; trigger={trigger}; "
                    + (" | ".join(tail) if tail else "см. journalctl -u mailpanel")
                )[:2000]
            _running = False
            _persist()

        if not ok:
            raise RuntimeError(_last_error or "Бэкап завершился с ошибкой")
        return {
            "ok": True,
            "trigger": trigger,
            "directory": str(dest),
            "archive": archive,
            "finished": _last_finished,
        }
    except Exception as exc:
        with _STATUS_LOCK:
            _last_finished = _now_iso()
            _last_ok = False
            _last_error = str(exc)[:2000]
            _running = False
            _persist()
        raise
    finally:
        _set_running(False)
        _RUN_LOCK.release()


def start_backup_async(trigger: str = "manual") -> dict[str, Any]:
    if _RUN_LOCK.locked() or _running:
        raise RuntimeError("Бэкап уже выполняется")

    def _worker() -> None:
        try:
            run_backup(trigger=trigger)
        except Exception:
            pass

    threading.Thread(target=_worker, daemon=True, name="mailpanel-backup").start()
    # дать потоку захватить lock
    time.sleep(0.15)
    return {"ok": True, "started": True, "trigger": trigger, **get_runtime_status()}


def maybe_auto_backup(last_ok_finished: datetime | None) -> datetime | None:
    """Вызывается из фонового цикла. Возвращает новое last_ok_finished."""
    cfg = get_config().backup
    if not cfg.enabled:
        return last_ok_finished
    if _RUN_LOCK.locked() or _running:
        return last_ok_finished

    interval_s = max(6 * 3600, float(cfg.interval_hours) * 3600)
    now = datetime.now().astimezone()
    if last_ok_finished is not None:
        elapsed = (now - last_ok_finished).total_seconds()
        if elapsed < interval_s:
            return last_ok_finished

    # если на диске уже есть свежий успешный статус — не гоняем сразу после рестарта
    st = get_runtime_status()
    if last_ok_finished is None and st.get("last_ok") and st.get("last_finished"):
        try:
            prev = datetime.fromisoformat(st["last_finished"])
            if (now - prev).total_seconds() < interval_s:
                return prev
        except Exception:
            pass

    try:
        result = run_backup(trigger="auto")
        finished = result.get("finished")
        if finished:
            return datetime.fromisoformat(finished)
        return now
    except Exception:
        return last_ok_finished


def run_loop() -> None:
    last_ok: datetime | None = None
    while True:
        cfg = get_config().backup
        try:
            last_ok = maybe_auto_backup(last_ok)
        except Exception:
            pass
        # проверяем раз в 5 минут; интервал бэкапа обычно сутки
        sleep_s = 60 if cfg.enabled else 300
        time.sleep(sleep_s)
