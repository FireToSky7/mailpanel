from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

import yaml

from app.config import get_config

MARKER_BANNED_BEGIN = "# MAILPANEL_BANNED_BEGIN"
MARKER_BANNED_END = "# MAILPANEL_BANNED_END"
MARKER_INCLUDE = "# MAILPANEL_INCLUDE"
MARKER_POLICY_BEGIN = "# MAILPANEL_POLICY_BEGIN"
MARKER_POLICY_END = "# MAILPANEL_POLICY_END"

EXTENSION_RE = re.compile(r"^[a-z0-9]{1,16}$")
QR_EXT_RE = re.compile(r"qr'[^(]*\(([^)]+)\)[^']*'\s*i?", re.IGNORECASE)
BANNED_BLOCK_RE = re.compile(
    r"(\$banned_filename_re\s*=\s*new_RE\s*\()(.*?)(\)\s*;)",
    re.DOTALL,
)

DEFAULT_EXTENSIONS = (
    "exe",
    "scr",
    "bat",
    "cmd",
    "com",
    "pif",
    "vbs",
    "dll",
    "msi",
    "jar",
    "ps1",
    "hta",
    "reg",
)


class AmavisPolicyError(RuntimeError):
    pass


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def amavisd_config_path() -> Path:
    return Path(getattr(get_config().paths, "amavisd_config", "/etc/amavisd/amavisd.conf"))


def banned_extensions_path() -> Path:
    default = _project_root() / "data" / "banned_extensions.txt"
    return Path(getattr(get_config().paths, "banned_extensions_file", str(default)))


def antispam_policy_path() -> Path:
    default = _project_root() / "data" / "antispam_policy.yaml"
    return Path(getattr(get_config().paths, "antispam_policy_file", str(default)))


def amavis_include_path() -> Path:
    return antispam_policy_path().parent / "amavis_mailpanel.inc"


def _normalize_extension(value: str) -> str:
    value = value.strip().lower().lstrip(".")
    if not EXTENSION_RE.fullmatch(value):
        raise ValueError(f"Некорректное расширение: {value}")
    return value


def _format_extension(value: str) -> str:
    return f".{_normalize_extension(value)}"


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(lines) + ("\n" if lines else "")
    path.write_text(body, encoding="utf-8")


def _parse_extensions_from_qr(content: str) -> list[str]:
    found: set[str] = set()
    for match in QR_EXT_RE.finditer(content):
        group = match.group(1)
        for part in group.split("|"):
            part = part.strip().lower().lstrip(".")
            if EXTENSION_RE.fullmatch(part):
                found.add(part)
    return sorted(found)


def _read_policy_file() -> dict[str, Any]:
    path = antispam_policy_path()
    if not path.exists():
        return {"scan_internal_mail": False, "content_filters_active": False}
    data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
    return {
        "scan_internal_mail": bool(data.get("scan_internal_mail", False)),
        "content_filters_active": bool(data.get("content_filters_active", False)),
    }


def _write_policy_file(
    *,
    scan_internal_mail: bool | None = None,
    content_filters_active: bool | None = None,
) -> dict[str, Any]:
    policy = _read_policy_file()
    if scan_internal_mail is not None:
        policy["scan_internal_mail"] = scan_internal_mail
    if content_filters_active is not None:
        policy["content_filters_active"] = content_filters_active
    path = antispam_policy_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(policy, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return policy


def _build_banned_qr(extensions: list[str]) -> str:
    normalized = sorted({_normalize_extension(ext) for ext in extensions})
    if not normalized:
        raise AmavisPolicyError("Список запрещённых расширений не может быть пустым")
    joined = "|".join(normalized)
    return f"  {MARKER_BANNED_BEGIN}\n  qr'\\.({joined})$'i,\n  {MARKER_BANNED_END}"


def _ensure_banned_block(content: str, extensions: list[str]) -> str:
    qr_block = _build_banned_qr(extensions)
    match = BANNED_BLOCK_RE.search(content)
    if not match:
        raise AmavisPolicyError(
            "В amavisd.conf не найден блок $banned_filename_re = new_RE(...). "
            "Добавьте маркеры вручную или проверьте путь amavisd_config."
        )
    inner = match.group(2)
    if MARKER_BANNED_BEGIN in inner and MARKER_BANNED_END in inner:
        inner = re.sub(
            re.escape(MARKER_BANNED_BEGIN) + r".*?" + re.escape(MARKER_BANNED_END),
            _build_banned_qr(extensions).strip(),
            inner,
            count=1,
            flags=re.DOTALL,
        )
    else:
        inner = inner.rstrip() + "\n" + qr_block + "\n"
    return content[: match.start(2)] + inner + content[match.end(2) :]


def _build_include_file(
    extensions: list[str],
    scan_internal_mail: bool,
    content_filters_active: bool = False,
    custom_filters_path: Path | None = None,
) -> str:
    joined = "|".join(sorted({_normalize_extension(ext) for ext in extensions}))
    scan_flag = 1 if scan_internal_mail else 0
    virus_bypass_block = ""
    if content_filters_active:
        virus_bypass_block = """
# ClamAV is not installed; AV failure otherwise short-circuits content filter hooks.
@bypass_virus_checks_maps = (1);
@bypass_spam_checks_maps = (0);
$bypass_spam_checks = 0;
@av_scanners = ();
@av_scanners_backup = ();
foreach my $bank (keys %policy_bank) {
  next unless ref($policy_bank{$bank}) eq 'HASH';
  $policy_bank{$bank}{'bypass_virus_checks_maps'} = [1];
  $policy_bank{$bank}{'bypass_spam_checks_maps'} = [0];
}
$policy_bank{'MAILPANEL_CONTENT'} = {
  final_spam_destiny => D_QUARANTINE,
  final_banned_destiny => D_QUARANTINE,
  spam_quarantine_to => $spam_quarantine_to,
  spam_quarantine_method => $spam_quarantine_method,
};
"""
    custom_do_block = ""
    if content_filters_active and custom_filters_path:
        custom_do_block = f"""
# MailPanel content filter hooks (Amavis::Custom + scanner)
do '{custom_filters_path.as_posix()}';
"""
    return f"""# Generated by MailPanel. Do not edit manually.
$mailpanel_scan_internal = {scan_flag};

# iRedMail often sets bypass_banned_checks_maps => [1]; force attachment checks.
foreach my $bank (keys %policy_bank) {{
  next unless ref($policy_bank{{$bank}}) eq 'HASH';
  $policy_bank{{$bank}}{{'bypass_banned_checks_maps'}} = [0];
}}
{virus_bypass_block}
if ($mailpanel_scan_internal) {{
  $interface_policy{{'127.0.0.1'}} = 'ORIGINATING';
  $interface_policy{{'::1'}} = 'ORIGINATING';
  foreach my $bank (keys %policy_bank) {{
    next unless ref($policy_bank{{$bank}}) eq 'HASH';
    $policy_bank{{$bank}}{{'bypass_spam_checks_maps'}} = [0];
  }}
}}
{custom_do_block}
{MARKER_POLICY_BEGIN}
# scan_internal_mail={str(scan_internal_mail).lower()}
# content_filters_active={str(content_filters_active).lower()}
# banned_extensions={joined}
{MARKER_POLICY_END}
"""


def _include_line(include_path: Path) -> str:
    # amavis 2.14 on iRedMail does not provide include_config_file(); use Perl do.
    return f"do '{include_path.as_posix()}';"


def _ensure_include_line(content: str, include_path: Path) -> str:
    include_line = _include_line(include_path)
    legacy_line = f"include_config_file('{include_path.as_posix()}');"
    content = content.replace(legacy_line, include_line)
    if include_line in content:
        return content
    marker = f"{MARKER_INCLUDE}\n{include_line}\n"
    if MARKER_INCLUDE in content:
        return re.sub(
            re.escape(MARKER_INCLUDE) + r".*",
            marker.strip(),
            content,
            count=1,
        )
    return content.rstrip() + "\n\n" + marker + "\n"


def _detect_bypass_state(content: str) -> bool:
    return "bypass_banned_checks_maps => [1]" in content or "bypass_banned_checks_maps => [ 1 ]" in content


def _current_extensions() -> list[str]:
    return [
        _normalize_extension(item)
        for item in read_banned_extensions()["extensions"]
    ]


def refresh_mailpanel_include() -> None:
    policy = _read_policy_file()
    include_path = amavis_include_path()
    include_path.parent.mkdir(parents=True, exist_ok=True)
    custom_path = None
    if policy["content_filters_active"]:
        from app.services.content_filter_ops import amavis_custom_filters_path

        custom_path = amavis_custom_filters_path()
    include_path.write_text(
        _build_include_file(
            _current_extensions(),
            policy["scan_internal_mail"],
            policy["content_filters_active"],
            custom_path,
        ),
        encoding="utf-8",
    )


def set_content_filters_active(active: bool) -> None:
    _write_policy_file(content_filters_active=active)
    refresh_mailpanel_include()


def read_banned_extensions() -> dict[str, Any]:
    ext_path = banned_extensions_path()
    stored = [_normalize_extension(item) for item in _read_lines(ext_path)]
    amavis_path = amavisd_config_path()
    parsed: list[str] = []
    markers_present = False
    if amavis_path.exists():
        content = amavis_path.read_text(encoding="utf-8", errors="replace")
        markers_present = MARKER_BANNED_BEGIN in content and MARKER_BANNED_END in content
        if markers_present:
            block_match = re.search(
                re.escape(MARKER_BANNED_BEGIN) + r"(.*?)" + re.escape(MARKER_BANNED_END),
                content,
                re.DOTALL,
            )
            if block_match:
                parsed = _parse_extensions_from_qr(block_match.group(1))
    extensions = stored or parsed or list(DEFAULT_EXTENSIONS)
    return {
        "extensions": [_format_extension(ext) for ext in extensions],
        "markers_present": markers_present,
        "source_file": str(ext_path),
    }


def write_banned_extensions(extensions: list[str]) -> dict[str, Any]:
    normalized = sorted({_normalize_extension(ext) for ext in extensions})
    if not normalized:
        raise AmavisPolicyError("Укажите хотя бы одно расширение")

    ext_path = banned_extensions_path()
    _write_lines(ext_path, normalized)

    amavis_path = amavisd_config_path()
    if not amavis_path.exists():
        raise AmavisPolicyError(f"Файл amavisd.conf не найден: {amavis_path}")

    policy = _read_policy_file()
    content = amavis_path.read_text(encoding="utf-8", errors="replace")
    content = _ensure_banned_block(content, normalized)
    include_path = amavis_include_path()
    content = _ensure_include_line(content, include_path)
    amavis_path.write_text(content, encoding="utf-8")

    custom_path = None
    if policy["content_filters_active"]:
        from app.services.content_filter_ops import amavis_custom_filters_path

        custom_path = amavis_custom_filters_path()
    include_path.write_text(
        _build_include_file(
            normalized,
            policy["scan_internal_mail"],
            policy["content_filters_active"],
            custom_path,
        ),
        encoding="utf-8",
    )
    _restart_amavisd()
    return {"ok": True, "extensions": [_format_extension(ext) for ext in normalized]}


def read_mail_policy() -> dict[str, Any]:
    amavis_path = amavisd_config_path()
    content = amavis_path.read_text(encoding="utf-8", errors="replace") if amavis_path.exists() else ""
    policy = _read_policy_file()
    return {
        "scan_internal_mail": policy["scan_internal_mail"],
        "content_filters_active": policy["content_filters_active"],
        "include_present": "amavis_mailpanel.inc" in content,
        "bypass_banned_active": _detect_bypass_state(content),
        "notes": [
            "Проверка вложений принудительно включена для всех политик Amavis (обход bypass_banned_checks).",
            "Проверка внутренней почты дополнительно включает антиспам для localhost и политики ORIGINATING.",
            "При активных правилах контента антивирус отключается (ClamAV не установлен), чтобы хук Amavis успевал сработать.",
            "Письма через Roundcube (порт 587 с AUTH) обычно уже проходят через Amavis.",
            "Прямая локальная доставка с 127.0.0.1 без content_filter может обходить фильтр — это ограничение Postfix.",
        ],
    }


def write_mail_policy(scan_internal_mail: bool) -> dict[str, Any]:
    policy = _write_policy_file(scan_internal_mail=scan_internal_mail)

    amavis_path = amavisd_config_path()
    if not amavis_path.exists():
        raise AmavisPolicyError(f"Файл amavisd.conf не найден: {amavis_path}")

    content = amavis_path.read_text(encoding="utf-8", errors="replace")
    include_path = amavis_include_path()
    content = _ensure_include_line(content, include_path)
    amavis_path.write_text(content, encoding="utf-8")
    custom_path = None
    if policy["content_filters_active"]:
        from app.services.content_filter_ops import amavis_custom_filters_path

        custom_path = amavis_custom_filters_path()
    include_path.write_text(
        _build_include_file(
            _current_extensions(),
            policy["scan_internal_mail"],
            policy["content_filters_active"],
            custom_path,
        ),
        encoding="utf-8",
    )
    _restart_amavisd()
    return {"ok": True, "scan_internal_mail": scan_internal_mail}


def _restart_amavisd() -> None:
    subprocess.run(["systemctl", "restart", "amavisd"], check=False)
