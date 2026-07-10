from __future__ import annotations

import re
import secrets
import subprocess
from pathlib import Path
from typing import Any

import yaml

from app.config import get_config

MARKER_FILTERS_BEGIN = "# MAILPANEL_FILTERS_BEGIN"
MARKER_FILTERS_END = "# MAILPANEL_FILTERS_END"
MARKER_SA_RULES_BEGIN = "# MAILPANEL_SA_FILTERS_BEGIN"
MARKER_SA_RULES_END = "# MAILPANEL_SA_FILTERS_END"
MARKER_CUSTOM_HOOK_BEGIN = "# MAILPANEL_CUSTOM_HOOK_BEGIN"
MARKER_CUSTOM_HOOK_END = "# MAILPANEL_CUSTOM_HOOK_END"

FILTER_SCORE = 100.0
VALID_FIELDS = {"subject", "body"}
FIELD_LABELS = {"subject": "Тема", "body": "Текст"}
RULE_ID_RE = re.compile(r"^[a-z0-9]{6,16}$")


class ContentFilterError(RuntimeError):
    pass


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def content_filters_path() -> Path:
    default = _project_root() / "data" / "content_filters.yaml"
    return Path(getattr(get_config().paths, "content_filters_file", str(default)))


def spamassassin_filters_path() -> Path:
    default = Path("/etc/mail/spamassassin/mailpanel_filters.cf")
    configured = getattr(get_config().paths, "spamassassin_filters_file", None)
    return Path(configured) if configured else default


def amavis_custom_filters_path() -> Path:
    default = Path("/etc/mailpanel/amavis_custom_filters.conf")
    configured = getattr(get_config().paths, "amavis_custom_filters_file", None)
    return Path(configured) if configured else default


def amavisd_config_path() -> Path:
    from app.services.amavis_policy import amavisd_config_path as policy_path

    return policy_path()


def spamassassin_config_path() -> Path:
    configured = Path(get_config().paths.spamassassin_config)
    if configured.is_file():
        return configured
    for candidate in (
        configured,
        Path("/etc/mail/spamassassin/local.cf"),
        Path("/etc/spamassassin/local.cf"),
    ):
        if candidate.is_file():
            return candidate
    return configured


def _validate_pattern(pattern: str) -> str:
    text = pattern.strip()
    if not text:
        raise ValueError("Укажите текст для поиска")
    if len(text) > 200:
        raise ValueError("Текст поиска не длиннее 200 символов")
    if "\n" in text or "\r" in text:
        raise ValueError("Текст поиска не должен содержать переносы строк")
    return text


def _validate_field(field: str) -> str:
    value = field.strip().lower()
    if value not in VALID_FIELDS:
        raise ValueError("Поле должно быть subject или body")
    return value


def _validate_rule_id(rule_id: str) -> str:
    rule_id = rule_id.strip().lower()
    if not RULE_ID_RE.fullmatch(rule_id):
        raise ValueError("Некорректный идентификатор правила")
    return rule_id


def _read_filters_file() -> list[dict[str, Any]]:
    path = content_filters_path()
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
    filters = data.get("filters") or []
    if not isinstance(filters, list):
        return []
    return [item for item in filters if isinstance(item, dict)]


def _write_filters_file(filters: list[dict[str, Any]]) -> None:
    path = content_filters_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump({"filters": filters}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def _normalize_filter(raw: dict[str, Any]) -> dict[str, Any]:
    rule_id = _validate_rule_id(str(raw.get("id", "")))
    field = _validate_field(str(raw.get("field", "")))
    pattern = _validate_pattern(str(raw.get("pattern", "")))
    enabled = bool(raw.get("enabled", True))
    return {
        "id": rule_id,
        "field": field,
        "field_label": FIELD_LABELS[field],
        "pattern": pattern,
        "action": "quarantine",
        "action_label": "Карантин",
        "enabled": enabled,
    }


def _rule_name(rule: dict[str, Any]) -> str:
    prefix = "SUBJ" if rule["field"] == "subject" else "BODY"
    return f"MAILPANEL_{prefix}_{rule['id'].upper()}"


def _sa_regex(pattern: str) -> str:
    return re.escape(pattern)


def _perl_qr(pattern: str) -> str:
    safe = pattern.replace("\\", "\\\\").replace("\\E", "\\\\E")
    return f"qr/\\Q{safe}\\E/i"


def _perl_qr_variants(pattern: str) -> list[str]:
    """Plain text and RFC2047 quoted-printable Subject forms."""
    variants: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if not value or value in seen:
            return
        seen.add(value)
        variants.append(_perl_qr(value))

    add(pattern)
    try:
        import quopri

        qp = quopri.encodestring(pattern.encode("utf-8")).decode("ascii")
        qp = qp.replace("\n", "").strip().rstrip("=")
        add(f"=?UTF-8?Q?{qp}?=")
        add(f"=?utf-8?q?{qp}?=")
    except Exception:
        pass
    return variants


def _build_amavis_custom_package(filters: list[dict[str, Any]]) -> str:
    subject_patterns: list[str] = []
    body_patterns: list[str] = []
    for rule in _enabled_rules(filters):
        normalized = _normalize_filter(rule)
        perl_patterns = _perl_qr_variants(normalized["pattern"])
        if normalized["field"] == "subject":
            subject_patterns.extend(perl_patterns)
        else:
            body_patterns.append(_perl_qr(normalized["pattern"]))

    subject_block = "\n".join(f"  {item}," for item in subject_patterns) or ""
    body_block = "\n".join(f"  {item}," for item in body_patterns) or ""

    return f"""# Generated by MailPanel. Do not edit manually.
package Amavis::Custom;

use strict;
use warnings;
no warnings qw(uninitialized);

our @MAILPANEL_SUBJECT_PATTERNS = (
{subject_block}
);

our @MAILPANEL_BODY_PATTERNS = (
{body_block}
);

sub _subject_candidates {{
  my ($msginfo) = @_;
  my @values;
  my $raw = $msginfo->get_header_field_body('subject');
  push @values, $raw if defined $raw && length $raw;
  my @header = $msginfo->get_header_field('Subject');
  if (@header) {{
    my $joined = join(' ', @header);
    push @values, $joined if length $joined;
  }}
  push @values, _decode_header($raw) if defined $raw;
  my %seen;
  return grep {{ defined $_ && length $_ && !$seen{{$_}}++ }} @values;
}}

sub _match_patterns {{
  my ($values, $patterns, $field_name) = @_;
  $field_name = 'subject' unless defined $field_name && length $field_name;
  return ('', 0) unless $values && @$patterns;
  for my $value (@$values) {{
    for my $pat (@$patterns) {{
      return ($field_name, 1) if $value =~ $pat;
    }}
  }}
  return ('', 0);
}}

sub _match_mail {{
  my ($msginfo) = @_;
  my ($field, $matched) = _match_patterns([_subject_candidates($msginfo)], \\@MAILPANEL_SUBJECT_PATTERNS, 'subject');
  if (!$matched && @MAILPANEL_BODY_PATTERNS) {{
    my $body = _read_body_sample($msginfo);
    ($field, $matched) = _match_patterns([$body], \\@MAILPANEL_BODY_PATTERNS, 'body');
  }}
  return ($field, $matched);
}}

sub _tag_as_spam {{
  my ($msginfo, $field) = @_;
  Amavis::load_policy_bank('MAILPANEL_CONTENT');
  $msginfo->spam_level(999);
  $msginfo->add_contents_category(&main::CC_SPAM, 0);
  for my $r (@{{$msginfo->per_recip_data}}) {{
    $r->spam_level(999);
    $r->add_contents_category(&main::CC_SPAM, 0);
  }}
  Amavis::Util::do_log(0, "MAILPANEL: tagged spam (%s) <%s>", $field, $msginfo->sender || '?');
}}

sub new {{
  my ($class, $conn, $msginfo) = @_;
  return undef unless @MAILPANEL_SUBJECT_PATTERNS || @MAILPANEL_BODY_PATTERNS;
  bless {{}}, $class;
}}

sub _decode_header {{
  my ($value) = @_;
  return '' unless defined $value;
  local $1;
  $value =~ s/\\n([ \\t])/$1/sg;
  $value =~ s/^[ \\t]+//s;
  $value =~ s/[ \\t]+\\z//s;
  my $raw = $value;
  eval {{
    require MIME::Words;
    my $decoded = MIME::Words::decode_mime_words($raw);
    $value = $decoded if defined $decoded && length $decoded;
  }};
  return $value;
}}

sub _read_body_sample {{
  my ($msginfo) = @_;
  my $fn = $msginfo->mail_text_fn;
  return '' unless $fn && -f $fn;
  open my $fh, '<', $fn or return '';
  binmode($fh, ':raw');
  my $in_headers = 1;
  my $body = '';
  while (my $line = <$fh>) {{
    if ($in_headers) {{
      $in_headers = 0 if $line =~ /^\\r?$/;
      next;
    }}
    $body .= $line;
    last if length($body) > 131072;
  }}
  close $fh;
  return $body;
}}

sub checks {{
  my ($self, $conn, $msginfo) = @_;
  my ($field, $matched) = _match_mail($msginfo);
  return unless $matched;
  _tag_as_spam($msginfo, $field);
}}

sub before_send {{
  my ($self, $conn, $msginfo) = @_;
  my ($field, $matched) = _match_mail($msginfo);
  return unless $matched;
  _tag_as_spam($msginfo, $field);
}}

1;
"""


def _build_amavis_hook_block(filters: list[dict[str, Any]], custom_path: Path) -> str:
    do_line = f"do '{custom_path.as_posix()}';"
    return f"# Generated by MailPanel. Do not edit manually.\n{do_line}"


def _build_amavis_custom_filters(filters: list[dict[str, Any]]) -> str:
    return _build_amavis_custom_package(filters)


def _replace_hook_block(content: str, block: str) -> str:
    begin = MARKER_CUSTOM_HOOK_BEGIN
    end = MARKER_CUSTOM_HOOK_END
    start = content.find(begin)
    if start != -1:
        end_pos = content.find(end, start)
        if end_pos != -1:
            end_pos += len(end)
            return content[:start] + block + content[end_pos:]
    return content.rstrip() + "\n\n" + block + "\n"


def _ensure_amavisd_custom_hook(content: str, hook_block: str, custom_path: Path) -> str:
    block = f"{MARKER_CUSTOM_HOOK_BEGIN}\n{hook_block.rstrip()}\n{MARKER_CUSTOM_HOOK_END}"
    updated = _replace_hook_block(content, block)
    do_line = f"do '{custom_path.as_posix()}';"
    if do_line not in updated:
        raise ContentFilterError(
            f"Хук Amavis не подключён в amavisd.conf (нет {do_line!r})."
        )
    return updated


def _enabled_rules(filters: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enabled: list[dict[str, Any]] = []
    for item in filters:
        if not item.get("enabled"):
            continue
        enabled.append(
            {
                "id": str(item.get("id", "")),
                "field": str(item.get("field", "")),
                "pattern": str(item.get("pattern", "")),
                "enabled": True,
            }
        )
    return enabled


def _build_spamassassin_rule_lines(filters: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for rule in _enabled_rules(filters):
        normalized = _normalize_filter(rule)
        name = _rule_name(normalized)
        regex = _sa_regex(normalized["pattern"])
        if normalized["field"] == "subject":
            lines.append(f"header {name} Subject =~ /{regex}/i")
        else:
            lines.append(f"body {name} /{regex}/i")
        lines.append(f"score {name} {FILTER_SCORE:g}")
        lines.append(f"describe {name} MailPanel content filter ({normalized['field']})")
        lines.append("")
    return lines


def _build_spamassassin_rules(filters: list[dict[str, Any]]) -> str:
    lines = [
        "# Generated by MailPanel. Do not edit manually.",
        MARKER_FILTERS_BEGIN,
        "# Incoming content filters: high score -> spam quarantine in Amavis.",
    ]
    rule_lines = _build_spamassassin_rule_lines(filters)
    if rule_lines:
        lines.extend(rule_lines)
    else:
        lines.append("# No active rules.")
    lines.append(MARKER_FILTERS_END)
    return "\n".join(lines).rstrip() + "\n"


def _ensure_local_cf_rules_block(content: str, filters: list[dict[str, Any]]) -> str:
    rule_lines = _build_spamassassin_rule_lines(filters)
    if rule_lines:
        inner = "\n".join(rule_lines).rstrip()
    else:
        inner = "# No active MailPanel content filter rules."
    block = f"{MARKER_SA_RULES_BEGIN}\n{inner}\n{MARKER_SA_RULES_END}"
    marker_pattern = (
        re.escape(MARKER_SA_RULES_BEGIN) + r".*?" + re.escape(MARKER_SA_RULES_END)
    )
    if re.search(marker_pattern, content, flags=re.DOTALL):
        return re.sub(marker_pattern, block, content, count=1, flags=re.DOTALL)
    # Remove legacy include-only block if present.
    legacy_include = (
        re.escape(MARKER_SA_RULES_BEGIN)
        + r"\ninclude .*?\n"
        + re.escape(MARKER_SA_RULES_END)
    )
    content = re.sub(legacy_include, block, content, count=1, flags=re.DOTALL)
    if MARKER_SA_RULES_BEGIN in content:
        return re.sub(marker_pattern, block, content, count=1, flags=re.DOTALL)
    return content.rstrip() + "\n\n" + block + "\n"


def _ensure_required_score(content: str) -> str:
    if re.search(r"^required_score\s+", content, flags=re.MULTILINE):
        return content
    return content.rstrip() + "\n\nrequired_score 5.0\n"


def _count_patterns_in_custom_file(path: Path) -> tuple[int, int]:
    if not path.is_file():
        return 0, 0
    text = path.read_text(encoding="utf-8", errors="replace")
    subject_block = re.search(
        r"@MAILPANEL_SUBJECT_PATTERNS\s*=\s*\((.*?)\);",
        text,
        flags=re.DOTALL,
    )
    body_block = re.search(
        r"@MAILPANEL_BODY_PATTERNS\s*=\s*\((.*?)\);",
        text,
        flags=re.DOTALL,
    )
    subject_count = len(re.findall(r"qr/", subject_block.group(1))) if subject_block else 0
    body_count = len(re.findall(r"qr/", body_block.group(1))) if body_block else 0
    return subject_count, body_count


def _amavisd_active() -> bool:
    result = subprocess.run(
        ["systemctl", "is-active", "amavisd"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    return result.stdout.strip() == "active"


def _amavisd_journal_tail(lines: int = 8) -> str:
    result = subprocess.run(
        ["journalctl", "-u", "amavisd", "-n", str(lines), "--no-pager"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    return (result.stdout or result.stderr or "").strip()


def _restart_amavisd() -> str | None:
    result = subprocess.run(
        ["systemctl", "restart", "amavisd"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        return detail or "systemctl restart amavisd failed"
    if not _amavisd_active():
        return "amavisd не запустился после restart (systemctl is-active != active)"
    return None


def _run_spamassassin_lint(local_cf: Path) -> str | None:
    result = subprocess.run(
        ["spamassassin", "--lint", "-C", str(local_cf.parent)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if result.returncode == 0:
        return None
    return (result.stderr or result.stdout or "spamassassin --lint failed").strip()


def _sync_amavis_policy(filters: list[dict[str, Any]]) -> list[str]:
    warnings: list[str] = []
    active = bool(_enabled_rules(filters))
    try:
        from app.services import amavis_policy

        policy = amavis_policy.read_mail_policy()
        if active and not policy.get("scan_internal_mail"):
            amavis_policy.write_mail_policy(True)
            warnings.append(
                "Автоматически включена проверка внутренней почты в Amavis "
                "(нужна для правил между ящиками на этом сервере)."
            )
        amavis_policy.set_content_filters_active(active)
        if active:
            warnings.append(
                "Антивирус Amavis отключён для работы правил (ClamAV не установлен, "
                "иначе письма проходят как UNCHECKED без проверки контента)."
            )
    except Exception as exc:
        warnings.append(f"Не удалось обновить политику Amavis: {exc}")
    return warnings


def _diagnostics(filters: list[dict[str, Any]]) -> dict[str, Any]:
    local_cf = spamassassin_config_path()
    local_content = local_cf.read_text(encoding="utf-8", errors="replace") if local_cf.is_file() else ""
    rules_in_local_cf = "header MAILPANEL_" in local_content or "body MAILPANEL_" in local_content
    custom_path = amavis_custom_filters_path()
    amavis_path = amavisd_config_path()
    amavis_content = amavis_path.read_text(encoding="utf-8", errors="replace") if amavis_path.is_file() else ""
    do_line = f"do '{custom_path.as_posix()}';"
    custom_text = custom_path.read_text(encoding="utf-8", errors="replace") if custom_path.is_file() else ""
    amavis_hook_loaded = (
        MARKER_CUSTOM_HOOK_BEGIN in amavis_content
        and do_line in amavis_content
        and "package Amavis::Custom" in custom_text
    )
    scan_internal_mail = False
    try:
        from app.services import amavis_policy

        scan_internal_mail = bool(amavis_policy.read_mail_policy().get("scan_internal_mail"))
    except Exception:
        scan_internal_mail = False
    subject_patterns, body_patterns = _count_patterns_in_custom_file(custom_path)
    include_path = None
    include_content = ""
    try:
        from app.services.amavis_policy import amavis_include_path

        include_path = amavis_include_path()
        if include_path.is_file():
            include_content = include_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        pass
    return {
        "local_cf": str(local_cf),
        "local_cf_exists": local_cf.is_file(),
        "rules_in_local_cf": rules_in_local_cf,
        "amavis_custom_file": str(custom_path),
        "amavis_custom_exists": custom_path.is_file(),
        "amavis_hook_loaded": amavis_hook_loaded,
        "amavisd_active": _amavisd_active(),
        "hook_subject_patterns": subject_patterns,
        "hook_body_patterns": body_patterns,
        "av_bypass_in_hook": bool(
            subject_patterns or body_patterns
        )
        and "@av_scanners = ();" in include_content,
        "amavis_include_file": str(include_path) if include_path else "",
        "active_rules": len(_enabled_rules(filters)),
        "scan_internal_mail": scan_internal_mail,
    }


def _apply_filters(filters: list[dict[str, Any]]) -> list[str]:
    warnings: list[str] = []
    filters_path = spamassassin_filters_path()
    filters_path.parent.mkdir(parents=True, exist_ok=True)
    filters_path.write_text(_build_spamassassin_rules(filters), encoding="utf-8")

    custom_content = _build_amavis_custom_package(filters)
    custom_path = amavis_custom_filters_path()
    custom_path.parent.mkdir(parents=True, exist_ok=True)
    if "package Amavis::Custom" not in custom_content:
        raise ContentFilterError("Сборка Amavis::Custom не удалась.")
    custom_path.write_text(custom_content, encoding="utf-8")

    hook_block = _build_amavis_hook_block(filters, custom_path)

    amavis_path = amavisd_config_path()
    if not amavis_path.is_file():
        raise ContentFilterError(
            f"Файл amavisd.conf не найден: {amavis_path}. "
            "Проверьте paths.amavisd_config в config.yaml"
        )
    amavis_backup = amavis_path.read_text(encoding="utf-8", errors="replace")
    try:
        amavis_content = _ensure_amavisd_custom_hook(amavis_backup, hook_block, custom_path)
        amavis_path.write_text(amavis_content, encoding="utf-8")
        written = amavis_path.read_text(encoding="utf-8", errors="replace")
        if f"do '{custom_path.as_posix()}';" not in written:
            raise ContentFilterError(f"Запись в {amavis_path} не подтверждена.")
    except OSError as exc:
        raise ContentFilterError(f"Не удалось обновить {amavis_path}: {exc}") from exc

    local_cf = spamassassin_config_path()
    if local_cf.is_file():
        try:
            content = local_cf.read_text(encoding="utf-8", errors="replace")
            content = _ensure_required_score(content)
            content = _ensure_local_cf_rules_block(content, filters)
            local_cf.write_text(content, encoding="utf-8")
            lint_error = _run_spamassassin_lint(local_cf)
            if lint_error:
                warnings.append(f"Проверка spamassassin --lint: {lint_error[:300]}")
        except OSError as exc:
            warnings.append(f"Не удалось обновить {local_cf}: {exc}")
    else:
        warnings.append(f"SpamAssassin local.cf не найден ({local_cf}), используется хук Amavis.")

    warnings.extend(_sync_amavis_policy(filters))
    restart_error = _restart_amavisd()
    if restart_error:
        try:
            amavis_path.write_text(amavis_backup, encoding="utf-8")
            _restart_amavisd()
        except OSError:
            pass
        raise ContentFilterError(
            f"Amavis не запустился после применения правил: {restart_error[:300]}. "
            f"Лог: {_amavisd_journal_tail()[:700]}"
        )
    return warnings


def list_content_filters() -> dict[str, Any]:
    raw_filters = _read_filters_file()
    filters = [_normalize_filter(item) for item in raw_filters]
    diagnostics = _diagnostics(raw_filters)
    notes = [
        "Правила работают через хук Amavis (включая письма между ящиками на сервере).",
        "При совпадении Amavis переключает политику на карантин (обход MYUSERS D_PASS).",
        "Дополнительно дублируются в SpamAssassin для внешней почты.",
        "При совпадении письмо попадает в карантин (тип «Спам»).",
        "Поиск без учёта регистра, по вхождению указанного текста.",
        "Отправители из белого списка могут обходить проверку SpamAssassin.",
    ]
    if diagnostics["active_rules"] and not diagnostics.get("amavis_hook_loaded"):
        notes.insert(
            0,
            "Хук Amavis не подключён в amavisd.conf — нажмите «Применить правила заново».",
        )
    return {
        "items": filters,
        "total": len(filters),
        "source_file": str(content_filters_path()),
        "rules_file": str(spamassassin_filters_path()),
        "diagnostics": diagnostics,
        "notes": notes,
    }


def create_content_filter(field: str, pattern: str, enabled: bool = True) -> dict[str, Any]:
    filters = _read_filters_file()
    rule = _normalize_filter(
        {
            "id": secrets.token_hex(4),
            "field": field,
            "pattern": pattern,
            "enabled": enabled,
        }
    )
    filters.append(
        {
            "id": rule["id"],
            "field": rule["field"],
            "pattern": rule["pattern"],
            "enabled": rule["enabled"],
        }
    )
    _write_filters_file(filters)
    try:
        warnings = _apply_filters(filters)
    except Exception as exc:
        raise ContentFilterError(str(exc)) from exc
    if warnings:
        rule["warnings"] = warnings
    return rule


def update_content_filter(
    rule_id: str,
    *,
    field: str | None = None,
    pattern: str | None = None,
    enabled: bool | None = None,
) -> dict[str, Any]:
    rule_id = _validate_rule_id(rule_id)
    filters = _read_filters_file()
    index = next((idx for idx, item in enumerate(filters) if str(item.get("id")) == rule_id), None)
    if index is None:
        raise ValueError(f"Правило не найдено: {rule_id}")

    current = dict(filters[index])
    if field is not None:
        current["field"] = _validate_field(field)
    if pattern is not None:
        current["pattern"] = _validate_pattern(pattern)
    if enabled is not None:
        current["enabled"] = bool(enabled)

    rule = _normalize_filter(current)
    filters[index] = {
        "id": rule["id"],
        "field": rule["field"],
        "pattern": rule["pattern"],
        "enabled": rule["enabled"],
    }
    _write_filters_file(filters)
    try:
        warnings = _apply_filters(filters)
    except Exception as exc:
        raise ContentFilterError(str(exc)) from exc
    if warnings:
        rule["warnings"] = warnings
    return rule


def delete_content_filter(rule_id: str) -> None:
    rule_id = _validate_rule_id(rule_id)
    filters = _read_filters_file()
    next_filters = [item for item in filters if str(item.get("id")) != rule_id]
    if len(next_filters) == len(filters):
        raise ValueError(f"Правило не найдено: {rule_id}")
    _write_filters_file(next_filters)
    try:
        _apply_filters(next_filters)
    except Exception as exc:
        raise ContentFilterError(str(exc)) from exc


def reapply_content_filters() -> dict[str, Any]:
    filters = _read_filters_file()
    warnings = _apply_filters(filters)
    return {"ok": True, "warnings": warnings, "diagnostics": _diagnostics(filters)}
