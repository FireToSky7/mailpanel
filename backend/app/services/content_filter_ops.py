from __future__ import annotations

import re
import secrets
import subprocess
from itertools import product
from pathlib import Path
from typing import Any

import yaml

from app.config import get_config

MARKER_FILTERS_BEGIN = "# MAILPANEL_FILTERS_BEGIN"
MARKER_FILTERS_END = "# MAILPANEL_FILTERS_END"
MARKER_SA_RULES_BEGIN = "# MAILPANEL_SA_FILTERS_BEGIN"
MARKER_SA_RULES_END = "# MAILPANEL_SA_FILTERS_END"
MARKER_CUSTOM_HOOK_BEGIN = "# MAILPANEL_CUSTOM_HOOK_BEGIN"
MARKER_SIEVE_BEGIN = "# MAILPANEL_SIEVE_BEGIN"
MARKER_SIEVE_END = "# MAILPANEL_SIEVE_END"
MARKER_CUSTOM_HOOK_END = "# MAILPANEL_CUSTOM_HOOK_END"

FILTER_SCORE = 100.0
VALID_FIELDS = {"subject", "body", "from"}
FIELD_LABELS = {"subject": "Тема", "body": "Текст", "from": "Отправитель"}
VALID_ACTIONS = {"quarantine", "delete", "forward", "add_recipient"}
ACTIONS_NEED_ADDRESS = {"forward", "add_recipient"}
ACTION_LABELS = {
    "quarantine": "Карантин",
    "delete": "Удалить",
    "forward": "Переслать",
    "add_recipient": "Добавить получателя",
}
RULE_ID_RE = re.compile(r"^[a-z0-9]{6,16}$")
FORWARD_EMAIL_RE = re.compile(
    r"^[a-z0-9][a-z0-9._%+-]*@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$",
    re.IGNORECASE,
)
_CYRILLIC_FOLD_FROM = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
_CYRILLIC_FOLD_TO = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"


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


def amavis_late_policy_path() -> Path:
    default = Path("/etc/mailpanel/amavis_late_policy.inc")
    configured = getattr(get_config().paths, "amavis_late_policy_file", None)
    return Path(configured) if configured else default


def dovecot_global_sieve_path() -> Path:
    default = Path("/var/vmail/sieve/dovecot.sieve")
    configured = getattr(get_config().paths, "dovecot_global_sieve", str(default))
    return Path(configured)


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
        raise ValueError("Поле должно быть subject, body или from")
    return value


def _validate_action(action: str) -> str:
    value = (action or "quarantine").strip().lower()
    if value not in VALID_ACTIONS:
        raise ValueError(
            "Действие должно быть quarantine, delete, forward или add_recipient"
        )
    return value


def _validate_forward_to(forward_to: str | None, action: str) -> str:
    if action not in ACTIONS_NEED_ADDRESS:
        return ""
    value = (forward_to or "").strip().lower()
    if not value:
        raise ValueError("Укажите адрес получателя")
    if len(value) > 200:
        raise ValueError("Адрес получателя не длиннее 200 символов")
    if not FORWARD_EMAIL_RE.fullmatch(value):
        raise ValueError("Некорректный адрес получателя")
    return value


def _validate_rule_id(rule_id: str) -> str:
    rule_id = rule_id.strip().lower()
    if not RULE_ID_RE.fullmatch(rule_id):
        raise ValueError("Некорректный идентификатор правила")
    return rule_id


def _action_label(action: str, forward_to: str = "") -> str:
    label = ACTION_LABELS.get(action, action)
    if action in ACTIONS_NEED_ADDRESS and forward_to:
        return f"{label} → {forward_to}"
    return label


def _storage_filter(rule: dict[str, Any]) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": rule["id"],
        "field": rule["field"],
        "pattern": rule["pattern"],
        "action": rule["action"],
        "enabled": rule["enabled"],
    }
    if rule["action"] in ACTIONS_NEED_ADDRESS and rule.get("forward_to"):
        item["forward_to"] = rule["forward_to"]
    return item


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
    action = _validate_action(str(raw.get("action", "quarantine")))
    forward_to = _validate_forward_to(raw.get("forward_to"), action)
    enabled = bool(raw.get("enabled", True))
    return {
        "id": rule_id,
        "field": field,
        "field_label": FIELD_LABELS[field],
        "pattern": pattern,
        "action": action,
        "action_label": _action_label(action, forward_to),
        "forward_to": forward_to,
        "enabled": enabled,
    }


def _rule_name(rule: dict[str, Any]) -> str:
    prefix = {"subject": "SUBJ", "body": "BODY", "from": "FROM"}[rule["field"]]
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


def _sieve_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _case_permutations(text: str, limit: int = 64) -> list[str]:
    """All upper/lower combinations for short Cyrillic/Latin patterns (Sieve fallback)."""
    if not text:
        return []
    folded = text.casefold()
    options: list[list[str]] = []
    for ch in folded:
        variants = list(dict.fromkeys([ch, ch.lower(), ch.upper()]))
        options.append(variants)
    result: list[str] = []
    seen: set[str] = set()
    for combo in product(*options):
        if len(result) >= limit:
            break
        value = "".join(combo)
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result or [text]


def _sieve_required_extensions(filters: list[dict[str, Any]]) -> list[str]:
    extensions: list[str] = []
    for rule in _enabled_rules(filters):
        normalized = _normalize_filter(rule)
        if normalized["action"] == "quarantine" and "fileinto" not in extensions:
            extensions.append("fileinto")
        if normalized["field"] == "body" and "body" not in extensions:
            extensions.append("body")
    return extensions or ["fileinto"]


def _merge_sieve_requires(content: str, extensions: list[str]) -> str:
    needed = list(dict.fromkeys(extensions))
    req_line = "require [" + ", ".join(f'"{item}"' for item in needed) + "];"
    require_re = re.compile(r"^require\s+\[([^\]]*)\]\s*;", re.MULTILINE)
    match = require_re.search(content)
    if match:
        return content[: match.start()] + req_line + content[match.end() :]
    return req_line + "\n\n" + content.lstrip()


def _build_sieve_block(filters: list[dict[str, Any]]) -> str:
    blocks: list[str] = []
    for rule in _enabled_rules(filters):
        normalized = _normalize_filter(rule)
        # Пересылка / доп. получатель только через Amavis (глобальный Sieve
        # на ящике получателя иначе ломает доставку).
        if normalized["action"] in ACTIONS_NEED_ADDRESS:
            continue

        conditions: list[str] = []
        for pattern in _case_permutations(normalized["pattern"]):
            escaped = _sieve_escape(pattern)
            if normalized["field"] == "subject":
                conditions.append(f'header :contains "Subject" "{escaped}"')
            elif normalized["field"] == "from":
                conditions.append(f'header :contains "From" "{escaped}"')
            else:
                conditions.append(f'body :contains "{escaped}"')
        if not conditions:
            continue
        cond = ",\n  ".join(conditions)
        if normalized["action"] == "delete":
            action_lines = "  discard;\n  stop;"
        else:
            action_lines = '  fileinto "Junk";\n  stop;'
        blocks.append(f"if anyof (\n  {cond}\n) {{\n{action_lines}\n}}")
    if not blocks:
        return ""
    joined = "\n\n".join(blocks)
    return f"""{MARKER_SIEVE_BEGIN}
{joined}
{MARKER_SIEVE_END}
"""


def _ensure_dovecot_sieve_block(filters: list[dict[str, Any]]) -> list[str]:
    warnings: list[str] = []
    block = _build_sieve_block(filters)
    sieve_path = dovecot_global_sieve_path()
    if not block:
        if sieve_path.is_file():
            content = sieve_path.read_text(encoding="utf-8", errors="replace")
            if MARKER_SIEVE_BEGIN in content:
                content = re.sub(
                    re.escape(MARKER_SIEVE_BEGIN) + r".*?" + re.escape(MARKER_SIEVE_END) + r"\n?",
                    "",
                    content,
                    count=1,
                    flags=re.DOTALL,
                )
                sieve_path.write_text(content.rstrip() + "\n", encoding="utf-8")
        return warnings

    sieve_path.parent.mkdir(parents=True, exist_ok=True)
    if not sieve_path.is_file():
        sample = sieve_path.parent / "dovecot.sieve.sample"
        if sample.is_file():
            sieve_path.write_text(sample.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
        else:
            sieve_path.write_text('require ["fileinto"];\n', encoding="utf-8")

    content = sieve_path.read_text(encoding="utf-8", errors="replace")
    if MARKER_SIEVE_BEGIN in content and MARKER_SIEVE_END in content:
        content = re.sub(
            re.escape(MARKER_SIEVE_BEGIN) + r".*?" + re.escape(MARKER_SIEVE_END),
            block.strip(),
            content,
            count=1,
            flags=re.DOTALL,
        )
    else:
        content = content.rstrip() + "\n\n" + block + "\n"
    content = _merge_sieve_requires(content, _sieve_required_extensions(filters))
    sieve_path.write_text(content, encoding="utf-8")
    try:
        sieve_path.chmod(0o644)
    except OSError:
        pass

    compile_result = subprocess.run(
        ["sievec", str(sieve_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if compile_result.returncode != 0:
        detail = (compile_result.stderr or compile_result.stdout or "sievec failed").strip()
        raise ContentFilterError(f"Скрипт Sieve не компилируется: {detail[:500]}")
    restart = subprocess.run(
        ["systemctl", "restart", "dovecot"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if restart.returncode != 0:
        warnings.append("Не удалось перезапустить dovecot после обновления sieve.")
    return warnings


def _write_readable(path: Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    try:
        path.chmod(mode)
    except OSError:
        pass


def _validate_perl_custom_filters(path: Path) -> None:
    result = subprocess.run(
        ["perl", "-c", str(path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "perl -c failed").strip()
        raise ContentFilterError(f"Синтаксис {path}: {detail[:500]}")


def _check_amavis_mailpanel_journal(active: bool) -> None:
    if not active:
        return
    tail = _amavisd_journal_tail(40)
    if "MAILPANEL: loaded" in tail:
        return
    raise ContentFilterError(
        "custom_filters.conf не загрузился при старте amavisd "
        "(в journalctl нет «MAILPANEL: loaded»). "
        "Проверьте синтаксис /etc/mailpanel/amavis_custom_filters.conf"
    )


def _build_amavis_late_policy(filters: list[dict[str, Any]]) -> str:
    has_quarantine = any(
        _normalize_filter(rule)["action"] == "quarantine" for rule in _enabled_rules(filters)
    )
    if not has_quarantine:
        return ""
    return """# Generated by MailPanel. Loaded last in amavisd.conf.
# MYUSERS / RelayedInternal: force spam scanning (otherwise Hits: - and rules never run).
@bypass_spam_checks_maps = (0);
$bypass_spam_checks = 0;
foreach my $bank (keys %policy_bank) {
  next unless ref($policy_bank{$bank}) eq 'HASH';
  $policy_bank{$bank}{'bypass_spam_checks_maps'} = [0];
}
warn "MAILPANEL: late policy loaded\\n";
"""


def _perl_q_string(pattern: str) -> str:
    safe = pattern.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{safe}'"


def _rule_match_parts(normalized: dict[str, Any]) -> tuple[list[str], list[str]]:
    literals: list[str] = []
    patterns: list[str] = []
    literals_seen: set[str] = set()
    patterns_seen: set[str] = set()
    variants = _case_permutations(normalized["pattern"])
    if normalized["field"] in ("subject", "from"):
        for variant in variants:
            if variant not in literals_seen:
                literals_seen.add(variant)
                literals.append(variant)
            for perl_pattern in _perl_qr_variants(variant):
                if perl_pattern not in patterns_seen:
                    patterns_seen.add(perl_pattern)
                    patterns.append(perl_pattern)
    else:
        for variant in variants:
            perl_pattern = _perl_qr(variant)
            if perl_pattern not in patterns_seen:
                patterns_seen.add(perl_pattern)
                patterns.append(perl_pattern)
    return literals, patterns


def _perl_rule_entry(normalized: dict[str, Any]) -> str:
    literals, patterns = _rule_match_parts(normalized)
    lit_inner = ",\n      ".join(_perl_q_string(item) for item in literals)
    pat_inner = ",\n      ".join(patterns)
    return "\n".join(
        [
            "  {",
            f"    id => {_perl_q_string(normalized['id'])},",
            f"    field => {_perl_q_string(normalized['field'])},",
            f"    action => {_perl_q_string(normalized['action'])},",
            f"    forward_to => {_perl_q_string(normalized.get('forward_to') or '')},",
            f"    literals => [{lit_inner}],",
            f"    patterns => [{pat_inner}],",
            "  },",
        ]
    )


def _build_amavis_custom_package(filters: list[dict[str, Any]]) -> str:
    from app.services.content_filter_amavis import build_package

    rules_block = "\n".join(
        _perl_rule_entry(_normalize_filter(rule)) for rule in _enabled_rules(filters)
    )
    return build_package(rules_block, _CYRILLIC_FOLD_FROM, _CYRILLIC_FOLD_TO)


def _build_amavis_hook_block(
    filters: list[dict[str, Any]], custom_path: Path, late_path: Path
) -> str:
    lines = ["# Generated by MailPanel. Do not edit manually.", f"do '{custom_path.as_posix()}';"]
    if _build_amavis_late_policy(filters):
        lines.append(f"do '{late_path.as_posix()}';")
    return "\n".join(lines)


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
        normalized = _normalize_filter(item)
        enabled.append(
            {
                "id": normalized["id"],
                "field": normalized["field"],
                "pattern": normalized["pattern"],
                "action": normalized["action"],
                "forward_to": normalized["forward_to"],
                "enabled": True,
            }
        )
    return enabled


def _build_spamassassin_rule_lines(filters: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for rule in _enabled_rules(filters):
        normalized = _normalize_filter(rule)
        if normalized["action"] != "quarantine":
            continue
        name = _rule_name(normalized)
        regex = _sa_regex(normalized["pattern"])
        if normalized["field"] == "subject":
            lines.append(f"header {name} Subject =~ /{regex}/i")
        elif normalized["field"] == "from":
            lines.append(f"header {name} From =~ /{regex}/i")
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


def _count_patterns_in_custom_file(path: Path) -> tuple[int, int, int]:
    if not path.is_file():
        return 0, 0, 0
    text = path.read_text(encoding="utf-8", errors="replace")
    subject_count = len(re.findall(r"field\s*=>\s*'subject'", text))
    from_count = len(re.findall(r"field\s*=>\s*'from'", text))
    body_count = len(re.findall(r"field\s*=>\s*'body'", text))
    return subject_count, from_count, body_count


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
            if amavis_policy.av_scanner_available():
                warnings.append(
                    "Антивирус остаётся включённым: правила контента срабатывают после проверки на вирусы."
                )
            else:
                warnings.append(
                    "Антивирус Amavis отключён для работы правил (сканер недоступен, "
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
    include_path = None
    include_content = ""
    try:
        from app.services.amavis_policy import amavis_include_path

        include_path = amavis_include_path()
        if include_path.is_file():
            include_content = include_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        pass
    amavis_hook_loaded = (
        MARKER_CUSTOM_HOOK_BEGIN in amavis_content
        and do_line in amavis_content
        and "sub Amavis::Custom::before_send" in custom_text
        and "mailpanel_action" in custom_text
    )
    include_do_loaded = do_line in include_content
    sieve_path = dovecot_global_sieve_path()
    sieve_content = sieve_path.read_text(encoding="utf-8", errors="replace") if sieve_path.is_file() else ""
    sieve_loaded = MARKER_SIEVE_BEGIN in sieve_content and MARKER_SIEVE_END in sieve_content
    scan_internal_mail = False
    try:
        from app.services import amavis_policy

        scan_internal_mail = bool(amavis_policy.read_mail_policy().get("scan_internal_mail"))
    except Exception:
        scan_internal_mail = False
    subject_patterns, from_patterns, body_patterns = _count_patterns_in_custom_file(custom_path)
    av_available = False
    try:
        from app.services import amavis_policy

        av_available = bool(amavis_policy.av_scanner_available())
    except Exception:
        av_available = False
    return {
        "local_cf": str(local_cf),
        "local_cf_exists": local_cf.is_file(),
        "rules_in_local_cf": rules_in_local_cf,
        "amavis_custom_file": str(custom_path),
        "amavis_custom_exists": custom_path.is_file(),
        "amavis_hook_loaded": amavis_hook_loaded,
        "amavis_include_do_loaded": include_do_loaded,
        "sieve_file": str(sieve_path),
        "sieve_loaded": sieve_loaded,
        "amavisd_active": _amavisd_active(),
        "hook_subject_patterns": subject_patterns,
        "hook_from_patterns": from_patterns,
        "hook_body_patterns": body_patterns,
        "av_bypass_in_hook": bool(
            subject_patterns or from_patterns or body_patterns
        )
        and "@av_scanners = ();" in include_content,
        "av_scanner_available": av_available,
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
    if "MailPanel::Filters" not in custom_content:
        raise ContentFilterError("Сборка фильтров MailPanel не удалась.")
    if "sub Amavis::Custom::before_send" not in custom_content:
        raise ContentFilterError("Сборка before_send hook MailPanel не удалась.")
    if "mailpanel_action" not in custom_content:
        raise ContentFilterError("Сборка action hook MailPanel не удалась.")
    _write_readable(custom_path, custom_content)
    _validate_perl_custom_filters(custom_path)

    late_path = amavis_late_policy_path()
    late_content = _build_amavis_late_policy(filters)
    if late_content:
        _write_readable(late_path, late_content)
    elif late_path.is_file():
        late_path.unlink()

    hook_block = _build_amavis_hook_block(filters, custom_path, late_path)

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
    warnings.extend(_ensure_dovecot_sieve_block(filters))
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
    _check_amavis_mailpanel_journal(bool(_enabled_rules(filters)))
    return warnings


def list_content_filters() -> dict[str, Any]:
    raw_filters = _read_filters_file()
    filters = [_normalize_filter(item) for item in raw_filters]
    diagnostics = _diagnostics(raw_filters)
    notes = [
        "Правила работают через хук Amavis (включая письма между ящиками на сервере).",
        "Для внутренней почты дополнительно применяется глобальный Sieve.",
        "Действия: «Карантин» — в карантин спама; «Удалить» — отбросить без доставки; "
        "«Переслать» — только на указанный адрес (вместо исходных получателей); "
        "«Добавить получателя» — и исходным, и на указанный адрес "
        "(оба варианта через Amavis; нужна проверка внутренней почты).",
        "Поиск без учёта регистра, по вхождению указанного текста.",
        "Правила с действием «Карантин» дублируются в SpamAssassin для внешней почты.",
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


def create_content_filter(
    field: str,
    pattern: str,
    enabled: bool = True,
    action: str = "quarantine",
    forward_to: str | None = None,
) -> dict[str, Any]:
    filters = _read_filters_file()
    rule = _normalize_filter(
        {
            "id": secrets.token_hex(4),
            "field": field,
            "pattern": pattern,
            "action": action,
            "forward_to": forward_to or "",
            "enabled": enabled,
        }
    )
    filters.append(_storage_filter(rule))
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
    action: str | None = None,
    forward_to: str | None = None,
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
    if action is not None:
        current["action"] = _validate_action(action)
    if forward_to is not None:
        current["forward_to"] = forward_to
    next_action = _validate_action(str(current.get("action", "quarantine")))
    if next_action not in ACTIONS_NEED_ADDRESS:
        current.pop("forward_to", None)
    if enabled is not None:
        current["enabled"] = bool(enabled)

    rule = _normalize_filter(current)
    filters[index] = _storage_filter(rule)
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
