from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from app.auth import PanelUser, Role, client_ip, get_current_user, require_permission, write_audit
from app.config import get_config, role_has_permission
from app.services import amavis_policy, content_filter_ops, group_ops, iredapd, log_reader, mail_ops
from app.services.amavis_policy import AmavisPolicyError
from app.services.content_filter_ops import ContentFilterError
from app.services.iredapd import IredapdError
from app.services import iredapd, mail_journal_search, postfix_diagnostics, postfix_queue, quarantine_ops
from app.services.greylisting_ops import get_greylisting_overview, greylisting_stats
from app.services.postfix_queue import PostfixQueueError
from app.services.quarantine_ops import QuarantineError
from app.validators import normalize_email, validate_mailbox_password

router = APIRouter(prefix="/api", tags=["api"])


class MailboxCreate(BaseModel):
    username: str
    password: str
    name: str = ""
    quota: int = Field(default=1024, ge=0)

    @field_validator("username")
    @classmethod
    def check_username(cls, value: str) -> str:
        return normalize_email(value, "Ящик")

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str) -> str:
        return validate_mailbox_password(value)


class MailboxPassword(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str) -> str:
        return validate_mailbox_password(value)


class MailboxQuota(BaseModel):
    quota: int = Field(ge=0)


class MailboxActive(BaseModel):
    active: bool


class MailboxNameUpdate(BaseModel):
    name: str = ""


class AliasCreate(BaseModel):
    address: str
    goto: str

    @field_validator("address")
    @classmethod
    def check_address(cls, value: str) -> str:
        return normalize_email(value, "Адрес алиаса")

    @field_validator("goto")
    @classmethod
    def check_goto(cls, value: str) -> str:
        return normalize_email(value, "Пересылка на")


class GroupCreate(BaseModel):
    address: str
    members: list[str] = Field(min_length=1)

    @field_validator("address")
    @classmethod
    def check_address(cls, value: str) -> str:
        return normalize_email(value, "Адрес группы")

    @field_validator("members")
    @classmethod
    def check_members(cls, values: list[str]) -> list[str]:
        return [normalize_email(item, "Участник") for item in values]


class GroupMemberRequest(BaseModel):
    member: str

    @field_validator("member")
    @classmethod
    def check_member(cls, value: str) -> str:
        return normalize_email(value, "Участник")


class ForwardingUpdate(BaseModel):
    goto: str


class ForwardingRemove(BaseModel):
    address: str
    goto: str


class WblistRequest(BaseModel):
    entries: list[str] = Field(min_length=1)
    comment: str = ""


class WblistCommentRequest(BaseModel):
    entry: str = Field(min_length=1)
    comment: str = ""


class GreylistRequest(BaseModel):
    to_addr: str
    from_addr: str | None = None


class GreylistDomainRequest(BaseModel):
    domain: str


class SpamUpdate(BaseModel):
    required_score: float = Field(ge=0, le=20)
    extra_rules: str = ""


class BannedExtensionsUpdate(BaseModel):
    extensions: list[str] = Field(min_length=1)


class MailPolicyUpdate(BaseModel):
    scan_internal_mail: bool


class ContentFilterCreate(BaseModel):
    field: Literal["subject", "body"]
    pattern: str = Field(min_length=1, max_length=200)
    enabled: bool = True


class ContentFilterUpdate(BaseModel):
    field: Literal["subject", "body"] | None = None
    pattern: str | None = Field(default=None, min_length=1, max_length=200)
    enabled: bool | None = None


class PanelUserCreate(BaseModel):
    username: str = Field(min_length=3)
    password: str = Field(min_length=6)
    role: Role
    display_name: str = ""
    mailbox: str | None = None


class PanelUserPassword(BaseModel):
    password: str = Field(min_length=6)


class Fail2banUnban(BaseModel):
    jail: str
    ip: str


class QueueFlushRequest(BaseModel):
    confirm: Literal["FLUSH_ALL"]


def _audit(user: PanelUser, request: Request, action: str, resource: str, details: str = "") -> None:
    write_audit(user, action, resource, details, client_ip(request))


@router.get("/dashboard", dependencies=[Depends(require_permission("mail.read"))])
def dashboard():
    services = [mail_ops.service_status(n) for n in get_config().services]
    return {"stats": mail_ops.dashboard_stats(), "services": services}


@router.get("/mailboxes", dependencies=[Depends(require_permission("mail.read"))])
def get_mailboxes():
    return mail_ops.list_mailboxes(get_config().panel.mail_domain)


@router.post("/mailboxes", dependencies=[Depends(require_permission("mail.write"))])
def post_mailbox(payload: MailboxCreate, request: Request, user: PanelUser = Depends(require_permission("mail.write"))):
    domain = get_config().panel.mail_domain.lower()
    if not payload.username.endswith(f"@{domain}"):
        raise HTTPException(400, f"Ящик должен быть в домене @{domain}")
    try:
        mail_ops.create_mailbox(payload.username, payload.password, payload.name, payload.quota)
        _audit(user, request, "create", "mailbox", payload.username)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(400, f"Не удалось создать ящик: {exc}") from exc
    return {"ok": True}


@router.delete("/mailboxes/{username:path}", dependencies=[Depends(require_permission("mail.write"))])
def del_mailbox(username: str, request: Request, user: PanelUser = Depends(require_permission("mail.write"))):
    mail_ops.delete_mailbox(username)
    _audit(user, request, "delete", "mailbox", username)
    return {"ok": True}


@router.put("/mailboxes/{username:path}/password", dependencies=[Depends(require_permission("mail.write"))])
def mailbox_password(username: str, payload: MailboxPassword, request: Request, user: PanelUser = Depends(require_permission("mail.write"))):
    try:
        mail_ops.update_mailbox_password(username, payload.password)
        _audit(user, request, "password_change", "mailbox", username)
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.put("/mailboxes/{username:path}/quota", dependencies=[Depends(require_permission("mail.write"))])
def mailbox_quota(username: str, payload: MailboxQuota, request: Request, user: PanelUser = Depends(require_permission("mail.write"))):
    try:
        mail_ops.update_mailbox_quota(username, payload.quota)
        _audit(user, request, "quota_change", "mailbox", f"{username}={payload.quota}MB")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.put("/mailboxes/{username:path}/active", dependencies=[Depends(require_permission("mail.write"))])
def mailbox_active(username: str, payload: MailboxActive, request: Request, user: PanelUser = Depends(require_permission("mail.write"))):
    try:
        mail_ops.update_mailbox_active(username, payload.active)
        action = "enable" if payload.active else "disable"
        _audit(user, request, action, "mailbox", username)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.put("/mailboxes/{username:path}/name", dependencies=[Depends(require_permission("mail.write"))])
def mailbox_name(username: str, payload: MailboxNameUpdate, request: Request, user: PanelUser = Depends(require_permission("mail.write"))):
    try:
        result = mail_ops.update_mailbox_name(username, payload.name)
        _audit(user, request, "comment_change", "mailbox", f"{result['username']}: {result['name'] or '—'}")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True, **result}


@router.get("/mailboxes/{username:path}/forwarding", dependencies=[Depends(require_permission("mail.read"))])
def get_mailbox_forwarding(username: str):
    address = username.lower()
    return {"address": address, "goto": mail_ops.get_forwarding(address)}


@router.put("/mailboxes/{username:path}/forwarding", dependencies=[Depends(require_permission("mail.write"))])
def put_mailbox_forwarding(
    username: str,
    payload: ForwardingUpdate,
    request: Request,
    user: PanelUser = Depends(require_permission("mail.write")),
):
    address = username.lower()
    goto = normalize_email(payload.goto, "Пересылка на")
    try:
        if not mail_ops.mailbox_exists(address):
            raise ValueError(f"Ящик не найден: {address}")
        mail_ops.set_forwarding(address, goto)
        _audit(user, request, "forwarding_set", "mailbox", f"{address} -> {goto}")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.delete("/mailboxes/{username:path}/forwarding", dependencies=[Depends(require_permission("mail.write"))])
def delete_mailbox_forwarding(
    username: str,
    request: Request,
    goto: str | None = None,
    user: PanelUser = Depends(require_permission("mail.write")),
):
    address = username.lower()
    if goto:
        target = goto.lower()
        mail_ops.remove_forwarding(address, target)
        _audit(user, request, "forwarding_remove", "mailbox", f"{address} -> {target}")
    else:
        mail_ops.clear_forwarding(address)
        _audit(user, request, "forwarding_clear", "mailbox", address)
    return {"ok": True}


@router.get("/aliases", dependencies=[Depends(require_permission("mail.read"))])
def get_aliases():
    return mail_ops.list_aliases(get_config().panel.mail_domain)


@router.get("/forwardings", dependencies=[Depends(require_permission("mail.read"))])
def get_forwardings():
    return mail_ops.list_mailbox_forwardings(get_config().panel.mail_domain)


@router.post("/forwardings/remove", dependencies=[Depends(require_permission("mail.write"))])
def remove_forwarding_entry(
    payload: ForwardingRemove,
    request: Request,
    user: PanelUser = Depends(require_permission("mail.write")),
):
    address = payload.address.lower()
    try:
        goto = normalize_email(payload.goto, "Пересылка на")
        if not mail_ops.mailbox_exists(address):
            raise ValueError(f"Ящик не найден: {address}")
        mail_ops.remove_forwarding(address, goto)
        _audit(user, request, "forwarding_remove", "mailbox", f"{address} -> {goto}")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    items = mail_ops.list_mailbox_forwardings(get_config().panel.mail_domain)
    return {"ok": True, "items": items}


@router.post("/aliases", dependencies=[Depends(require_permission("mail.write"))])
def post_alias(payload: AliasCreate, request: Request, user: PanelUser = Depends(require_permission("mail.write"))):
    domain = get_config().panel.mail_domain.lower()
    if not payload.address.endswith(f"@{domain}"):
        raise HTTPException(400, f"Алиас должен быть в домене @{domain}")
    try:
        if group_ops.is_group_address(payload.address):
            raise ValueError("Этот адрес уже используется как группа")
        mail_ops.create_alias(payload.address, payload.goto)
        _audit(user, request, "create", "alias", payload.address)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(400, f"Не удалось создать алиас: {exc}") from exc
    return {"ok": True}


@router.delete("/aliases/{address:path}", dependencies=[Depends(require_permission("mail.write"))])
def del_alias(address: str, request: Request, user: PanelUser = Depends(require_permission("mail.write"))):
    if group_ops.is_group_address(address):
        raise HTTPException(400, "Это групповой адрес — удаляйте в разделе «Группы»")
    mail_ops.delete_alias(address)
    _audit(user, request, "delete", "alias", address)
    return {"ok": True}


@router.get("/groups", dependencies=[Depends(require_permission("mail.read"))])
def get_groups():
    return group_ops.list_groups(get_config().panel.mail_domain)


@router.post("/groups", dependencies=[Depends(require_permission("mail.write"))])
def post_group(payload: GroupCreate, request: Request, user: PanelUser = Depends(require_permission("mail.write"))):
    domain = get_config().panel.mail_domain.lower()
    if not payload.address.endswith(f"@{domain}"):
        raise HTTPException(400, f"Группа должна быть в домене @{domain}")
    for member in payload.members:
        if not member.endswith(f"@{domain}"):
            raise HTTPException(400, f"Участник должен быть в домене @{domain}: {member}")
    try:
        group_ops.create_group(payload.address, payload.members)
        _audit(user, request, "create", "group", f"{payload.address} -> {', '.join(payload.members)}")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(400, f"Не удалось создать группу: {exc}") from exc
    return {"ok": True}


@router.delete("/groups/{address:path}", dependencies=[Depends(require_permission("mail.write"))])
def del_group(address: str, request: Request, user: PanelUser = Depends(require_permission("mail.write"))):
    try:
        group_ops.delete_group(address)
        _audit(user, request, "delete", "group", address)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.post("/groups/{address:path}/members", dependencies=[Depends(require_permission("mail.write"))])
def add_group_member(
    address: str,
    payload: GroupMemberRequest,
    request: Request,
    user: PanelUser = Depends(require_permission("mail.write")),
):
    domain = get_config().panel.mail_domain.lower()
    if not payload.member.endswith(f"@{domain}"):
        raise HTTPException(400, f"Участник должен быть в домене @{domain}")
    try:
        members = group_ops.add_group_member(address, payload.member)
        _audit(user, request, "group_add_member", "group", f"{address} + {payload.member}")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True, "members": members}


@router.post("/groups/{address:path}/members/remove", dependencies=[Depends(require_permission("mail.write"))])
def remove_group_member(
    address: str,
    payload: GroupMemberRequest,
    request: Request,
    user: PanelUser = Depends(require_permission("mail.write")),
):
    try:
        members = group_ops.remove_group_member(address, payload.member)
        _audit(user, request, "group_remove_member", "group", f"{address} - {payload.member}")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True, "members": members}


@router.get("/wblist/{list_type}", dependencies=[Depends(require_permission("antispam.read"))])
def get_wblist(list_type: str):
    if list_type not in ("whitelist", "blacklist"):
        raise HTTPException(400, "Invalid list type")
    try:
        entries = iredapd.list_wblist(list_type, None)
    except IredapdError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"entries": entries}


@router.post("/wblist/{list_type}", dependencies=[Depends(require_permission("antispam.write"))])
def post_wblist(
    list_type: str,
    payload: WblistRequest,
    request: Request,
    user: PanelUser = Depends(require_permission("antispam.write")),
):
    if list_type not in ("whitelist", "blacklist"):
        raise HTTPException(400, "Invalid list type")
    if not payload.entries or not any(item.strip() for item in payload.entries):
        raise HTTPException(400, "Укажите запись для добавления в список")
    try:
        validated = [iredapd.validate_wblist_entry(e) for e in payload.entries]
        iredapd.add_wblist(list_type, validated, None, comment=payload.comment)
        detail = ", ".join(validated)
        if payload.comment.strip():
            detail = f"{detail} ({payload.comment.strip()})"
        _audit(user, request, "wblist_add", list_type, detail)
    except IredapdError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        message = str(exc)
        if "1062" in message or "Duplicate entry" in message:
            raise HTTPException(
                400,
                "Этот адрес уже есть в другом списке (белом или чёрном). Удалите его оттуда и попробуйте снова.",
            ) from exc
        raise HTTPException(400, f"Не удалось добавить в список: {message}") from exc
    return {"ok": True}


@router.put("/wblist/{list_type}/comment", dependencies=[Depends(require_permission("antispam.write"))])
def put_wblist_comment(
    list_type: str,
    payload: WblistCommentRequest,
    request: Request,
    user: PanelUser = Depends(require_permission("antispam.write")),
):
    if list_type not in ("whitelist", "blacklist"):
        raise HTTPException(400, "Invalid list type")
    try:
        validated = iredapd.validate_wblist_entry(payload.entry)
        result = iredapd.update_wblist_comment(list_type, validated, payload.comment)
        detail = result["address"]
        if result["comment"]:
            detail = f"{detail} ({result['comment']})"
        _audit(user, request, "wblist_comment", list_type, detail)
    except IredapdError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True, **result}


@router.delete("/wblist/{list_type}", dependencies=[Depends(require_permission("antispam.write"))])
def delete_wblist(
    list_type: str,
    payload: WblistRequest,
    request: Request,
    user: PanelUser = Depends(require_permission("antispam.write")),
):
    if list_type not in ("whitelist", "blacklist"):
        raise HTTPException(400, "Invalid list type")
    try:
        validated = [iredapd.validate_wblist_entry(e) for e in payload.entries]
        iredapd.delete_wblist(list_type, validated, None)
        _audit(user, request, "wblist_delete", list_type, ", ".join(validated))
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.get("/greylisting", dependencies=[Depends(require_permission("greylisting.read"))])
def get_greylisting():
    try:
        return get_greylisting_overview()
    except iredapd.IredapdError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(500, f"Greylisting: {exc}") from exc


@router.get("/greylisting/stats", dependencies=[Depends(require_permission("greylisting.read"))])
def get_greylisting_stats(hours: int = 24):
    try:
        return greylisting_stats(hours=hours)
    except RuntimeError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/greylisting/disable", dependencies=[Depends(require_permission("greylisting.write"))])
def grey_disable(
    payload: GreylistRequest,
    request: Request,
    user: PanelUser = Depends(require_permission("greylisting.write")),
):
    try:
        iredapd.greylisting_disable(payload.to_addr, payload.from_addr)
        _audit(user, request, "disable", "greylisting", f"{payload.from_addr or '*'} -> {payload.to_addr}")
    except iredapd.IredapdError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.post("/greylisting/enable", dependencies=[Depends(require_permission("greylisting.write"))])
def grey_enable(
    payload: GreylistRequest,
    request: Request,
    user: PanelUser = Depends(require_permission("greylisting.write")),
):
    try:
        iredapd.greylisting_enable(payload.to_addr, payload.from_addr)
        _audit(user, request, "enable", "greylisting", f"{payload.from_addr or '*'} -> {payload.to_addr}")
    except iredapd.IredapdError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.post("/greylisting/delete-rule", dependencies=[Depends(require_permission("greylisting.write"))])
def grey_delete_rule(
    payload: GreylistRequest,
    request: Request,
    user: PanelUser = Depends(require_permission("greylisting.write")),
):
    try:
        iredapd.greylisting_delete(payload.to_addr, payload.from_addr)
        _audit(user, request, "delete", "greylisting", f"{payload.from_addr or '*'} -> {payload.to_addr}")
    except iredapd.IredapdError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.post("/greylisting/whitelist-domain", dependencies=[Depends(require_permission("greylisting.write"))])
def grey_whitelist_domain(
    payload: GreylistDomainRequest,
    request: Request,
    user: PanelUser = Depends(require_permission("greylisting.write")),
):
    domain = payload.domain if payload.domain.startswith("@") else f"@{payload.domain}"
    try:
        iredapd.greylisting_whitelist_domain(domain)
        _audit(user, request, "whitelist-domain", "greylisting", domain)
    except iredapd.IredapdError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.post("/greylisting/remove-whitelist-domain", dependencies=[Depends(require_permission("greylisting.write"))])
def grey_remove_whitelist_domain(
    payload: GreylistDomainRequest,
    request: Request,
    user: PanelUser = Depends(require_permission("greylisting.write")),
):
    domain = payload.domain if payload.domain.startswith("@") else f"@{payload.domain}"
    try:
        iredapd.greylisting_remove_whitelist_domain(domain)
        _audit(user, request, "remove-whitelist-domain", "greylisting", domain)
    except iredapd.IredapdError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.post("/greylisting/sync-spf", dependencies=[Depends(require_permission("greylisting.write"))])
def grey_sync_spf(
    request: Request,
    user: PanelUser = Depends(require_permission("greylisting.write")),
):
    try:
        message = iredapd.sync_spf_greylist_whitelists()
        _audit(user, request, "sync-spf", "greylisting", "spf_to_greylist_whitelists.py")
    except iredapd.IredapdError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True, "message": message}


@router.get("/spam", dependencies=[Depends(require_permission("antispam.read"))])
def get_spam():
    return mail_ops.read_spam_config()


@router.put("/spam", dependencies=[Depends(require_permission("antispam.write"))])
def put_spam(payload: SpamUpdate, request: Request, user: PanelUser = Depends(require_permission("antispam.write"))):
    try:
        mail_ops.write_spam_config(payload.required_score, payload.extra_rules)
        _audit(user, request, "spam_config", "spamassassin", str(payload.required_score))
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.get("/antispam/banned-extensions", dependencies=[Depends(require_permission("antispam.read"))])
def get_banned_extensions():
    try:
        return amavis_policy.read_banned_extensions()
    except AmavisPolicyError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/antispam/banned-extensions/reapply", dependencies=[Depends(require_permission("antispam.write"))])
def reapply_banned_extensions_route(
    request: Request,
    user: PanelUser = Depends(require_permission("antispam.write")),
):
    try:
        result = amavis_policy.reapply_banned_extensions()
        _audit(user, request, "reapply", "banned_extensions", ", ".join(result["extensions"]))
    except AmavisPolicyError as exc:
        raise HTTPException(400, str(exc)) from exc
    return result


@router.put("/antispam/banned-extensions", dependencies=[Depends(require_permission("antispam.write"))])
def put_banned_extensions(
    payload: BannedExtensionsUpdate,
    request: Request,
    user: PanelUser = Depends(require_permission("antispam.write")),
):
    try:
        result = amavis_policy.write_banned_extensions(payload.extensions)
        _audit(user, request, "banned_extensions", "amavisd", ", ".join(result["extensions"]))
    except (AmavisPolicyError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc
    return result


@router.get("/antispam/mail-policy", dependencies=[Depends(require_permission("antispam.read"))])
def get_mail_policy():
    try:
        return amavis_policy.read_mail_policy()
    except AmavisPolicyError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.put("/antispam/mail-policy", dependencies=[Depends(require_permission("antispam.write"))])
def put_mail_policy(
    payload: MailPolicyUpdate,
    request: Request,
    user: PanelUser = Depends(require_permission("antispam.write")),
):
    try:
        result = amavis_policy.write_mail_policy(payload.scan_internal_mail)
        _audit(
            user,
            request,
            "mail_policy",
            "amavisd",
            f"scan_internal_mail={payload.scan_internal_mail}",
        )
    except AmavisPolicyError as exc:
        raise HTTPException(400, str(exc)) from exc
    return result


@router.get("/rules", dependencies=[Depends(require_permission("antispam.read"))])
def get_content_filters():
    return content_filter_ops.list_content_filters()


@router.post("/rules/reapply", dependencies=[Depends(require_permission("antispam.write"))])
def reapply_content_filters(user: PanelUser = Depends(require_permission("antispam.write"))):
    try:
        return content_filter_ops.reapply_content_filters()
    except ContentFilterError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(400, f"Не удалось применить правила: {exc}") from exc


@router.post("/rules", dependencies=[Depends(require_permission("antispam.write"))])
def post_content_filter(
    payload: ContentFilterCreate,
    request: Request,
    user: PanelUser = Depends(require_permission("antispam.write")),
):
    try:
        rule = content_filter_ops.create_content_filter(payload.field, payload.pattern, payload.enabled)
        _audit(
            user,
            request,
            "rule_create",
            "content_filter",
            f"{rule['field']}:{rule['pattern']}",
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ContentFilterError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(400, f"Не удалось создать правило: {exc}") from exc
    response: dict[str, Any] = {"ok": True, "item": rule}
    if rule.get("warnings"):
        response["warnings"] = rule["warnings"]
    return response


@router.put("/rules/{rule_id}", dependencies=[Depends(require_permission("antispam.write"))])
def put_content_filter(
    rule_id: str,
    payload: ContentFilterUpdate,
    request: Request,
    user: PanelUser = Depends(require_permission("antispam.write")),
):
    try:
        rule = content_filter_ops.update_content_filter(
            rule_id,
            field=payload.field,
            pattern=payload.pattern,
            enabled=payload.enabled,
        )
        _audit(user, request, "rule_update", "content_filter", rule_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ContentFilterError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True, "item": rule}


@router.delete("/rules/{rule_id}", dependencies=[Depends(require_permission("antispam.write"))])
def delete_content_filter(
    rule_id: str,
    request: Request,
    user: PanelUser = Depends(require_permission("antispam.write")),
):
    try:
        content_filter_ops.delete_content_filter(rule_id)
        _audit(user, request, "rule_delete", "content_filter", rule_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ContentFilterError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.get("/quarantine", dependencies=[Depends(require_permission("quarantine.read"))])
def get_quarantine(
    limit: int = 50,
    offset: int = 0,
    content: str | None = None,
):
    try:
        return quarantine_ops.list_quarantine(limit, offset, None, content)
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/quarantine/{mail_id}", dependencies=[Depends(require_permission("quarantine.read"))])
def get_quarantine_one(
    mail_id: str,
    partition_tag: str = "",
):
    try:
        return quarantine_ops.get_quarantine_item(mail_id, partition_tag)
    except QuarantineError as exc:
        raise HTTPException(404, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/quarantine/{mail_id}/body", dependencies=[Depends(require_permission("quarantine.read"))])
def get_quarantine_body(
    mail_id: str,
    partition_tag: str = "",
):
    try:
        return quarantine_ops.get_quarantine_body(mail_id, partition_tag)
    except QuarantineError as exc:
        raise HTTPException(404, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/quarantine/{mail_id}/release", dependencies=[Depends(require_permission("quarantine.write"))])
def release_quarantine_msg(
    mail_id: str,
    request: Request,
    partition_tag: str = "",
    user: PanelUser = Depends(require_permission("quarantine.write")),
):
    try:
        item = quarantine_ops.get_quarantine_item(mail_id, partition_tag)
        result = quarantine_ops.release_quarantine(mail_id, item["partition_tag"])
        _audit(user, request, "release", "quarantine", mail_id)
        return result
    except QuarantineError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@router.delete("/quarantine/{mail_id}", dependencies=[Depends(require_permission("quarantine.write"))])
def delete_quarantine_msg(
    mail_id: str,
    request: Request,
    partition_tag: str = "",
    user: PanelUser = Depends(require_permission("quarantine.write")),
):
    try:
        item = quarantine_ops.get_quarantine_item(mail_id, partition_tag)
        quarantine_ops.delete_quarantine(mail_id, item["partition_tag"])
        _audit(user, request, "delete", "quarantine", mail_id)
        return {"ok": True}
    except QuarantineError as exc:
        raise HTTPException(404, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/queue/diagnostics", dependencies=[Depends(require_permission("queue.read"))])
def get_queue_diagnostics():
    return postfix_diagnostics.mail_delivery_diagnostics()


@router.get("/queue", dependencies=[Depends(require_permission("queue.read"))])
def get_queue(
    status: str | None = None,
    sender: str | None = None,
    recipient: str | None = None,
    limit: int = 200,
    offset: int = 0,
):
    try:
        return postfix_queue.list_queue(status, sender, recipient, limit, offset)
    except PostfixQueueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/queue/flush", dependencies=[Depends(require_permission("queue.write"))])
def flush_all_queue(
    payload: QueueFlushRequest,
    request: Request,
    user: PanelUser = Depends(require_permission("queue.write")),
):
    try:
        postfix_queue.flush_all()
        _audit(user, request, "flush_all", "postfix_queue", "")
        return {"ok": True}
    except PostfixQueueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/queue/{queue_id}", dependencies=[Depends(require_permission("queue.read"))])
def get_queue_message(queue_id: str):
    try:
        return postfix_queue.get_queue_message(queue_id)
    except PostfixQueueError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.delete("/queue/{queue_id}", dependencies=[Depends(require_permission("queue.write"))])
def delete_queue_message(
    queue_id: str,
    request: Request,
    user: PanelUser = Depends(require_permission("queue.write")),
):
    try:
        qid = postfix_queue.delete_message(queue_id)
        _audit(user, request, "delete", "postfix_queue", qid)
        return {"ok": True, "queue_id": qid}
    except PostfixQueueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/queue/{queue_id}/flush", dependencies=[Depends(require_permission("queue.write"))])
def flush_queue_message(
    queue_id: str,
    request: Request,
    user: PanelUser = Depends(require_permission("queue.write")),
):
    try:
        qid = postfix_queue.flush_message(queue_id)
        _audit(user, request, "flush", "postfix_queue", qid)
        return {"ok": True, "queue_id": qid}
    except PostfixQueueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/queue/{queue_id}/hold", dependencies=[Depends(require_permission("queue.write"))])
def hold_queue_message(
    queue_id: str,
    request: Request,
    user: PanelUser = Depends(require_permission("queue.write")),
):
    try:
        qid = postfix_queue.hold_message(queue_id)
        _audit(user, request, "hold", "postfix_queue", qid)
        return {"ok": True, "queue_id": qid}
    except PostfixQueueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/queue/{queue_id}/release", dependencies=[Depends(require_permission("queue.write"))])
def release_queue_message(
    queue_id: str,
    request: Request,
    user: PanelUser = Depends(require_permission("queue.write")),
):
    try:
        qid = postfix_queue.release_message(queue_id)
        _audit(user, request, "release", "postfix_queue", qid)
        return {"ok": True, "queue_id": qid}
    except PostfixQueueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/logs/search", dependencies=[Depends(require_permission("logs.read"))])
def logs_search(
    service: str | None = None,
    q: str | None = None,
    queue_id: str | None = None,
    mail_from: str | None = None,
    mail_to: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = 200,
    offset: int = 0,
):
    try:
        return mail_journal_search.search_mail_logs(
            query=q,
            queue_id=queue_id,
            mail_from=mail_from,
            mail_to=mail_to,
            date_from=date_from,
            date_to=date_to,
            service=service,
            limit=limit,
            offset=offset,
        )
    except RuntimeError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/logs/trace/{queue_id}", dependencies=[Depends(require_permission("logs.read"))])
def logs_trace(queue_id: str):
    try:
        return mail_journal_search.trace_queue_id(queue_id)
    except RuntimeError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/logs/live/{log_type}", dependencies=[Depends(require_permission("logs.read"))])
def logs_live(log_type: str, lines: int = 200):
    cfg = get_config()
    mapping = {
        "mail": cfg.paths.maillog,
        "iredapd": cfg.paths.iredapd_log,
        "dovecot": cfg.paths.dovecot_log,
        "system": cfg.paths.messages_log,
    }
    if log_type not in mapping:
        raise HTTPException(404, "Unknown log type")
    return log_reader.tail_live_log(log_type, mapping[log_type], lines)


@router.get("/audit", dependencies=[Depends(require_permission("logs.read"))])
def audit_log(limit: int = 100):
    return mail_ops.list_audit_log(limit)


@router.get("/services", dependencies=[Depends(require_permission("services.read"))])
def get_services():
    return [mail_ops.service_status(n) for n in get_config().services]


@router.post("/services/{name}/restart", dependencies=[Depends(require_permission("services.restart"))])
def restart_service(name: str, request: Request, user: PanelUser = Depends(require_permission("services.restart"))):
    try:
        result = mail_ops.restart_service(name)
        _audit(user, request, "restart", "service", name)
        return result
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/fail2ban", dependencies=[Depends(require_permission("services.read"))])
def get_fail2ban():
    return mail_ops.fail2ban_status()


@router.post("/fail2ban/unban", dependencies=[Depends(require_permission("services.restart"))])
def post_unban(payload: Fail2banUnban, user: PanelUser = Depends(require_permission("services.restart"))):
    try:
        mail_ops.fail2ban_unban(payload.jail, payload.ip)
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.get("/panel-users", dependencies=[Depends(require_permission("panel.users.read"))])
def get_panel_users():
    return mail_ops.list_panel_users()


@router.post("/panel-users", dependencies=[Depends(require_permission("panel.users.write"))])
def post_panel_user(payload: PanelUserCreate, request: Request, user: PanelUser = Depends(require_permission("panel.users.write"))):
    if payload.role == Role.USER:
        raise HTTPException(400, "Роль user отключена")
    try:
        mail_ops.create_panel_user(payload.username, payload.password, payload.role, payload.display_name, payload.mailbox)
        _audit(user, request, "create", "panel_user", payload.username)
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.put("/panel-users/{user_id}/password", dependencies=[Depends(require_permission("panel.users.write"))])
def panel_user_password(user_id: int, payload: PanelUserPassword, request: Request, user: PanelUser = Depends(require_permission("panel.users.write"))):
    mail_ops.update_panel_user_password(user_id, payload.password)
    _audit(user, request, "password_change", "panel_user", str(user_id))
    return {"ok": True}


@router.delete("/panel-users/{user_id}", dependencies=[Depends(require_permission("panel.users.write"))])
def del_panel_user(user_id: int, request: Request, user: PanelUser = Depends(require_permission("panel.users.write"))):
    if user_id == user.id:
        raise HTTPException(400, "Cannot delete yourself")
    mail_ops.delete_panel_user(user_id)
    _audit(user, request, "delete", "panel_user", str(user_id))
    return {"ok": True}
