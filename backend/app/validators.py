from __future__ import annotations

import re

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(value: str, field_name: str) -> str:
    value = value.strip().lower()
    if not value:
        raise ValueError(f"{field_name}: укажите адрес")
    if not EMAIL_RE.match(value):
        raise ValueError(f"{field_name}: некорректный формат (пример user@domain.ru)")
    return value


def validate_mailbox_password(value: str) -> str:
    if len(value) < 8:
        raise ValueError("Пароль: минимум 8 символов")
    if not re.search(r"[a-z]", value):
        raise ValueError("Пароль: нужна хотя бы одна строчная латинская буква (a-z)")
    if not re.search(r"[A-Z]", value):
        raise ValueError("Пароль: нужна хотя бы одна заглавная латинская буква (A-Z)")
    if not re.search(r"\d", value):
        raise ValueError("Пароль: нужна хотя бы одна цифра")
    return value
