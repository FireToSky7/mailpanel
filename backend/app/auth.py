from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import Role, get_config, role_has_permission
from app.database import execute, fetch_one, panel_conn

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)


@dataclass
class PanelUser:
    id: int
    username: str
    role: Role
    mailbox: str | None
    display_name: str


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_user_by_username(username: str) -> PanelUser | None:
    with panel_conn() as conn:
        row = fetch_one(
            conn,
            "SELECT id, username, role, mailbox, display_name, password_hash, active "
            "FROM panel_users WHERE username = %s",
            (username,),
        )
    if not row or not row["active"]:
        return None
    return PanelUser(
        id=row["id"],
        username=row["username"],
        role=Role(row["role"]),
        mailbox=row["mailbox"],
        display_name=row["display_name"] or row["username"],
    )


def authenticate(username: str, password: str) -> PanelUser | None:
    with panel_conn() as conn:
        row = fetch_one(
            conn,
            "SELECT id, username, role, mailbox, display_name, password_hash, active "
            "FROM panel_users WHERE username = %s",
            (username,),
        )
    if not row or not row["active"]:
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    return PanelUser(
        id=row["id"],
        username=row["username"],
        role=Role(row["role"]),
        mailbox=row["mailbox"],
        display_name=row["display_name"] or row["username"],
    )


def create_access_token(user: PanelUser) -> str:
    config = get_config()
    expire = datetime.now(timezone.utc) + timedelta(hours=config.panel.token_expire_hours)
    payload = {
        "sub": user.username,
        "role": user.role.value,
        "uid": user.id,
        "exp": expire,
    }
    return jwt.encode(payload, config.panel.secret_key, algorithm="HS256")


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
) -> PanelUser:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    config = get_config()
    try:
        payload = jwt.decode(credentials.credentials, config.panel.secret_key, algorithms=["HS256"])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        user = get_user_by_username(username)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc


def require_permission(permission: str):
    def checker(user: PanelUser = Depends(get_current_user)) -> PanelUser:
        if not role_has_permission(user.role, permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return checker


def write_audit(
    user: PanelUser,
    action: str,
    resource: str = "",
    details: str = "",
    ip_address: str | None = None,
) -> None:
    with panel_conn() as conn:
        execute(
            conn,
            "INSERT INTO audit_log (user_id, username, action, resource, details, ip_address) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (user.id, user.username, action, resource, details, ip_address),
        )


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return ""
