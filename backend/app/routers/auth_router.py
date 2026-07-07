from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.auth import (
    PanelUser,
    Role,
    authenticate,
    client_ip,
    create_access_token,
    get_current_user,
    require_permission,
    write_audit,
)
from app.config import Role as RoleEnum
from app.services import iredapd, mail_ops

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    display_name: str


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request) -> LoginResponse:
    user = authenticate(payload.username, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    write_audit(user, "login", "auth", ip_address=client_ip(request))
    return LoginResponse(
        access_token=create_access_token(user),
        role=user.role.value,
        display_name=user.display_name,
    )


@router.get("/me")
def me(user: PanelUser = Depends(get_current_user)) -> dict:
    return {
        "username": user.username,
        "role": user.role.value,
        "display_name": user.display_name,
        "mailbox": user.mailbox,
    }
