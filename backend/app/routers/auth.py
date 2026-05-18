from datetime import datetime, timezone
import uuid

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.security import hash_password, verify_password, create_access_token
from app.db.mongo import (
    create_user,
    get_user_by_email,
    get_user_by_username,
    get_user_by_id,
)
from app.models.schemas import UserRegister, UserLogin, TokenResponse, UserResponse
from app.core.security import get_current_user

router = APIRouter()


def _to_user_response(user: dict) -> UserResponse:
    return UserResponse(
        user_id=user["user_id"],
        username=user["username"],
        email=user["email"],
        created_at=user["created_at"],
    )


@router.post("/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(body: UserRegister):
    email = body.email.lower()
    username = body.username.lower()

    if await get_user_by_email(email):
        raise HTTPException(status_code=400, detail="Email already registered")
    if await get_user_by_username(username):
        raise HTTPException(status_code=400, detail="Username already taken")

    user_id = str(uuid.uuid4())
    user_doc = {
        "user_id": user_id,
        "username": username,
        "email": email,
        "password_hash": hash_password(body.password),
        "created_at": datetime.now(timezone.utc),
    }
    user = await create_user(user_doc)
    token = create_access_token(user_id)

    return TokenResponse(
        access_token=token,
        user=_to_user_response(user),
    )


@router.post("/auth/login", response_model=TokenResponse)
async def login(body: UserLogin):
    user = await get_user_by_email(body.email.lower())
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(user["user_id"])
    return TokenResponse(
        access_token=token,
        user=_to_user_response(user),
    )


@router.get("/auth/me", response_model=UserResponse)
async def me(current_user: dict = Depends(get_current_user)):
    return _to_user_response(current_user)
