from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from database import supabase
from auth import hash_password, verify_password, create_token

router = APIRouter()

class RegisterInput(BaseModel):
    username: str
    password: str

class LoginInput(BaseModel):
    username: str
    password: str

@router.post("/register")
def register(data: RegisterInput):
    username = data.username.lower().strip()
    if len(username) < 3:
        raise HTTPException(400, "Username too short")
    if len(data.password) < 8:
        raise HTTPException(400, "Password too short (min 8)")

    existing = supabase.table("users").select("id").eq("username", username).execute()
    if existing.data:
        raise HTTPException(400, "Username already taken")

    hashed = hash_password(data.password)
    result = supabase.table("users").insert({
        "username": username,
        "password_hash": hashed
    }).execute()

    user = result.data[0]
    token = create_token(user["id"])
    return {"token": token, "user": {"id": user["id"], "username": user["username"]}}

@router.post("/login")
def login(data: LoginInput):
    username = data.username.lower().strip()
    result = supabase.table("users").select("*").eq("username", username).execute()
    if not result.data:
        raise HTTPException(400, "User not found")

    user = result.data[0]
    if not verify_password(data.password, user["password_hash"]):
        raise HTTPException(400, "Incorrect password")

    if user.get("is_banned"):
        raise HTTPException(403, "Account banned")

    token = create_token(user["id"])
    supabase.table("users").update({"is_online": True}).eq("id", user["id"]).execute()
    return {"token": token, "user": {"id": user["id"], "username": user["username"]}}
