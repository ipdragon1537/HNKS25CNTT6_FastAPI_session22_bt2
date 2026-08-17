from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Literal

from database import db_users
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token
)
app = FastAPI()
security = HTTPBearer()
class RegisterSchema(BaseModel):
    username: str = Field(..., min_length=3, example="dr_smith")
    password: str = Field(..., min_length=6, example="SecurePassword123!")
    role: Literal["doctor", "pharmacist"]

class LoginSchema(BaseModel):
    username: str
    password: str
def get_current_user_claims(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        return payload
    except Exception as e:
        err_msg = str(e)
        if err_msg == "TOKEN_EXPIRED":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token đã hết hạn. Vui lòng đăng nhập lại."
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token không hợp lệ hoặc đã bị can thiệp."
        )
def require_role(allowed_roles: list[str]):
    def role_checker(claims: dict = Depends(get_current_user_claims)):
        user_role = claims.get("role")
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Truy cập bị từ chối: Quyền hạn không hợp lệ."
            )
        return claims
    return role_checker
@app.post("/api/v1/medical/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterSchema):
    if payload.username in db_users:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tên tài khoản đã tồn tại trên hệ thống."
        )
    hashed_pwd = hash_password(payload.password)
    db_users[payload.username] = {
        "username": payload.username,
        "hashed_password": hashed_pwd,
        "role": payload.role
    }
    return {"message": f"Tạo tài khoản {payload.role} thành công.", "username": payload.username}
@app.post("/api/v1/medical/login")
def login(payload: LoginSchema):
    user = db_users.get(payload.username)
    if not user or not verify_password(payload.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Thông tin đăng nhập không chính xác"
        )
    token_claims = {
        "sub": user["username"],
        "role": user["role"]
    }
    access_token = create_access_token(token_claims)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 1200
    }
@app.post("/api/v1/prescriptions", status_code=status.HTTP_201_CREATED)
def create_prescription(claims: dict = Depends(require_role(["doctor"]))):
    return {
        "message": "Đơn thuốc đã được ký và tạo thành công.",
        "created_by": claims.get("sub"),
        "role": claims.get("role")
    }
@app.get("/api/v1/prescriptions/view")
def view_prescriptions(claims: dict = Depends(require_role(["doctor", "pharmacist"]))):
    return {
        "message": "Danh sách đơn thuốc điện tử toàn quốc.",
        "accessed_by": claims.get("sub"),
        "role": claims.get("role")
    }