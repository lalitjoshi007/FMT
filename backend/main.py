# main.py
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from typing import Optional
from datetime import datetime, timedelta
from pymongo import MongoClient
from bson.objectid import ObjectId
import os

# Configurations
SECRET_KEY = "UM3Mt2czA4FYFtWuwZp9mGajEmeHdcaA287kLMSCha8"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client.fmt_auth
db_users = db.users

app = FastAPI()

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth2 setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Schemas
class UserCreate(BaseModel):
    email: EmailStr
    username: Optional[str] = None
    name: Optional[str] = None
    date_of_birth: Optional[str] = None
    gender: Optional[str] = None
    provider: Optional[str] = None  # 'google' or 'facebook'

class UserAuth(BaseModel):
    email: EmailStr
    provider: str  # 'google' or 'facebook'

class Token(BaseModel):
    access_token: str
    token_type: str

# JWT Token Creation
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# First step: login/signup via Google/Facebook
@app.post("/token", response_model=Token)
def social_login(auth_data: UserAuth):
    user = db_users.find_one({"email": auth_data.email})

    if not user:
        # Auto-create partial account (no username or personal details yet)
        user_data = {
            "email": auth_data.email,
            "provider": auth_data.provider,
            "created_at": datetime.utcnow(),
            "is_profile_complete": False
        }
        db_users.insert_one(user_data)
    elif user.get("provider") != auth_data.provider:
        raise HTTPException(status_code=400, detail="Provider mismatch")

    access_token = create_access_token(data={"sub": auth_data.email})
    return {"access_token": access_token, "token_type": "bearer"}

# Second step: complete the profile (called after login if profile is not filled)
@app.post("/signup")
def complete_signup(user: UserCreate):
    existing_user = db_users.find_one({"email": user.email})
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")

    update_fields = user.dict(exclude_unset=True)
    update_fields["is_profile_complete"] = True
    db_users.update_one({"email": user.email}, {"$set": update_fields})

    return {"message": "Profile completed and user signed in successfully"}

# Get logged-in user data
@app.get("/me")
def read_users_me(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Could not validate credentials")
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    user = db_users.find_one({"email": email}, {"_id": 0})
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return user
