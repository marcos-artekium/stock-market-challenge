"""Stock market api models"""
# pylint: disable=no-name-in-module
from typing import Optional

from pydantic import BaseModel
from pydantic.networks import EmailStr


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    username: str
    name: str
    last_name: str
    email: EmailStr


class UserInDB(User):
    password: str
