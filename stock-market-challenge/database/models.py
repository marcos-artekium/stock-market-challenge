"""User database model"""
from passlib.context import CryptContext
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class RegisteredUser(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    name = Column(String)
    last_name = Column(String)
    email = Column(String)
    password = Column(String)

    def __init__(self, username, name, last_name, email, password):
        self.username = username
        self.name = name
        self.last_name = last_name
        self.email = email
        self.password = pwd_context.hash(password)
