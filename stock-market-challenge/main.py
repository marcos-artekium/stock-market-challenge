"""Stock Market Challenge api

"""
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from database.models import RegisteredUser
from database.helpers import session_scope

app = FastAPI(title="Stock Market Challenge", version="0.0.1")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "42bb1604cbbd11e94a0c3bc18e452592ab5ed4fe53da5e72b380dbc7b9c515b0"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    username: str
    name: str
    last_name: str
    email: str


class UserInDB(User):
    password: str


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(passeword):
    return pwd_context.hash(passeword)


def get_user(username: str):
    with session_scope() as session:
        user = session.query(RegisteredUser).filter(RegisteredUser.username == username).first()
    if user:
        return UserInDB(
            username=user.username,
            name=user.name,
            last_name=user.last_name,
            email=user.email,
            password=user.password,
        )


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    elif not verify_password(password, user.password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        username: str = payload.get("sub")  # type: ignore
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError as error:
        raise credentials_exception from error
    else:
        user = get_user(username=token_data.username)  # type: ignore
        if user is None:
            raise credentials_exception
        return user


@app.post("/sign-up", status_code=status.HTTP_201_CREATED)
async def sign_up(registered_user: UserInDB):
    with session_scope() as session:
        session.add(
            RegisteredUser(
                username=registered_user.username,
                name=registered_user.name,
                last_name=registered_user.last_name,
                email=registered_user.email,
                password=registered_user.password,
            )
        )
        session.commit()
    return {"msg": "user added to db"}


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000)
