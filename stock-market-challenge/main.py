"""Stock Market Challenge api

"""
from collections import deque
from datetime import datetime, timedelta
from functools import lru_cache, wraps
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
import requests

from database.models import RegisteredUser
from database.helpers import session_scope
from rest.models import UserInDB, Token, TokenData

# Token constants
SECRET_KEY = "42bb1604cbbd11e94a0c3bc18e452592ab5ed4fe53da5e72b380dbc7b9c515b0"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Throttling constants
MAX_LEN = 5
SECONDS = 30
deq = deque(maxlen=MAX_LEN)  # type: deque


app = FastAPI(title="Stock Market Challenge", version="0.0.1")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Throttling expeption and decorator
class RateLimitException(Exception):
    pass


@app.exception_handler(RateLimitException)
async def rate_limit_exception_handler(*args, **kwargs):
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "error msg": f"Rate-limit reached. The API call frequency is {MAX_LEN} per {SECONDS} seconds."
        },
    )


def rate_limit(maxlen, seconds):
    def inner(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            global deq
            current_time = datetime.now()
            if len(deq) != 0:
                if len(deq) == maxlen and (current_time - deq[0]).seconds < seconds:
                    raise RateLimitException()
            deq.append(current_time)
            return await func(*args, **kwargs)

        return wrapper

    return inner


# Authentication method
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


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


async def check_credentials(token: str = Depends(oauth2_scheme)):
    """Check if credentials are valid else raise a HTTPError"""
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


@app.post("/sign-up", status_code=status.HTTP_201_CREATED)
async def sign_up(user_to_register: UserInDB):
    """Endpoint to register a new user. Both username and email address must be unique"""
    with session_scope() as session:
        registered_user = (
            session.query(RegisteredUser)
            .filter(RegisteredUser.username == user_to_register.username)
            .first()
        )
        registered_email = (
            session.query(RegisteredUser)
            .filter(RegisteredUser.email == user_to_register.email)
            .first()
        )
        if registered_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Username {user_to_register.username} already exist in database",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if registered_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Email {user_to_register.email} already exist in database",
                headers={"WWW-Authenticate": "Bearer"},
            )
        session.add(
            RegisteredUser(
                username=user_to_register.username,
                name=user_to_register.name,
                last_name=user_to_register.last_name,
                email=user_to_register.email,
                password=user_to_register.password,
            )
        )
        session.commit()
    return {"msg": "User has been successfully registered"}


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """An authorized user can log in to get a token"""
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


@lru_cache
def call_alphavantage(symbol: str):
    """Call the alpha vantage api with lru_cache to avoid exhausting the allowed api calls"""
    url = (
        f"https://www.alphavantage.co/query?function=TIME_SERIES_DAILY&symbol={symbol}"
        + "&outputsize=compact&apikey=X86NOH6II01P7R24"
    )

    return requests.get(url)


@app.get("/stock-info/")
@rate_limit(maxlen=MAX_LEN, seconds=SECONDS)
async def get_stock_information(symbol: str, token: str = Depends(oauth2_scheme)):
    """Call Alpha Vantage API to retrieve stock information from the stock symbol
    passed as a header request.

    It's necessary to be an authorized user to consume the endpoint. The service return
    a json with the open, high and low price values, and the variation between the
    last two closing price values."""
    await check_credentials(token)

    response = call_alphavantage(symbol)

    try:
        daily_stock_info = response.json()["Time Series (Daily)"]
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Oops, something went wrong, try again.",
        )
    else:
        current_day, last_day, *_ = sorted(daily_stock_info, reverse=True)

        needed_info = {
            "open_price": daily_stock_info[current_day]["1. open"],
            "higher_price": daily_stock_info[current_day]["2. high"],
            "lower_price": daily_stock_info[current_day]["3. low"],
            "variation_last_two_closing_price": round(
                float(daily_stock_info[current_day]["4. close"])
                - float(daily_stock_info[last_day]["4. close"]),
                4,
            ),
        }

        return {symbol: needed_info}


@app.get("/test-rl")
@rate_limit(maxlen=MAX_LEN, seconds=SECONDS)
async def test_ri():
    return {"msg": "endpoint called"}


if __name__ == "__main__":
    from uvicorn import Config, Server
    from logs.utils import setup_logging, LOG_LEVEL

    server = Server(
        Config("main:app", host="0.0.0.0", log_level=LOG_LEVEL, reload=True),
    )

    # setup logging last, to make sure no library overwrites it
    setup_logging()

    server.run()
