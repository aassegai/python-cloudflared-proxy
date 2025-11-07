import httpx
import uvicorn
import logging
import argparse
import os
import jwt
from datetime import datetime, timedelta
from typing import Optional

from logging.handlers import RotatingFileHandler
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import JSONResponse, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel

from crypto_utils import encrypt_json_values, decrypt_json_values
from config import load_config, load_users

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

config = load_config('src/config/config.yaml')
ALGORITHM = config["jwt"]["algorithm"]
USERS_DB_PATH = config["users"]["db_path"]
ACCESS_TOKEN_EXPIRE_MINUTES = config["jwt"]["access_token_expire_minutes"]
SECRET_KEY = config["jwt"]["secret_key"]

users_db = load_users(USERS_DB_PATH)

class User(BaseModel):
    username: str

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if ACCESS_TOKEN_EXPIRE_MINUTES and ACCESS_TOKEN_EXPIRE_MINUTES > 0:
        if expires_delta:
            expire = datetime.now() + expires_delta
        else:
            expire = datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
    # If ACCESS_TOKEN_EXPIRE_MINUTES is 0 or None, no expiration
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user(users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


def create_server_proxy(target_backend_url: str, key: bytes, iv: bytes) -> FastAPI:
    logger = logging.getLogger("server_proxy")
    app = FastAPI()

    @app.post("/token", response_model=Token)
    async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
        user = authenticate_user(users_db, form_data.username, form_data.password)
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

    async def handle_request(request: Request, current_user: User = Depends(get_current_user)):
        try:
            method = request.method
            path = request.url.path
            query = request.url.query
            headers = {
                k: v for k, v in request.headers.items()
                if k.lower() not in ["host", "content-length", "transfer-encoding"]
            }
            target_url = f"{target_backend_url}{path}"
            if query:
                target_url += f"?{query}"

            # decrypt JSON body if exists
            try:
                data = await request.json()
                timeout = data.pop('timeout', 60.0)
                data['timeout'] = timeout
                logger.debug("Using timeout: %f", timeout)
                decrypted = decrypt_json_values(data, key, iv)
                logger.debug(f"Decrypted data: {decrypted}")
            except Exception:
                timeout = 60.0
                decrypted = None

            async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
                resp = await client.request(
                    method=method,
                    url=target_url,
                    json=decrypted,
                    headers=headers,
                    content=await request.body() if decrypted is None else None,
                )

            # encrypt JSON response if possible
            try:
                json_data = resp.json()
                encrypted_resp = encrypt_json_values(json_data, key, iv)
                return JSONResponse(content=encrypted_resp, status_code=resp.status_code)
            except Exception:
                return Response(content=resp.content, status_code=resp.status_code)

        except Exception as e:
            logger.exception("Error handling request: %s", e)
            return JSONResponse(content={"error": str(e)}, status_code=500)

    app.add_api_route("/{path:path}", handle_request,
                      methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    return app


def create_client_proxy(remote_url: str, key: bytes, iv: bytes) -> FastAPI:
    logger = logging.getLogger("client_proxy")
    app = FastAPI()

    @app.post("/token", response_model=Token)
    async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
        user = authenticate_user(users_db, form_data.username, form_data.password)
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

    async def handle_request(request: Request, current_user: User = Depends(get_current_user)):
        try:
            method = request.method
            path = request.url.path
            query = request.url.query
            headers = {
                k: v for k, v in request.headers.items()
                if k.lower() not in ["host", "content-length", "transfer-encoding"]
            }
            target_url = f"{remote_url}{path}"
            if query:
                target_url += f"?{query}"

            # encrypt outgoing JSON
            try:
                data = await request.json()
                timeout = data.pop('timeout', 60.0)
                data['timeout'] = timeout
                logger.debug("Using timeout: %f", timeout)
                encrypted = encrypt_json_values(data, key, iv)
            except Exception:
                timeout = 60.0
                encrypted = None

            async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
                resp = await client.request(
                    method=method,
                    url=target_url,
                    json=encrypted,
                    headers=headers,
                    content=await request.body() if encrypted is None else None,
                )

            # decrypt server’s response
            try:
                json_data = resp.json()
                decrypted_resp = decrypt_json_values(json_data, key, iv)
                return JSONResponse(content=decrypted_resp, status_code=resp.status_code)
            except Exception:
                return Response(content=resp.content, status_code=resp.status_code)

        except Exception as e:
            logger.exception("Error handling client request: %s", e)
            return JSONResponse(content={"error": str(e)}, status_code=500)

    app.add_api_route("/{path:path}", handle_request,
                      methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    return app

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AES-encrypting proxy (client/server)")
    parser.add_argument("--mode", choices=["client", "server"], required=True, help="Proxy mode")
    parser.add_argument("--listen-port", type=int, default=8001, help="Local port to listen on")
    parser.add_argument("--target-url", required=True, help="Target backend (for server) or remote proxy (for client)")
    parser.add_argument("--key", required=True, help="AES-256 key (32 bytes)")
    parser.add_argument("--iv", required=True, help="AES IV (16 bytes)")
    parser.add_argument("--logs-path", required=False, help="Path to save logs on server")
    args = parser.parse_args()

    key = args.key.encode("utf-8")
    iv = args.iv.encode("utf-8")

    if args.mode == "server":
        if args.logs_path is not None:
            logs_path = args.logs_path
        else:
            logs_path = 'server.log'
        logger = logging.getLogger("server_proxy")
        logger.setLevel(logging.DEBUG)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        console_handler.setFormatter(console_formatter)

        # Rotating file handler
        file_handler = RotatingFileHandler(
            logs_path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        file_handler.setFormatter(file_formatter)

        # Attach handlers
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

        app = create_server_proxy(args.target_url.rstrip("/"), key, iv)

    else:
        # Client logs only to console
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s [%(levelname)s] %(message)s")
        app = create_client_proxy(args.target_url.rstrip("/"), key, iv)

    uvicorn.run(app, host="0.0.0.0", port=args.listen_port)
