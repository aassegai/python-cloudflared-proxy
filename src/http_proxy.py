import httpx
import uvicorn
import logging
import argparse

from logging.handlers import RotatingFileHandler
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from crypto_utils import encrypt_value, decrypt_value, encrypt_json_values, decrypt_json_values


def create_server_proxy(target_backend_url: str, key: bytes, iv: bytes) -> FastAPI:
    logger = logging.getLogger("server_proxy")
    app = FastAPI()

    async def handle_request(request: Request):
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

    async def handle_request(request: Request):
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
