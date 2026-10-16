"""FastAPI app: create a secret, serve the open page, reveal once.

The server only ever sees ciphertext. Whatever is wrong with a secret id (never existed, already
read, expired, malformed) the answer is the same 404, byte for byte.
"""

import base64
import mimetypes
import os
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field, model_validator
from redis.asyncio import Redis
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from one_time_vault.keyring import (
    MAX_ITERATIONS,
    MIN_ITERATIONS,
    VERIFIER_BYTES,
    Keyring,
    iterations_of,
)
from one_time_vault.ratelimit import CreateLimiter, CreateLimitMiddleware
from one_time_vault.security import SecurityHeadersMiddleware
from one_time_vault.storage import (
    ID_LENGTH,
    NotFound,
    PasswordRequired,
    Revealed,
    SecretStorage,
    WrongPassword,
)

mimetypes.add_type("text/javascript", ".js")  # module scripts need it; the Windows registry lies

HERE = Path(__file__).parent

# Lifetimes: a closed list, never a number from the caller.
TTL_SECONDS = {"1h": 3600, "1d": 86400, "7d": 604800}

IV_BYTES = 12
TAG_BYTES = 16
BLOCK_BYTES = 256  # the browser pads the plaintext to this; the server enforces it
MAX_TEXT_BYTES = 10 * 1024
# Padding always adds at least one byte (0x80), so a full 10 KB text takes one more block.
MAX_CIPHERTEXT_BYTES = (MAX_TEXT_BYTES // BLOCK_BYTES + 1) * BLOCK_BYTES + TAG_BYTES
MAX_BODY_BYTES = 16 * 1024  # base64url of the largest ciphertext is ~14 KB

_ID = re.compile(rf"[A-Za-z0-9_-]{{{ID_LENGTH}}}")


def b64url_decode(value: object) -> bytes:
    """Strict base64url without padding: the text must be exactly what encoding the bytes gives."""
    if not isinstance(value, str):
        raise ValueError("must be a string")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as exc:
        raise ValueError("invalid base64url") from exc
    if b64url_encode(raw) != value:
        raise ValueError("not canonical base64url without padding")
    return raw


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _check_iv(iv: bytes) -> bytes:
    if len(iv) != IV_BYTES:
        raise ValueError(f"iv must be {IV_BYTES} bytes")
    return iv


def _check_ciphertext(ct: bytes) -> bytes:
    if len(ct) > MAX_CIPHERTEXT_BYTES:
        raise ValueError(f"ciphertext is larger than {MAX_CIPHERTEXT_BYTES} bytes")
    body = len(ct) - TAG_BYTES
    if body < BLOCK_BYTES or body % BLOCK_BYTES:
        raise ValueError(f"plaintext must be padded to {BLOCK_BYTES}-byte blocks")
    return ct


def _check_verifier(verifier: bytes) -> bytes:
    if len(verifier) != VERIFIER_BYTES:
        raise ValueError(f"verifier must be {VERIFIER_BYTES} bytes")
    return verifier


Verifier = Annotated[bytes, BeforeValidator(b64url_decode), AfterValidator(_check_verifier)]


class CreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    iv: Annotated[bytes, BeforeValidator(b64url_decode), AfterValidator(_check_iv)]
    ciphertext: Annotated[bytes, BeforeValidator(b64url_decode), AfterValidator(_check_ciphertext)]
    expires_in: Literal["1h", "1d", "7d"]
    # Access password: both fields or neither. The iterations tell the opener how to derive it.
    password_verifier: Verifier | None = None
    iterations: Annotated[int, Field(ge=MIN_ITERATIONS, le=MAX_ITERATIONS)] | None = None

    @model_validator(mode="after")
    def _password_fields_go_together(self) -> "CreateRequest":
        if (self.password_verifier is None) != (self.iterations is None):
            raise ValueError("password_verifier and iterations go together")
        return self


class RevealRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    verifier: Verifier


class BodyLimitMiddleware:
    """413 for a body over the limit, by Content-Length and by the bytes actually streamed.

    The body is read here, up to the limit (a few KB), and replayed to the app, so an oversized
    stream is refused before the app (or FastAPI's own body error handling) sees it.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        too_large = JSONResponse({"detail": "body too large"}, status_code=413)
        declared = Headers(scope=scope).get("content-length", "")
        if declared.isdigit() and int(declared) > self.max_bytes:
            await too_large(scope, receive, send)
            return
        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > self.max_bytes:
                await too_large(scope, receive, send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if replayed:
                return await receive()
            replayed = True
            return {"type": "http.request", "body": b"".join(chunks), "more_body": False}

        await self.app(scope, replay, send)


def _not_found() -> Response:
    """The one 404 for every id that cannot be opened. Built here only, so it cannot drift."""
    return Response(b'{"detail":"not found"}', status_code=404, media_type="application/json")


def create_app(
    redis: Redis,
    keyring: Keyring,
    *,
    create_limit: int = 20,
    create_window_seconds: int = 3600,
    trusted_hops: int = 0,
) -> FastAPI:
    storage = SecretStorage(redis)
    templates = Jinja2Templates(directory=HERE / "templates")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        await redis.aclose()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    # Innermost first. The limiter sits outside the body limit so a refused body still counts.
    app.add_middleware(BodyLimitMiddleware, max_bytes=MAX_BODY_BYTES)
    limiter = CreateLimiter(redis, limit=create_limit, window_seconds=create_window_seconds)
    app.add_middleware(CreateLimitMiddleware, limiter=limiter, trusted_hops=trusted_hops)
    app.add_middleware(SecurityHeadersMiddleware)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    @app.get("/")
    async def index(request: Request) -> Response:
        return templates.TemplateResponse(request, "create.html")

    @app.api_route("/s/{secret_id}", methods=["GET", "HEAD"])
    async def open_page(request: Request, secret_id: str) -> Response:
        # Same page for every id and no storage access: opening a link consumes nothing.
        return templates.TemplateResponse(request, "open.html")

    @app.post("/api/secrets", status_code=201)
    async def create(body: CreateRequest) -> Response:
        sealed = None
        if body.password_verifier is not None and body.iterations is not None:
            sealed = keyring.seal(body.password_verifier, body.iterations)
        secret_id = await storage.create(
            body.iv + body.ciphertext, TTL_SECONDS[body.expires_in], verifier=sealed
        )
        return JSONResponse({"id": secret_id}, status_code=201)

    @app.post("/api/secrets/{secret_id}/reveal")
    async def reveal(secret_id: str, body: RevealRequest | None = None) -> Response:
        if not _ID.fullmatch(secret_id):
            return _not_found()
        result = await storage.open(secret_id, body.verifier if body else None, bind=keyring.bind)
        match result:
            case Revealed(payload):
                iv, ciphertext = payload[:IV_BYTES], payload[IV_BYTES:]
                return JSONResponse(
                    {"iv": b64url_encode(iv), "ciphertext": b64url_encode(ciphertext)}
                )
            case PasswordRequired():
                stored = await storage.peek_verifier(secret_id)
                if not stored:  # gone between the two calls
                    return _not_found()
                return JSONResponse(
                    {"error": "password_required", "iterations": iterations_of(stored)},
                    status_code=403,
                )
            case WrongPassword(attempts_left):
                return JSONResponse(
                    {"error": "wrong_password", "attempts_left": attempts_left}, status_code=403
                )
            case NotFound():
                return _not_found()

    # Registered last: anything else under /api/secrets/ (wrong path or method) is the same 404.
    @app.api_route(
        "/api/secrets/{rest:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    )
    async def unknown_secret_route(rest: str) -> Response:
        return _not_found()

    return app


def app_from_env() -> FastAPI:
    """Entry point for `uvicorn --factory --no-proxy-headers one_time_vault.app:app_from_env`.

    The server keys are required: without `OTV_SERVER_KEYS` this raises and the app does not boot.
    """
    env = os.environ
    return create_app(
        Redis.from_url(env.get("OTV_REDIS_URL", "redis://localhost:6379")),
        Keyring.parse(env.get("OTV_SERVER_KEYS")),
        create_limit=int(env.get("OTV_CREATE_LIMIT", "20")),
        create_window_seconds=int(env.get("OTV_CREATE_WINDOW_SECONDS", "3600")),
        trusted_hops=int(env.get("OTV_TRUSTED_HOPS", "0")),
    )
