"""Headers every response carries, pages and API alike, set in one place."""

import logging
import re
import secrets

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from one_time_vault.storage import ID_LENGTH

logger = logging.getLogger(__name__)

# `{nonce}` becomes a fresh nonce per response. The page script is the only script, and its nonce
# lets it load the modules it imports (`strict-dynamic`).
CSP = (
    "default-src 'none'; script-src 'nonce-{nonce}' 'strict-dynamic'; connect-src 'self'; "
    "style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; "
    "object-src 'none'"
)
FIXED_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

# A secret id never goes to a log, wherever it sits in the path or query. Two nets: the segment
# after the id routes (so a malformed id is masked too), and any run of id characters as long as
# an id or longer (so `//s/<id>`, `/x/../s/<id>`, `?next=<id>` or an id glued to other characters
# cannot slip past). Routes without an id keep their path, except a 22 character name.
_ID_PREFIX = re.compile(r"^(/s/|/api/secrets/)[^/]*")
_ID_SHAPED = re.compile(rf"[A-Za-z0-9_-]{{{ID_LENGTH},}}")
_UNSAFE = re.compile(r"[^ -~]")


def loggable_path(path: str) -> str:
    """The path as one safe log token: no secret id, and no character that could forge a line.

    The ASGI path is already percent-decoded, so a caller can put a newline in it. Anything
    outside printable ASCII is written as an escape sequence (a backslash and hex digits).
    """
    path = _ID_PREFIX.sub(lambda m: m.group(1) + "<id>", path)
    path = _ID_SHAPED.sub("<id>", path)
    return _UNSAFE.sub(lambda m: m.group().encode("unicode_escape").decode("ascii"), path)


class AccessLogMask(logging.Filter):
    """Masks the secret id in uvicorn's access log, whatever flags the server was started with.

    uvicorn calls the logger with `(client, method, path, http_version, status)`. A record of
    any other shape is dropped and reported: better no line than a line that could hold an id.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) == 5 and isinstance(args[2], str):
            record.args = (*args[:2], loggable_path(args[2]), *args[3:])
            return True
        logger.warning("access log record dropped: unexpected arguments")
        return False


_ACCESS_LOG_MASK = AccessLogMask()


def mask_access_log() -> None:
    """Install the mask on uvicorn's access log (idempotent: the same filter object)."""
    logging.getLogger("uvicorn.access").addFilter(_ACCESS_LOG_MASK)


class SecurityHeadersMiddleware:
    """Outermost of ours, so 404, 413, 422 and 429 get the headers too.

    An exception nobody handled would reach Starlette's own 500 handler, which sits outside this
    middleware and adds no headers. So it is caught here: logged with its traceback, and answered
    with a generic 500 that carries the same headers and none of the detail.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        nonce = secrets.token_urlsafe(16)  # 128 random bits
        scope.setdefault("state", {})["csp_nonce"] = nonce  # the templates read it

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Content-Security-Policy"] = CSP.format(nonce=nonce)
                for name, value in FIXED_HEADERS.items():
                    headers[name] = value
            await send(message)

        started = False

        async def tracking_send(message: Message) -> None:
            nonlocal started
            started = started or message["type"] == "http.response.start"
            await send_with_headers(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception:
            if started:
                raise  # too late to change the answer
            path = loggable_path(scope["path"])
            logger.exception("unhandled error on %s %s", scope["method"], path)
            failure = JSONResponse({"detail": "internal server error"}, status_code=500)
            await failure(scope, receive, send_with_headers)
