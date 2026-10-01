"""Stateless HTTP authentication with a user's Kaiten API token.

The bearer token is the user's Kaiten PAT. It is accepted for one request,
checked against the configured Kaiten tenant, and never persisted by this
service. There is deliberately no second, server-issued access key.
"""

import os
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from kaiten_mcp.client import KaitenApiError, KaitenClient, normalize_api_base_url
from kaiten_mcp.logging_utils import redact_secrets
from kaiten_mcp.request_context import PersonalRequestContext, personal_request

MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_TOKEN_BYTES = 4096


def personal_base_url() -> str:
    value = os.environ.get("KAITEN_BASE_URL", "")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.port not in {None, 443}
        or parsed.path.rstrip("/") not in {"", "/api", "/api/latest"}
        or any(character.isspace() for character in value)
    ):
        raise ValueError("Personal HTTP mode requires a fixed HTTPS KAITEN_BASE_URL")
    return normalize_api_base_url(value)


def _company_id() -> str:
    value = os.environ.get("MCP_KAITEN_COMPANY_ID", "").strip()
    if not value.isdecimal() or int(value) <= 0:
        raise ValueError("Personal HTTP mode requires a positive MCP_KAITEN_COMPANY_ID")
    return value


def _bearer_token(scope: Scope) -> str:
    values = [value for key, value in scope.get("headers", []) if key.lower() == b"authorization"]
    if len(values) != 1:
        return ""
    try:
        value: str = values[0].decode("ascii")
    except UnicodeDecodeError:
        return ""
    if len(value) > MAX_TOKEN_BYTES or not value.lower().startswith("bearer "):
        return ""
    token: str = value[7:]
    if not token or any(ord(character) < 33 or ord(character) > 126 for character in token):
        return ""
    return token


def _positive_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


class PersonalAuthMiddleware:
    """Authenticate a Kaiten PAT and pass isolated credentials to one request."""

    def __init__(self, app: ASGIApp):
        self.app = app
        self.base_url = personal_base_url()
        self.company_id = _company_id()
        self.allowed_origins = frozenset(
            value.strip()
            for value in os.environ.get("MCP_ALLOWED_ORIGINS", "").split(",")
            if value.strip()
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def reject(status: int, error: str) -> None:
            headers = {"Cache-Control": "no-store"}
            if status == 401:
                headers["WWW-Authenticate"] = 'Bearer realm="kaiten-mcp"'
            if status == 405:
                headers["Allow"] = "POST"
            await JSONResponse({"error": error}, status_code=status, headers=headers)(
                scope, receive, send
            )

        if (
            sum(len(key) + len(value) for key, value in scope.get("headers", []))
            > MAX_HEADER_BYTES
        ):
            await reject(431, "Request headers too large")
            return
        if scope.get("query_string"):
            await reject(400, "Query parameters are not supported")
            return
        if scope.get("method") != "POST":
            # Do this before credential validation: GET/DELETE cannot create
            # an SSE stream or session and must not trigger a Kaiten probe.
            await reject(405, "Only POST is supported")
            return
        request = Request(scope)
        if request.headers.get("origin") and request.headers["origin"] not in self.allowed_origins:
            await reject(403, "Forbidden origin")
            return
        # A legacy X-Kaiten-Token must never be accepted alongside or instead
        # of Authorization; rejecting it avoids ambiguous credential handling.
        if any(key.lower() == b"x-kaiten-token" for key, _ in scope.get("headers", [])):
            await reject(401, "Unauthorized")
            return
        kaiten_token = _bearer_token(scope)
        if not kaiten_token:
            await reject(401, "Unauthorized")
            return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > MAX_BODY_BYTES:
                await reject(413, "Request body too large")
                return
            if not message.get("more_body", False):
                break
        body_sent = False

        async def bounded_receive():
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        response_start = None
        response_body = bytearray()

        async def redacted_send(message):
            # json_response=True makes responses finite JSON, not long-lived SSE streams.
            nonlocal response_start
            if message["type"] == "http.response.start":
                response_start = message
                return
            if message["type"] == "http.response.body":
                response_body.extend(message.get("body", b""))
                if message.get("more_body", False):
                    return
                safe_body = redact_secrets(response_body.decode("utf-8")).encode("utf-8")
                if response_start is not None:
                    response_start["headers"] = [
                        (key, value)
                        for key, value in response_start.get("headers", [])
                        if key.lower() not in {b"content-length", b"cache-control"}
                    ] + [
                        (b"content-length", str(len(safe_body)).encode()),
                        (b"cache-control", b"no-store"),
                    ]
                    await send(response_start)
                await send({**message, "body": safe_body})
                return
            await send(message)

        # Install a short-lived redaction context while the user's PAT is
        # validated, then replace it with the verified identity before MCP
        # dispatch. This also covers upstream errors and diagnostic logging.
        context_token = personal_request.set(
            PersonalRequestContext("pending", self.base_url, kaiten_token, "", self.company_id)
        )
        try:
            client = KaitenClient(token=kaiten_token, base_url=self.base_url)
            try:
                user = await client.get("/users/current")
            except KaitenApiError as error:
                if error.status_code in {401, 403}:
                    await reject(401, "Unauthorized")
                else:
                    await reject(503, "Kaiten authentication unavailable")
                return
            except (ValueError, TypeError):
                await reject(503, "Kaiten authentication unavailable")
                return
            finally:
                await client.close()
            user_id = _positive_int(user.get("id")) if isinstance(user, dict) else None
            company_id = _positive_int(user.get("company_id")) if isinstance(user, dict) else None
            role = user.get("role") if isinstance(user, dict) else None
            if (
                user_id is None
                or company_id is None
                or str(company_id) != self.company_id
                or user.get("activated") is not True
                or type(role) is not int
                or role not in {1, 2}
            ):
                await reject(401, "Unauthorized")
                return
            personal_request.reset(context_token)
            context_token = personal_request.set(
                PersonalRequestContext(
                    str(user_id), self.base_url, kaiten_token, str(user_id), str(company_id)
                )
            )
            await self.app(scope, bounded_receive, redacted_send)
        finally:
            if context_token is not None:
                personal_request.reset(context_token)
