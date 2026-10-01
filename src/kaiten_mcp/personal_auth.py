"""Personal HTTP authentication without OAuth or server-side Kaiten token storage."""

import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from kaiten_mcp.client import KaitenApiError, KaitenClient, normalize_api_base_url
from kaiten_mcp.logging_utils import redact_secrets
from kaiten_mcp.request_context import PersonalRequestContext, personal_request

MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_REGISTRY_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 4096


@dataclass(frozen=True)
class AccessKey:
    id: str
    sha256: str
    kaiten_user_id: str | None = None


def read_access_keys(path: Path) -> list[AccessKey]:
    """Read on each request so replacing the registry immediately revokes keys."""
    with path.open("rb") as registry:
        raw = registry.read(MAX_REGISTRY_BYTES + 1)
    if len(raw) > MAX_REGISTRY_BYTES:
        raise ValueError("MCP access key registry is too large")
    data = json.loads(raw)
    if not isinstance(data, dict) or set(data) != {"keys"} or not isinstance(data["keys"], list):
        raise ValueError("Invalid MCP access key registry")
    keys = []
    ids: set[str] = set()
    hashes: set[str] = set()
    for entry in data["keys"]:
        if not isinstance(entry, dict) or set(entry) - {"id", "sha256", "kaiten_user_id"}:
            raise ValueError("Invalid MCP access key entry")
        label, digest, user_id = entry.get("id"), entry.get("sha256"), entry.get("kaiten_user_id")
        if (
            not isinstance(label, str)
            or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", label)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or label in ids
            or digest in hashes
            or (user_id is not None and (not isinstance(user_id, str) or not user_id.isdecimal()))
        ):
            raise ValueError("Invalid or duplicate MCP access key entry")
        ids.add(label)
        hashes.add(digest)
        keys.append(AccessKey(label, digest, user_id))
    return keys


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


def _single_header(scope: Scope, name: bytes) -> str:
    values = [value for key, value in scope.get("headers", []) if key.lower() == name]
    if len(values) != 1:
        return ""
    try:
        value: str = values[0].decode("ascii")
    except UnicodeDecodeError:
        return ""
    if (
        not value
        or len(value) > MAX_TOKEN_BYTES
        or any(ord(char) < 33 or ord(char) > 126 for char in value)
    ):
        return ""
    return value


class PersonalAuthMiddleware:
    """Authenticate two headers and pass isolated credentials through the MCP task group."""

    def __init__(self, app: ASGIApp):
        self.app = app
        self.base_url = personal_base_url()
        path = os.environ.get("MCP_ACCESS_KEYS_FILE", "")
        if not path:
            raise ValueError("MCP_ACCESS_KEYS_FILE is required in personal HTTP mode")
        self.registry_path = Path(path)
        read_access_keys(self.registry_path)  # Fail closed at startup for malformed/missing files.
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
        request = Request(scope)
        if request.headers.get("origin") and request.headers["origin"] not in self.allowed_origins:
            await reject(403, "Forbidden origin")
            return
        # Authorization contains one separating space, unlike the opaque token itself.
        auth_headers = [
            value for key, value in scope.get("headers", []) if key.lower() == b"authorization"
        ]
        edge_key = ""
        if len(auth_headers) == 1 and auth_headers[0].lower().startswith(b"bearer "):
            stripped_scope = {**scope, "headers": [(b"edge-key", auth_headers[0][7:])]}
            edge_key = _single_header(stripped_scope, b"edge-key")
        kaiten_token = _single_header(scope, b"x-kaiten-token")
        if not edge_key or not kaiten_token:
            await reject(401, "Unauthorized")
            return
        try:
            keys = read_access_keys(self.registry_path)
        except (OSError, ValueError):
            await reject(503, "Access registry unavailable")
            return
        digest = hashlib.sha256(edge_key.encode("ascii")).hexdigest()
        identity = next((key for key in keys if secrets.compare_digest(key.sha256, digest)), None)
        if identity is None:
            await reject(401, "Unauthorized")
            return

        # Buffer a bounded body before invoking the SDK (including chunked requests).
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

        context_token = personal_request.set(
            PersonalRequestContext(identity.id, self.base_url, kaiten_token, edge_key)
        )
        response_start = None
        response_body = bytearray()

        async def redacted_send(message):
            # json_response=True makes responses finite JSON, not long-lived SSE streams.
            # Also covers validation errors emitted by the SDK before call_tool runs.
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
            except ValueError:
                await reject(503, "Kaiten authentication unavailable")
                return
            finally:
                await client.close()
            if (
                not isinstance(user, dict)
                or not user.get("id")
                or (
                    identity.kaiten_user_id is not None
                    and str(user["id"]) != identity.kaiten_user_id
                )
            ):
                await reject(401, "Unauthorized")
                return
            personal_request.set(
                PersonalRequestContext(
                    identity.id, self.base_url, kaiten_token, edge_key, str(user["id"])
                )
            )
            # There are no persistent sessions or server-initiated notifications.
            # A GET SSE stream would retain credentials beyond one finite request.
            if scope["method"] != "POST":
                await reject(405, "Only POST is supported")
                return
            await self.app(scope, bounded_receive, redacted_send)
        finally:
            personal_request.reset(context_token)
