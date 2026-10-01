"""Real stateless transport tests for personal credentials and API-key isolation."""

import asyncio
import hashlib
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from starlette.testclient import TestClient

from kaiten_mcp import runtime
from kaiten_mcp.auth import AUTH_STORE
from kaiten_mcp.client import KaitenClient
from kaiten_mcp.http_server import create_http_app
from kaiten_mcp.personal_auth import MAX_BODY_BYTES, PersonalAuthMiddleware
from kaiten_mcp.request_context import PersonalRequestContext, personal_request

BASE_URL = "https://company.kaiten.example"
EDGE_KEY = "test-edge-key-with-sufficient-entropy"
PAT = "test-personal-kaiten-token"


def write_keys(path, *entries):
    path.write_text(
        json.dumps(
            {
                "keys": [
                    {"id": label, "sha256": hashlib.sha256(key.encode()).hexdigest(), **extras}
                    for label, key, extras in entries
                ]
            }
        )
    )


@pytest.fixture
def registry(tmp_path, monkeypatch):
    path = tmp_path / "access-keys.json"
    write_keys(path, ("alice", EDGE_KEY, {"kaiten_user_id": "42"}))
    monkeypatch.setenv("MCP_HTTP_AUTH_MODE", "personal")
    monkeypatch.setenv("MCP_ACCESS_KEYS_FILE", str(path))
    monkeypatch.setenv("KAITEN_BASE_URL", BASE_URL)
    # Even a configured shared token must never be used as a fallback.
    monkeypatch.setenv("KAITEN_TOKEN", "global-token-must-not-be-used")
    return path


def headers(edge=EDGE_KEY, pat=PAT):
    return {
        "Authorization": f"Bearer {edge}",
        "X-Kaiten-Token": pat,
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-03-26",
    }


def rpc(method="tools/list", params=None):
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}


@pytest.fixture
def upstream():
    with respx.mock as router:
        route = router.get(f"{BASE_URL}/api/latest/users/current").respond(200, json={"id": 42})
        yield router, route


def test_personal_inventory_exact_path_and_no_oauth(registry, upstream):
    with TestClient(create_http_app()) as client:
        response = client.post("/mcp", headers=headers(), json=rpc(), follow_redirects=False)
        assert response.status_code == 200
        tools = response.json()["result"]["tools"]
        assert len(tools) == 243
        assert not runtime.PERSONAL_EXCLUDED_TOOLS.intersection(tool["name"] for tool in tools)
        assert client.get("/mcp/", follow_redirects=False).status_code == 404
        assert client.get("/healthz").status_code == 200
        assert client.get("/readyz").json()["auth_mode"] == "personal"
        for path in (
            "/authorize",
            "/token",
            "/register",
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-protected-resource",
            "/.well-known/openid-configuration",
        ):
            assert client.get(path).status_code == 404
    assert AUTH_STORE.credentials == {}
    assert personal_request.get() is None


@pytest.mark.parametrize(
    "auth_headers",
    [
        {},
        {"Authorization": f"Bearer {EDGE_KEY}"},
        {"X-Kaiten-Token": PAT},
        headers(edge="wrong"),
        headers(pat=""),
        headers(pat="unsafe token"),
        [*headers().items(), ("X-Kaiten-Token", "duplicate")],
        [*headers().items(), ("Authorization", f"Bearer {EDGE_KEY}")],
    ],
)
def test_missing_invalid_or_duplicate_credentials_never_fall_back(registry, auth_headers):
    with respx.mock(assert_all_called=False) as router, TestClient(create_http_app()) as client:
        response = client.post("/mcp", headers=auth_headers, json=rpc())
        assert response.status_code == 401
        assert "resource_metadata" not in response.headers["www-authenticate"]
        assert len(router.calls) == 0


@pytest.mark.parametrize(
    "status,user", [(401, {"message": PAT}), (403, {}), (200, {"id": 99}), (200, {})]
)
def test_kaiten_validation_and_optional_user_binding(registry, status, user):
    with respx.mock as router, TestClient(create_http_app()) as client:
        route = router.get(f"{BASE_URL}/api/latest/users/current").respond(status, json=user)
        response = client.post("/mcp", headers=headers(), json=rpc())
        assert response.status_code == 401
        assert PAT not in response.text
        assert route.calls.last.request.headers["authorization"] == f"Bearer {PAT}"


def test_registry_reload_revokes_without_restart(registry, upstream):
    with TestClient(create_http_app()) as client:
        assert client.post("/mcp", headers=headers(), json=rpc()).status_code == 200
        write_keys(registry)
        assert client.post("/mcp", headers=headers(), json=rpc()).status_code == 401
        registry.write_text("invalid JSON")
        assert client.post("/mcp", headers=headers(), json=rpc()).status_code == 503


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://company.kaiten.example",
        "https://alice:secret@company.kaiten.example",
        "https://company.kaiten.example?key=secret",
        "https://company.kaiten.example/other",
        "https://company.kaiten.example:8443",
    ],
)
def test_unsafe_fixed_host_fails_startup(registry, monkeypatch, url):
    monkeypatch.setenv("KAITEN_BASE_URL", url)
    with pytest.raises(ValueError, match="fixed HTTPS"):
        create_http_app()


def test_invalid_mode_and_registry_fail_startup(registry, monkeypatch):
    monkeypatch.setenv("MCP_HTTP_AUTH_MODE", "persnoal")
    with pytest.raises(ValueError, match="Unsupported"):
        create_http_app()
    monkeypatch.setenv("MCP_HTTP_AUTH_MODE", "personal")
    registry.write_text('{"keys":[{"id":"alice","sha256":"plaintext-is-not-a-hash"}]}')
    with pytest.raises(ValueError, match="Invalid"):
        create_http_app()


def test_origin_and_query_rejected_before_credentials_reach_upstream(registry):
    with respx.mock(assert_all_called=False) as router, TestClient(create_http_app()) as client:
        assert client.post("/mcp?token=secret", headers=headers(), json=rpc()).status_code == 400
        assert (
            client.post(
                "/mcp", headers={**headers(), "Origin": "https://evil.example"}, json=rpc()
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/mcp", headers={**headers(), "Too-Large": "x" * 17000}, json=rpc()
            ).status_code
            == 431
        )
        assert len(router.calls) == 0


async def test_chunked_body_size_bounded_before_upstream_validation(registry):
    inner = AsyncMock()
    middleware = PersonalAuthMiddleware(inner)
    receive = AsyncMock(
        side_effect=[
            {"type": "http.request", "body": b"x" * MAX_BODY_BYTES, "more_body": True},
            {"type": "http.request", "body": b"x", "more_body": False},
        ]
    )
    send = AsyncMock()
    scope = {
        "type": "http",
        "headers": [(key.lower().encode(), value.encode()) for key, value in headers().items()],
        "query_string": b"",
    }
    await middleware(scope, receive, send)
    assert send.await_args_list[0].args[0]["status"] == 413
    inner.assert_not_awaited()


@pytest.mark.parametrize("name", sorted(runtime.PERSONAL_EXCLUDED_TOOLS))
def test_disabled_tools_cannot_be_called_directly(registry, upstream, name):
    with TestClient(create_http_app()) as client:
        response = client.post(
            "/mcp",
            headers=headers(),
            json=rpc("tools/call", {"name": name, "arguments": {"name": "new", "key_id": 1}}),
        )
        assert response.status_code == 200
        assert response.json()["result"]["isError"]
    assert len(upstream[0].calls) == 1  # Only authentication, never /api-keys.


def test_tools_reject_wrong_type_ids_before_upstream_call(registry, upstream):
    with TestClient(create_http_app()) as client:
        response = client.post(
            "/mcp",
            headers=headers(),
            json=rpc(
                "tools/call",
                {"name": "kaiten_get_card", "arguments": {"card_id": "../../api-keys"}},
            ),
        )
        assert response.json()["result"]["isError"]
    assert len(upstream[0].calls) == 1


async def test_upstream_paths_cannot_escape_or_redirect(registry):
    context = personal_request.set(PersonalRequestContext("alice", BASE_URL, PAT, EDGE_KEY))
    client = KaitenClient(token=PAT, base_url=BASE_URL)
    try:
        for path in (
            "//evil.example",
            "https://evil.example",
            "/calendars/../api-keys",
            "/calendars/%2e%2e",
            "/calendars/valid?token=other",
            "/calendars/id#fragment",
            "/calendars/x\\y",
        ):
            with pytest.raises(ValueError, match="Invalid Kaiten API path"):
                await client.get(path)
        with respx.mock as router:
            router.get(f"{BASE_URL}/api/latest/users/current").respond(
                302, headers={"Location": "https://evil.example"}
            )
            from kaiten_mcp.client import KaitenApiError

            with pytest.raises(KaitenApiError, match="redirects are not allowed"):
                await client.get("/users/current")
            assert len(router.calls) == 1
    finally:
        await client.close()
        personal_request.reset(context)


async def test_personal_runtime_never_uses_global_token_without_context(registry):
    with pytest.raises(ValueError, match="authentication context"):
        runtime.get_client()


async def test_concurrent_real_mcp_dispatch_preserves_credentials(registry):
    """The SDK starts server tasks in its lifespan task group; test that actual boundary."""
    second_key, second_pat = "second-edge-access-key", "second-user-personal-kaiten-token"
    write_keys(
        registry,
        ("alice", EDGE_KEY, {"kaiten_user_id": "42"}),
        ("bob", second_key, {"kaiten_user_id": "43"}),
    )
    arrivals = 0
    ready = asyncio.Event()
    clients = []

    async def probe(client, args):
        nonlocal arrivals
        clients.append(client)
        arrivals += 1
        if arrivals == 2:
            ready.set()
        await asyncio.wait_for(ready.wait(), timeout=5)
        await asyncio.sleep(0)
        context = personal_request.get()
        assert context.kaiten_token == client.token
        user = await client.get("/users/current")
        # Verify request tokens are also redacted in successful upstream responses.
        return {"id": user["id"], "token": client.token, "edge_key": context.access_key}

    async def current_user(request):
        user_id = 42 if request.headers["authorization"] == f"Bearer {PAT}" else 43
        return httpx.Response(200, json={"id": user_id})

    app = create_http_app()
    with (
        patch.dict(
            runtime.ALL_TOOLS,
            {
                "test_probe": {
                    "description": "Probe",
                    "inputSchema": {"type": "object"},
                    "handler": probe,
                }
            },
        ),
        respx.mock as router,
    ):
        router.get(f"{BASE_URL}/api/latest/users/current").mock(side_effect=current_user)
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://testserver"
            ) as client,
        ):
            replies = await asyncio.gather(
                *[
                    client.post(
                        "/mcp",
                        headers=auth,
                        json=rpc("tools/call", {"name": "test_probe", "arguments": {}}),
                    )
                    for auth in (headers(), headers(edge=second_key, pat=second_pat))
                ]
            )
    results = [json.loads(response.json()["result"]["content"][0]["text"]) for response in replies]
    assert [result["id"] for result in results] == [42, 43]
    assert all(
        result["token"] == "[REDACTED]" and result["edge_key"] == "[REDACTED]"
        for result in results
    )
    assert all(client._client.is_closed for client in clients)
    assert personal_request.get() is None
    assert AUTH_STORE.credentials == {}


def test_request_credentials_redacted_from_errors_and_logs(registry, upstream, caplog):
    handler = AsyncMock(side_effect=ValueError(f"Rejected {PAT} / {EDGE_KEY}"))
    with (
        patch.dict(
            runtime.ALL_TOOLS,
            {
                "test_probe": {
                    "description": "Probe",
                    "inputSchema": {"type": "object"},
                    "handler": handler,
                }
            },
        ),
        TestClient(create_http_app()) as client,
    ):
        response = client.post(
            "/mcp",
            headers=headers(),
            json=rpc("tools/call", {"name": "test_probe", "arguments": {}}),
        )
        assert response.json()["result"]["isError"]
    assert PAT not in response.text + caplog.text
    assert EDGE_KEY not in response.text + caplog.text
    assert "[REDACTED]" in response.text


def test_personal_mode_does_not_persist_large_results_or_escaped_tokens(
    registry, tmp_path, monkeypatch
):
    escaped_pat = 'token-with-"quote-and-\\-backslash'
    token = personal_request.set(PersonalRequestContext("alice", BASE_URL, escaped_pat, EDGE_KEY))
    output_dir = tmp_path / "tool-output"
    monkeypatch.setenv("KAITEN_MCP_OUTPUT_DIR", str(output_dir))
    try:
        result = runtime._serialize_result("test", {"token": escaped_pat, "data": "x" * 210000})
    finally:
        personal_request.reset(token)
    assert json.loads(result)["token"] == "[REDACTED]"
    assert not output_dir.exists()


def test_invalid_upstream_json_is_a_generic_auth_failure(registry):
    with respx.mock as router, TestClient(create_http_app()) as client:
        router.get(f"{BASE_URL}/api/latest/users/current").respond(200, text=PAT)
        response = client.post("/mcp", headers=headers(), json=rpc())
    assert response.status_code == 503
    assert PAT not in response.text


def test_sdk_validation_error_does_not_echo_credentials(registry, upstream):
    with TestClient(create_http_app()) as client:
        response = client.post(
            "/mcp",
            headers=headers(),
            json=rpc("tools/call", {"name": "kaiten_get_card", "arguments": {"card_id": PAT}}),
        )
    assert response.json()["result"]["isError"]
    assert PAT not in response.text
    assert int(response.headers["content-length"]) == len(response.content)


def test_get_stream_and_delete_session_are_not_supported(registry, upstream):
    with TestClient(create_http_app()) as client:
        for method in ("GET", "DELETE"):
            response = client.request(method, "/mcp", headers=headers())
            assert response.status_code == 405
            assert response.headers["allow"] == "POST"
