"""Every tool declares in MCP annotations whether it only reads Kaiten data."""

import pytest
import respx
from starlette.testclient import TestClient

from kaiten_mcp import runtime
from kaiten_mcp.http_server import create_http_app
from kaiten_mcp.tool_access import DESTRUCTIVE, READ, TOOL_ACCESS, tool_annotations

SAMPLE_VALUES = {
    "integer": 1,
    "number": 1,
    "string": "x",
    "boolean": False,
    "array": [],
    "object": {},
    "null": None,
}
REMOVAL_VERBS = {"delete", "remove", "archive"}
BASE_URL = "https://company.kaiten.example"
COMPANY_ID = "123"


class RecordingClient:
    """Stands in for KaitenClient and records every request a handler sends."""

    def __init__(self):
        self.requests: list[tuple[str, str]] = []

    async def get(self, path, params=None):
        self.requests.append(("GET", path))
        return []

    async def post(self, path, json=None):
        self.requests.append(("POST", path))
        return {}

    async def patch(self, path, json=None):
        self.requests.append(("PATCH", path))
        return {}

    async def delete(self, path, json=None):
        self.requests.append(("DELETE", path))
        return {}


def _sample(prop: dict):
    if "enum" in prop:
        return prop["enum"][0]
    kind = prop["type"]
    return SAMPLE_VALUES[kind[0] if isinstance(kind, list) else kind]


def _required_args(schema: dict) -> dict:
    return {key: _sample(schema["properties"][key]) for key in schema.get("required", [])}


def test_every_tool_is_classified():
    registered = set(runtime.ALL_TOOLS)
    classified = set(TOOL_ACCESS)
    assert not registered - classified, "Classify new tools in kaiten_mcp/tool_access.py"
    assert not classified - registered, "Remove stale tools from kaiten_mcp/tool_access.py"


@pytest.mark.parametrize("name", sorted(runtime.ALL_TOOLS))
async def test_classification_matches_requests_sent_to_kaiten(name):
    definition = runtime.ALL_TOOLS[name]
    client = RecordingClient()
    await definition["handler"](client, _required_args(definition["inputSchema"]))
    access = TOOL_ACCESS[name]
    methods = {method for method, _ in client.requests}

    assert client.requests, "the handler sent no request"
    if access is READ:
        # Chart endpoints compute analytics through POST without changing data.
        assert all(
            method == "GET" or (method == "POST" and path.startswith("/charts/"))
            for method, path in client.requests
        ), client.requests
    else:
        assert methods - {"GET"}, client.requests
    verb = name.removeprefix("kaiten_").split("_")[0]
    removes = "DELETE" in methods or verb in REMOVAL_VERBS
    assert (access is DESTRUCTIVE) == removes, client.requests


def test_unclassified_tool_is_announced_as_destructive_write():
    annotations = tool_annotations("kaiten_not_classified")
    assert annotations.readOnlyHint is False
    assert annotations.destructiveHint is True


@pytest.mark.parametrize(
    ("name", "read_only", "destructive"),
    [
        ("kaiten_get_card", True, None),
        ("kaiten_list_all_cards", True, None),
        ("kaiten_get_current_user", True, None),
        ("kaiten_chart_cfd", True, None),
        ("kaiten_create_card", False, False),
        ("kaiten_update_card", False, False),
        ("kaiten_delete_card", False, True),
        ("kaiten_archive_card", False, True),
        ("kaiten_delete_sd_service", False, True),
    ],
)
async def test_list_tools_carries_annotations(name, read_only, destructive):
    tools = {tool.name: tool for tool in await runtime.list_tools()}
    annotations = tools[name].annotations
    assert annotations is not None
    assert annotations.readOnlyHint is read_only
    assert annotations.destructiveHint is destructive


def test_personal_http_inventory_declares_read_only_tools(monkeypatch):
    monkeypatch.setenv("MCP_HTTP_AUTH_MODE", "personal")
    monkeypatch.setenv("KAITEN_BASE_URL", BASE_URL)
    monkeypatch.setenv("MCP_KAITEN_COMPANY_ID", COMPANY_ID)
    with respx.mock as router:
        router.get(f"{BASE_URL}/api/latest/users/current").respond(
            200, json={"id": 42, "company_id": int(COMPANY_ID), "activated": True, "role": 2}
        )
        with TestClient(create_http_app()) as client:
            response = client.post(
                "/mcp",
                headers={
                    "Authorization": "Bearer test-personal-kaiten-token",
                    "Accept": "application/json, text/event-stream",
                    "MCP-Protocol-Version": "2025-03-26",
                },
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            )
    assert response.status_code == 200
    tools = response.json()["result"]["tools"]
    assert len(tools) == 243
    for tool in tools:
        access = TOOL_ACCESS[tool["name"]]
        if access is READ:
            assert tool["annotations"] == {"readOnlyHint": True}, tool["name"]
        else:
            assert tool["annotations"] == {
                "readOnlyHint": False,
                "destructiveHint": access is DESTRUCTIVE,
            }, tool["name"]
