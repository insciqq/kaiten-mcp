"""Initialize the Docker stdio image and list tools, without a network or secrets."""

import json
import subprocess
import sys

requests = [
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "container-smoke", "version": "1"},
        },
    },
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
]

process = subprocess.run(
    [
        "docker",
        "run",
        "--rm",
        "-i",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        sys.argv[1],
    ],
    input="".join(json.dumps(request) + "\n" for request in requests),
    capture_output=True,
    text=True,
    timeout=30,
    check=True,
)
responses = {
    message["id"]: message
    for line in process.stdout.splitlines()
    if "id" in (message := json.loads(line))
}
assert "result" in responses[1], responses.get(1)
tools = responses[2]["result"]["tools"]
names = {tool["name"] for tool in tools}
assert {"kaiten_get_current_user", "kaiten_list_spaces", "kaiten_list_cards"} <= names
print(f"stdio image initialized; {len(tools)} tools available; network disabled")  # noqa: T201
