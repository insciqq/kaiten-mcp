"""Initialize the Docker stdio image and list tools, without a network or secrets."""

import json
import queue
import subprocess
import sys
import threading
import time

process = subprocess.Popen(
    [
        "docker", "run", "--rm", "-i", "--network=none", "--read-only",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", sys.argv[1],
    ],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
    bufsize=1,
)
messages = queue.Queue()


def read_messages():
    for line in process.stdout:
        messages.put(json.loads(line))
    messages.put(None)


threading.Thread(target=read_messages, daemon=True).start()


def send(message):
    process.stdin.write(json.dumps(message) + "\n")
    process.stdin.flush()


def response(identifier):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        message = messages.get(timeout=max(0.01, deadline - time.monotonic()))
        if message is None:
            raise RuntimeError("stdio process ended before the expected response")
        if message.get("id") == identifier:
            assert "result" in message, message
            return message["result"]
    raise RuntimeError("stdio response timed out")


try:
    send({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "container-smoke", "version": "1"},
        },
    })
    response(1)
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = response(2)["tools"]
    names = {tool["name"] for tool in tools}
    assert {"kaiten_get_current_user", "kaiten_list_spaces", "kaiten_list_cards"} <= names
    print(f"stdio image initialized; {len(tools)} tools available; network disabled")  # noqa: T201
finally:
    # EOF is only sent after all responses arrived; early EOF races SDK task cleanup.
    process.stdin.close()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.terminate()
        process.wait(timeout=5)
