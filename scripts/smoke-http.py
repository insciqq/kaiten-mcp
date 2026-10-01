"""Check personal HTTP image startup and fail-closed auth without network or PATs."""

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

image = sys.argv[1]
with tempfile.TemporaryDirectory() as directory:
    registry = Path(directory) / "access-keys.json"
    registry.write_text(
        json.dumps(
            {"keys": [{"id": "smoke", "sha256": hashlib.sha256(b"fake-smoke-key").hexdigest()}]}
        )
    )
    registry.chmod(0o644)
    container = subprocess.check_output(
        [
            "docker",
            "run",
            "-d",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--tmpfs",
            "/tmp:rw,nosuid,noexec,size=16m",
            "--mount",
            f"type=bind,src={registry},dst=/run/secrets/access-keys.json,readonly",
            "-e",
            "MCP_HTTP_AUTH_MODE=personal",
            "-e",
            "MCP_ACCESS_KEYS_FILE=/run/secrets/access-keys.json",
            "-e",
            "KAITEN_BASE_URL=https://example.kaiten.ru",
            "--entrypoint",
            "kaiten-mcp-http",
            image,
        ],
        text=True,
    ).strip()
    try:
        probe = """import time, urllib.request, urllib.error
for attempt in range(40):
 try:
  with urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=1) as r: assert r.status == 200
  break
 except OSError: time.sleep(.25)
else: raise RuntimeError('HTTP server did not start')
for path, expected in [('/mcp',401),('/authorize',404),('/token',404),('/register',404)]:
 try:
  urllib.request.urlopen('http://127.0.0.1:8000'+path, timeout=2)
  raise AssertionError('Unauthenticated route accepted')
 except urllib.error.HTTPError as error: assert error.code == expected
print('personal HTTP image: health ready, missing auth rejected, OAuth routes absent')
"""
        subprocess.run(
            ["docker", "exec", "-i", container, "python", "-"],
            input=probe,
            text=True,
            check=True,
            timeout=20,
        )
    finally:
        subprocess.run(["docker", "rm", "-f", container], check=True, stdout=subprocess.DEVNULL)
