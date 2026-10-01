"""Check personal HTTP image startup and fail-closed auth without network or PATs."""

import subprocess
import sys

image = sys.argv[1]
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
        "-e",
        "MCP_HTTP_AUTH_MODE=personal",
        "-e",
        "MCP_KAITEN_COMPANY_ID=123",
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
for path, expected in [('/authorize',404),('/token',404),('/register',404)]:
 try:
  urllib.request.urlopen('http://127.0.0.1:8000'+path, timeout=2)
  raise AssertionError('Unauthenticated route accepted')
 except urllib.error.HTTPError as error: assert error.code == expected
request = urllib.request.Request('http://127.0.0.1:8000/mcp', method='POST', data=b'{}')
try:
 urllib.request.urlopen(request, timeout=2)
 raise AssertionError('Unauthenticated MCP route accepted')
except urllib.error.HTTPError as error: assert error.code == 401
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
