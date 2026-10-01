"""Keep runtime credentials out of diagnostic output."""

import json
import logging
import os

from kaiten_mcp.request_context import personal_request


def redact_secrets(message: str, *secrets: str) -> str:
    values = {
        *secrets,
        os.environ.get("KAITEN_TOKEN", ""),
        os.environ.get("MCP_AUTH_TOKEN", ""),
    }
    context = personal_request.get()
    if context is not None:
        values.add(context.kaiten_token)
    # JSON serialization escapes quotes/backslashes inside opaque credentials.
    values.update(json.dumps(value, ensure_ascii=False)[1:-1] for value in tuple(values) if value)
    for value in sorted(filter(None, values), key=len, reverse=True):
        message = message.replace(value, "[REDACTED]")
    return message


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        # Formatting first also covers exceptions and third-party library logs.
        return redact_secrets(super().format(record))
