"""Keep runtime credentials out of diagnostic output."""

import logging
import os


def redact_secrets(message: str, *secrets: str) -> str:
    values = {
        *secrets,
        os.environ.get("KAITEN_TOKEN", ""),
        os.environ.get("MCP_AUTH_TOKEN", ""),
    }
    for value in sorted(filter(None, values), key=len, reverse=True):
        message = message.replace(value, "[REDACTED]")
    return message


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        # Formatting first also covers exceptions and third-party library logs.
        return redact_secrets(super().format(record))
