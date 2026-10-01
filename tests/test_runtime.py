"""Tests for shared runtime helpers."""

import io
import logging
from unittest.mock import AsyncMock, patch

import pytest

from kaiten_mcp import runtime
from kaiten_mcp.logging_utils import RedactingFormatter


@pytest.mark.asyncio
async def test_close_client_closes_and_clears_cached_client():
    client = AsyncMock()
    with patch("kaiten_mcp.runtime._client", client):
        await runtime.close_client()

    client.close.assert_awaited_once()
    assert runtime._client is None


async def test_error_redacts_credentials_from_tool_output_and_logs(monkeypatch, caplog):
    token = "personal-secret-that-must-not-leak"
    monkeypatch.setenv("KAITEN_TOKEN", token)
    tool = "kaiten_get_space"
    handler = AsyncMock(side_effect=ValueError(f"Rejected Bearer {token}"))
    with (
        patch("kaiten_mcp.runtime.get_client", return_value=AsyncMock()),
        patch.dict(runtime.ALL_TOOLS, {tool: {"handler": handler}}),
    ):
        result = await runtime.call_tool(tool, {"space_id": 1})

    assert result.isError
    assert token not in result.model_dump_json()
    assert token not in caplog.text
    assert "[REDACTED]" in caplog.text


def test_log_formatter_redacts_exception_traceback(monkeypatch):
    token = "personal-secret-that-must-not-leak"
    monkeypatch.setenv("KAITEN_TOKEN", token)
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.setFormatter(RedactingFormatter())
    logger = logging.getLogger("redaction-test")
    logger.addHandler(handler)
    try:
        try:
            raise ValueError(f"Bearer {token}")
        except ValueError:
            logger.exception("Request failed")
    finally:
        logger.removeHandler(handler)

    assert token not in output.getvalue()
    assert "[REDACTED]" in output.getvalue()
