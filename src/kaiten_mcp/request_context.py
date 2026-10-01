"""Credentials for one stateless HTTP request; never stored globally or on disk."""

from contextvars import ContextVar
from dataclasses import dataclass, field


@dataclass(frozen=True)
class PersonalRequestContext:
    principal_id: str
    base_url: str
    kaiten_token: str = field(repr=False)
    kaiten_user_id: str = ""
    company_id: str = ""


personal_request: ContextVar[PersonalRequestContext | None] = ContextVar(
    "kaiten_personal_request", default=None
)
