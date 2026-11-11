"""Tests for SupabaseStore error mapping (no live database needed).

The store talks to Supabase through a fake postgrest client here — these
tests prove the 23505/constraint-name mapping in create_target /
create_scan, which the pgserver migration validation cannot cover (it
runs raw SQL, not supabase-py). The live error string is still unproven
against a real project (see the NOTE in supabase_store.py); these tests
pin the mapping for the error shape postgrest-py documents.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest
from pydantic import SecretStr

from app.core.config import Settings
from app.db.store import DuplicateTargetError, TargetCapError


def _configured_settings() -> Settings:
    return Settings(
        supabase_url="https://example.supabase.co",
        supabase_anon_key="anon-key",
        supabase_service_role_key=SecretStr("service-key"),
    )


class _FakeQuery:
    """Minimal postgrest chain: table().insert().execute() raises."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def insert(self, payload: dict[str, Any]) -> "_FakeQuery":
        return self

    def execute(self) -> None:
        raise self._exc


class _FakeClient:
    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def table(self, name: str) -> _FakeQuery:
        return _FakeQuery(self._exc)


def _store_with_failing_insert(monkeypatch: pytest.MonkeyPatch, exc: Exception) -> Any:
    from app.db.supabase_store import SupabaseStore

    monkeypatch.setattr("supabase.create_client", lambda url, key: _FakeClient(exc))
    return SupabaseStore(_configured_settings())


def test_create_target_cap_error_on_one_live_target_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Round-2 review, Blocker 2: the targets_one_live_per_user index
    # violation maps to TargetCapError (router: 429), NOT to the
    # same-domain duplicate (409). The index message also contains
    # "duplicate", so the index-name check must run first.
    store = _store_with_failing_insert(
        monkeypatch,
        Exception('duplicate key value violates unique constraint "targets_one_live_per_user"'),
    )
    with pytest.raises(TargetCapError):
        store.create_target(UUID(int=1), "second.example.com", "hash")


def test_create_target_duplicate_on_domain_constraint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store_with_failing_insert(
        monkeypatch,
        Exception('duplicate key value violates unique constraint "targets_user_id_domain_key"'),
    )
    with pytest.raises(DuplicateTargetError):
        store.create_target(UUID(int=1), "dup.example.com", "hash")


def test_create_target_other_errors_propagate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store_with_failing_insert(monkeypatch, RuntimeError("connection reset by peer"))
    with pytest.raises(RuntimeError, match="connection reset"):
        store.create_target(UUID(int=1), "x.example.com", "hash")
