"""Tests for proxy-safe Supabase client construction (live-proof fix F1).

Regression: the VM's stock ``no_proxy`` contains bracketed IPv6 entries
(``[::1]``, ``[fd8b:...]``); httpx turns ``[::1]`` into the proxy mount
``all://*[::1]``, whose port ``:1]`` fails URL parsing, so a plain
``httpx.Client()`` raises ``InvalidURL`` inside ``supabase.create_client``
— killing every Supabase call (evidence ``/tmp/live-proof/evidence.md``
§0a). The two layers under test:

(a) ``create_supabase_client`` passes a prebuilt
    ``httpx.Client(trust_env=False)`` via ``SyncClientOptions`` — pinned
    here by asserting the built client's ``trust_env`` flag, so the fix
    holds even if the env is never sanitized.
(b) ``sanitize_no_proxy_env`` strips bracketed entries from
    ``NO_PROXY``/``no_proxy`` at launch, leaving everything else alone.

Env poisoning uses ``monkeypatch.setenv`` (function-scoped: the real
process env is restored after each test — nothing here mutates it
outside a test). The real-``create_client`` tests below point at the
unroutable ``example.supabase.co`` on purpose: supabase-py swallows the
failed session probe at construction, so they prove construction only
and never touch a live project.
"""

from __future__ import annotations

import os

import httpx
import pytest
from pydantic import SecretStr

from app.auth.provider import SupabaseAuthProvider
from app.core.config import Settings
from app.core.http import (
    _proxy_from_env,
    create_supabase_client,
    proxy_safe_httpx_client,
    proxy_safe_supabase_options,
    sanitize_no_proxy_env,
)
from app.db.supabase_store import SupabaseStore

POISONED_NO_PROXY = "localhost,127.0.0.1,::1,[::1],198.19.0.1,[fd8b:4f84:7d32:99::1]"


def _configured_settings() -> Settings:
    return Settings(
        supabase_url="https://example.supabase.co",
        supabase_anon_key="anon-key",
        supabase_service_role_key=SecretStr("service-key"),
    )


def _poison_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_PROXY", POISONED_NO_PROXY)
    monkeypatch.setenv("no_proxy", POISONED_NO_PROXY)


def test_plain_httpx_client_raises_with_poisoned_no_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The poison is real: a stock httpx client cannot even be built."""
    _poison_env(monkeypatch)
    with pytest.raises(httpx.InvalidURL):
        httpx.Client()


def test_proxy_safe_httpx_client_constructs_with_poisoned_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Layer (a): the helper builds a client that ignores the proxy env."""
    _poison_env(monkeypatch)
    client = proxy_safe_httpx_client()
    try:
        assert getattr(client, "_trust_env", None) is False
    finally:
        client.close()


def test_proxy_from_http_proxy_only_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-L6: an http_proxy-only setup must still route through the proxy.

    Previously only https_proxy was read, so http_proxy-only went direct
    and failed on this VM. The client is built with trust_env=False, so
    the proxy it carries is exactly the one the helper re-applied.
    """
    monkeypatch.delenv("https_proxy", raising=False)
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("all_proxy", raising=False)
    monkeypatch.delenv("ALL_PROXY", raising=False)
    monkeypatch.setenv("http_proxy", "http://proxy.example:3128")
    assert _proxy_from_env() == "http://proxy.example:3128"
    # And the built client still constructs (trust_env=False, proxy
    # re-applied) — it must not silently go direct.
    client = proxy_safe_httpx_client()
    try:
        assert getattr(client, "_trust_env", None) is False
    finally:
        client.close()


def test_https_proxy_takes_precedence_over_http_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-L6: when both are set, https_proxy wins (httpx env parity)."""
    monkeypatch.setenv("https_proxy", "http://https-proxy.example:3128")
    monkeypatch.setenv("http_proxy", "http://http-proxy.example:3128")
    assert _proxy_from_env() == "http://https-proxy.example:3128"


def test_malformed_proxy_url_raises_value_error_at_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F-L6: a malformed proxy URL fails LOUDLY at client construction.

    ``http://[::1`` (unterminated bracket) previously surfaced as an
    httpx InvalidURL deep inside a request — or, worse, was silently
    ignored. Now it is a clear ValueError before any request is made.
    """
    monkeypatch.setenv("https_proxy", "http://[::1")
    monkeypatch.delenv("http_proxy", raising=False)
    with pytest.raises(ValueError, match="invalid proxy URL in https_proxy"):
        proxy_safe_httpx_client()


def test_proxy_url_without_scheme_raises_value_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-L6: a schemeless proxy value is malformed, not a direct route."""
    monkeypatch.setenv("https_proxy", "proxy.example:3128")
    monkeypatch.delenv("http_proxy", raising=False)
    with pytest.raises(ValueError, match="invalid proxy URL in https_proxy"):
        proxy_safe_httpx_client()


def test_proxy_safe_supabase_options_carry_trust_env_false_client() -> None:
    """Layer (a): the options hand supabase-py a trust_env=False client."""
    options = proxy_safe_supabase_options()
    http_client = options.httpx_client
    try:
        assert http_client is not None
        assert getattr(http_client, "_trust_env", None) is False
    finally:
        if http_client is not None:
            http_client.close()


def test_create_supabase_client_with_poisoned_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real ``create_client`` with poisoned env: no InvalidURL."""
    _poison_env(monkeypatch)
    client = create_supabase_client("https://example.supabase.co", "test-anon-key")
    assert client.supabase_url == "https://example.supabase.co"
    http_client = client.options.httpx_client
    assert http_client is not None
    assert getattr(http_client, "_trust_env", None) is False


def test_supabase_provider_constructs_client_with_poisoned_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Provider path (``provider.py``) constructs under poisoned env."""
    _poison_env(monkeypatch)
    provider = SupabaseAuthProvider(_configured_settings())
    assert provider._get_client() is not None


def test_supabase_store_constructs_client_with_poisoned_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Store path (``supabase_store.py``) constructs under poisoned env."""
    _poison_env(monkeypatch)
    store = SupabaseStore(_configured_settings())
    assert store._client is not None


def test_sanitize_no_proxy_env_strips_bracketed_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Layer (b): bracketed entries go, everything else stays."""
    monkeypatch.setenv("NO_PROXY", "localhost,[::1],example.com,[fd8b:4f84:7d32:99::1]")
    monkeypatch.setenv("no_proxy", "[::1]")
    monkeypatch.setenv("https_proxy", "http://proxy.example:3128")
    removed = sanitize_no_proxy_env()
    assert removed == {
        "NO_PROXY": ["[::1]", "[fd8b:4f84:7d32:99::1]"],
        "no_proxy": ["[::1]"],
    }
    assert os.environ["NO_PROXY"] == "localhost,example.com"
    assert os.environ["no_proxy"] == ""
    assert os.environ["https_proxy"] == "http://proxy.example:3128"
    # Idempotent: a second call removes nothing.
    assert sanitize_no_proxy_env() == {}


def test_sanitize_no_proxy_env_leaves_clean_env_untouched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Layer (b): a clean no_proxy (bare ::1 included) is not rewritten."""
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1,::1,example.com")
    monkeypatch.delenv("no_proxy", raising=False)
    assert sanitize_no_proxy_env() == {}
    assert os.environ["NO_PROXY"] == "localhost,127.0.0.1,::1,example.com"
