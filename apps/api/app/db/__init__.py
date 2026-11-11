"""Store selection: Supabase when configured, in-memory otherwise.

The selection is explicit and logged at startup (which store is active), so
a dev server silently running on the in-memory store is visible in the logs
instead of being a mystery when data "disappears" on restart.
"""

from __future__ import annotations

import logging

from app.core.config import settings
from app.db.memory import InMemoryStore
from app.db.store import Store

logger = logging.getLogger("websurfacehq.db")

_STORE: Store | None = None


def get_store() -> Store:
    """Return the active store (module-level singleton).

    SupabaseStore when ``settings.supabase_configured`` is True, else a
    single shared InMemoryStore. The choice is logged the first time it is
    made. Tests never call this — they inject a fresh InMemoryStore via the
    ``get_store_dep`` dependency override.
    """
    global _STORE
    if _STORE is not None:
        return _STORE
    if settings.supabase_configured:
        from app.db.supabase_store import SupabaseStore

        _STORE = SupabaseStore()
        logger.info("store selected: supabase")
    else:
        _STORE = InMemoryStore()
        logger.info("store selected: in-memory (Supabase not configured)")
    return _STORE


def reset_store_for_tests() -> None:
    """Drop the cached singleton. Test-only helper (lets a test process
    re-select the store after changing settings)."""
    global _STORE
    _STORE = None


__all__ = ["Store", "get_store", "reset_store_for_tests"]
