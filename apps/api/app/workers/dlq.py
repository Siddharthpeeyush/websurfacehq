"""Dead-letter queue (DLQ) helpers.

After a task exhausts its retries (blueprint §1.5: max 3, then DLQ), the
base task sends one entry to ``dlq:scan:{scan_id}`` in Redis and marks the
scan ``failed``. Entries are JSON so ops can read them with ``read_dlq``
without knowing the payload shape of any particular stage.

Fail-safe rule: a DLQ write must NEVER raise. If Redis is unreachable the
failure is logged loudly (this is an ops-visible error — a scan died AND
its DLQ entry is missing) and the caller keeps the scan marked failed.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, cast

from app.workers.redis_client import get_redis_client

logger = logging.getLogger(__name__)

# Dead-letter entries are ops evidence, not an archive: cap each scan's
# list so a failing stage cannot grow a Redis key without bound (L6).
DLQ_MAX_ENTRIES = 1000


def dlq_key(scan_id: str) -> str:
    """Redis key holding the dead-letter entries for one scan."""
    return f"dlq:scan:{scan_id}"


def send_to_dlq(
    scan_id: str,
    stage: str,
    payload: dict[str, Any],
    error: object,
) -> bool:
    """Append one dead-letter entry for a failed stage.

    Returns ``True`` when the entry was written, ``False`` when Redis was
    unreachable (logged loudly; never raises).
    """
    entry: dict[str, Any] = {
        "scan_id": scan_id,
        "stage": stage,
        "payload": payload,
        "error": str(error),
        "failed_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        client = get_redis_client()
        pipe = client.pipeline()
        pipe.rpush(dlq_key(scan_id), json.dumps(entry))
        # Trim to the newest DLQ_MAX_ENTRIES (L6 review fix): a stage
        # failing in a loop must not grow the key without bound.
        pipe.ltrim(dlq_key(scan_id), -DLQ_MAX_ENTRIES, -1)
        pipe.execute()  # type: ignore[no-untyped-call]
    except Exception:
        logger.exception(
            "DLQ write failed for scan %s stage %s; "
            "dead-letter entry lost (scan stays marked failed)",
            scan_id,
            stage,
        )
        return False
    return True


def read_dlq(scan_id: str) -> list[dict[str, Any]]:
    """Read all dead-letter entries for a scan (debugging / ops).

    Returns an empty list when Redis is unreachable or the scan has no
    entries. A non-JSON entry is returned as ``{"raw": <value>}`` instead
    of raising, so one corrupt entry cannot hide the rest.
    """
    try:
        client = get_redis_client()
        # redis-py types lrange as sync-or-async; this client is sync.
        raw_entries = cast("list[Any]", client.lrange(dlq_key(scan_id), 0, -1))
    except Exception:
        logger.exception("DLQ read failed for scan %s", scan_id)
        return []
    entries: list[dict[str, Any]] = []
    for raw in raw_entries:
        try:
            parsed = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            entries.append({"raw": raw})
            continue
        if isinstance(parsed, dict):
            entries.append(parsed)
        else:
            entries.append({"raw": raw})
    return entries
