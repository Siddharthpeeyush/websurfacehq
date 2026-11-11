#!/usr/bin/env python3
"""Validate WebSurfaceHQ Supabase migrations 0001-0006 on a FRESH database.

Methodology (fixed 11 Nov 2026 — see "Why no pre-grant" below):
  1. Start an ephemeral local Postgres (pgserver) — a brand-new,
     empty cluster. Nothing is pre-granted.
  2. Create ONLY the stubs Supabase itself provides: the roles
     ``anon`` / ``authenticated`` / ``service_role``, the ``auth``
     schema with ``auth.users`` and ``auth.uid()`` (the stub reads
     the ``app.test_uid`` session setting, standing in for the JWT
     ``sub`` claim Supabase's real ``auth.uid()`` reads).
  3. Apply the migrations in order 0001 -> 0002 -> 0003 -> 0004
     -> 0005 -> 0006, then the seed, exactly as the parent applies them live
     via the dashboard SQL editor — with NO grant of any kind issued
     by this script before or between the migrations.
  4. Assert, per table and per role, with ``has_table_privilege``:
     grants are PRESENT where the design requires them (0005) AND
     the 0004 REVOKEs hold (no write privilege on the server-created
     and read-only tables). Then prove the same behaviourally: real
     INSERT/UPDATE/DELETE attempts as ``authenticated`` fail with
     42501 on the read-only tables and succeed on the user-writable
     ones, real SELECTs as ``authenticated`` return the owner's own
     seed rows, and the H4 triggers still fire. Then assert the 0006
     policy cleanup: the six server-created tables keep ONLY their
     SELECT policy (no write policy survives to re-open a forged
     write if a future grant ever forgot the REVOKE).
  5. Control run: ``--exclude 0005_grants.sql 0006_policy_cleanup.sql``
     applies 0001–0004 only (the pre-fix state) and must FAIL — the
     harness catches the missing-grant bug (and the surviving write
     policies) instead of passing vacuously.

Why no pre-grant (H4 lesson, round-3 review): the Week 1 validator
pre-granted full DML to ``authenticated`` before applying 0004, so
it proved the REVOKEs hold GIVEN grants — but it was blind to
MISSING grants. The live proof (11 Nov 2026) then failed exactly
there: 0001-0004 contain no GRANT at all, tables created in the SQL
editor as ``postgres`` get no default grants, and service_role,
anon and authenticated all got 42501 on every table. A validator
that CONSTRUCTS the expected privilege state cannot prove a GRANT
exists. This script therefore constructs NOTHING about privileges:
the only grants in the database are the ones the migrations
themselves issue. If a migration forgets a grant, a check here
fails. (The old 83-check run's RLS/trigger/index probes are kept
and extended; the count is higher now because every table x role x
privilege is asserted individually.)

What this does NOT prove: the live Supabase project, Auth users,
``supabase db push``, or the PostgREST/JWT path — those need the
real project (the parent's live re-run). It proves the SQL: the
migrations, applied in order to a fresh database, produce exactly
the privilege state the RLS design assumes.

Dependencies (scratch venv only — NOT added to the API):
  pip install pgserver "psycopg[binary]"
Usage:
  python supabase/validate_migrations.py [--exclude 0005_grants.sql 0006_policy_cleanup.sql]
Exit code 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import pathlib
import sys
import tempfile

import pgserver
import psycopg
from psycopg import errors as pg_errors
from psycopg import sql as psql

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
MIGRATIONS_DIR = REPO_ROOT / "supabase" / "migrations"
SEED_SQL = REPO_ROOT / "supabase" / "seed.sql"
MIGRATION_FILES = [
    "0001_core.sql",
    "0002_billing_teams.sql",
    "0003_part7.sql",
    "0004_review_fixes.sql",
    "0005_grants.sql",
    "0006_policy_cleanup.sql",
]

# Tables whose write RLS policies 0006 drops (server-created rows).
# audit_logs has only an INSERT policy to drop — no UPDATE/DELETE
# policies ever existed there (append-only by design).
POLICY_CLEANUP_TABLES = ["scans", "findings", "scan_jobs", "assets", "audit_logs", "attack_paths"]
POLICY_CLEANUP_DROPS = {
    "scans": ["scans_insert_own", "scans_update_own", "scans_delete_own"],
    "findings": ["findings_insert_own", "findings_update_own", "findings_delete_own"],
    "scan_jobs": ["scan_jobs_insert_own", "scan_jobs_update_own", "scan_jobs_delete_own"],
    "assets": ["assets_insert_own", "assets_update_own", "assets_delete_own"],
    "audit_logs": ["audit_logs_insert_own"],
    "attack_paths": [
        "attack_paths_insert_own",
        "attack_paths_update_own",
        "attack_paths_delete_own",
    ],
}

TABLES = [
    "targets",
    "scans",
    "assets",
    "findings",
    "scan_jobs",
    "audit_logs",
    "subscriptions",
    "teams",
    "team_members",
    "api_keys",
    "notifications",
    "support_tickets",
    "attack_paths",
]

# Tables an authenticated user may write (their RLS policies allow
# user INSERT/UPDATE/DELETE). Every other table is SELECT-only for
# authenticated per 0004: server-created rows (scans, findings,
# scan_jobs, assets, audit_logs, attack_paths) and user-read-only
# billing tables (subscriptions, api_keys).
USER_WRITABLE = {"targets", "teams", "team_members", "notifications", "support_tickets"}
READ_ONLY_FOR_USERS = [t for t in TABLES if t not in USER_WRITABLE]
PRIVILEGES = ["SELECT", "INSERT", "UPDATE", "DELETE"]

# Seed tenants (seed.sql) + scratch tenants created by this script.
USER_A = "11111111-1111-4111-8111-111111111111"
USER_B = "22222222-2222-4222-8222-222222222222"
USER_C = "33333333-3333-4333-8333-333333333333"  # scratch tenant, no seed rows
USER_D = "44444444-4444-4444-8444-444444444444"  # scratch tenant, no seed rows

SEED_COUNTS = {
    "targets": 2,
    "scans": 2,
    "assets": 4,
    "findings": 4,
    "scan_jobs": 2,
    "audit_logs": 2,
    "subscriptions": 2,
    "teams": 1,
    "team_members": 1,
    "api_keys": 2,
    "notifications": 2,
    "support_tickets": 2,
    "attack_paths": 2,
}


class Results:
    """Collects named checks; prints a summary; exits non-zero on failure."""

    def __init__(self) -> None:
        self.passed: list[str] = []
        self.failed: list[tuple[str, str]] = []

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        if ok:
            self.passed.append(name)
        else:
            self.failed.append((name, detail))
            print(f"  FAIL: {name} — {detail}")

    def summary(self) -> int:
        total = len(self.passed) + len(self.failed)
        print(f"\n{len(self.passed)}/{total} checks passed, {len(self.failed)} failed.")
        if self.failed:
            print("Failed checks:")
            for name, detail in self.failed:
                print(f"  - {name}: {detail}")
            return 1
        return 0


def exec_script(conn: psycopg.Connection, path: pathlib.Path) -> None:
    """Run a whole .sql file (may contain its own BEGIN/COMMIT)."""
    conn.execute(path.read_text(encoding="utf-8"))


def probe(uri: str, role: str, uid: str | None, query: str, params: tuple = ()):
    """Run one statement as ``role`` (with ``auth.uid()`` = ``uid``).

    Returns ("ok", rows, rowcount) or ("err", exception).
    A fresh connection per probe: role + uid are session state.
    """
    try:
        with psycopg.connect(uri, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute(psql.SQL("SET ROLE {}").format(psql.Identifier(role)))
            if uid is not None:
                cur.execute("SELECT set_config('app.test_uid', %s, false)", (uid,))
            cur.execute(query, params)
            rows = cur.fetchall() if cur.description is not None else []
            return ("ok", rows, cur.rowcount)
    except Exception as exc:  # noqa: BLE001 — probe outcome is the point
        return ("err", exc, -1)


def main() -> int:
    # Control-run support: --exclude <files...> drops migrations from
    # the apply list (e.g. --exclude 0005_grants.sql
    # 0006_policy_cleanup.sql reproduces the pre-fix state — the run
    # must then FAIL, proving the harness catches the missing grants
    # and the surviving write policies).
    excluded: set[str] = set()
    argv = sys.argv[1:]
    if "--exclude" in argv:
        idx = argv.index("--exclude")
        excluded = set(argv[idx + 1 :])
        for name in sorted(excluded):
            if name not in MIGRATION_FILES:
                print(f"unknown migration in --exclude: {name}")
                return 2
    apply_files = [name for name in MIGRATION_FILES if name not in excluded]
    if excluded:
        print(f"CONTROL RUN: excluding {sorted(excluded)}; applying {apply_files}")
    results = Results()
    pgdata = tempfile.mkdtemp(prefix="wshq-validate-")
    server = pgserver.get_server(pgdata)
    try:
        uri = server.get_uri()
        with psycopg.connect(uri, autocommit=True) as conn:
            # --- Stubs for what Supabase itself provides. NOT grants:
            # roles exist in every Supabase project; auth.users /
            # auth.uid() are the Auth schema. No privilege is granted
            # here — the ONLY grants in this database will be the ones
            # the migrations issue (that is the whole point).
            conn.execute("CREATE ROLE anon NOLOGIN")
            conn.execute("CREATE ROLE authenticated NOLOGIN")
            # BYPASSRLS is what real Supabase gives service_role: the
            # API's store must bypass RLS (its requests carry no user
            # JWT, so auth.uid() is NULL and no owner policy could ever
            # match). Without it this stub would wrongly fail every
            # service_role write at the policy layer.
            conn.execute("CREATE ROLE service_role NOLOGIN BYPASSRLS")
            conn.execute("CREATE SCHEMA IF NOT EXISTS auth")
            conn.execute("CREATE TABLE auth.users (id uuid PRIMARY KEY)")
            conn.execute(
                """
                CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid
                LANGUAGE sql STABLE AS $$
                  SELECT NULLIF(current_setting('app.test_uid', true), '')::uuid;
                $$;
                """
            )
            for uid in (USER_A, USER_B, USER_C, USER_D):
                conn.execute("INSERT INTO auth.users (id) VALUES (%s)", (uid,))
            # --- Migrations, in order, no pre-grant. Then the seed.
            for name in apply_files:
                exec_script(conn, MIGRATIONS_DIR / name)
            exec_script(conn, SEED_SQL)

            # --- G1: schema shape (superuser reads).
            with conn.cursor() as cur:
                for table in TABLES:
                    cur.execute(
                        "SELECT relrowsecurity FROM pg_class "
                        "WHERE relname = %s AND relnamespace = 'public'::regnamespace",
                        (table,),
                    )
                    row = cur.fetchone()
                    results.check(f"table {table} exists", row is not None)
                    results.check(
                        f"RLS enabled on {table}",
                        row is not None and bool(row[0]),
                        "relrowsecurity is false",
                    )
                cur.execute(
                    "SELECT 1 FROM information_schema.columns WHERE "
                    "table_schema = 'public' AND table_name = 'scan_jobs' "
                    "AND column_name = 'idempotency_key'"
                )
                results.check(
                    "scan_jobs.idempotency_key column exists",
                    cur.fetchone() is not None,
                )
                for index in (
                    "targets_one_live_per_user",
                    "scans_one_active_per_user_key",
                ):
                    cur.execute(
                        "SELECT 1 FROM pg_indexes WHERE schemaname = 'public' AND indexname = %s",
                        (index,),
                    )
                    results.check(f"index {index} exists", cur.fetchone() is not None)

            # --- G2: seed row counts (before any mutation).
            with conn.cursor() as cur:
                for table, expected in SEED_COUNTS.items():
                    cur.execute(
                        psql.SQL("SELECT count(*) FROM public.{}").format(
                            psql.Identifier(table)
                        )
                    )
                    got = cur.fetchone()[0]
                    results.check(
                        f"seed count {table} == {expected}",
                        got == expected,
                        f"got {got}",
                    )

            # --- G3: schema USAGE is a Postgres/PUBLIC default — no
            # migration grants it, and none may need to. If any of
            # these fails, 0005 must gain a USAGE grant (see its header).
            with conn.cursor() as cur:
                for role in ("anon", "authenticated", "service_role"):
                    cur.execute(
                        "SELECT has_schema_privilege(%s, 'public', 'USAGE')", (role,)
                    )
                    results.check(
                        f"schema USAGE on public for {role} (default, no grant in migrations)",
                        bool(cur.fetchone()[0]),
                        "USAGE missing — 0005 needs an explicit GRANT USAGE",
                    )

            # --- G4/G5/G6: has_table_privilege, every table x role x
            # privilege. This is the grant-presence proof the old
            # validator could not give (it pre-granted the state).
            with conn.cursor() as cur:
                for table in TABLES:
                    for priv in PRIVILEGES:
                        cur.execute(
                            "SELECT has_table_privilege('service_role', %s, %s)",
                            (f"public.{table}", priv),
                        )
                        results.check(
                            f"service_role has {priv} on {table}",
                            bool(cur.fetchone()[0]),
                            "0005 must grant full DML to service_role",
                        )
                for table in TABLES:
                    for priv in PRIVILEGES:
                        cur.execute(
                            "SELECT has_table_privilege('authenticated', %s, %s)",
                            (f"public.{table}", priv),
                        )
                        want = bool(table in USER_WRITABLE or priv == "SELECT")
                        results.check(
                            f"authenticated {priv} on {table} == {want}",
                            bool(cur.fetchone()[0]) == want,
                            "grant state contradicts 0004/0005 design",
                        )
                for table in TABLES:
                    for priv in PRIVILEGES:
                        cur.execute(
                            "SELECT has_table_privilege('anon', %s, %s)",
                            (f"public.{table}", priv),
                        )
                        results.check(
                            f"anon has no {priv} on {table}",
                            not bool(cur.fetchone()[0]),
                            "anon must hold nothing on app tables",
                        )

        # --- G7: authenticated SELECTs return the owner's own seed rows.
        seed_id = {
            "targets": "a0000000-0000-4000-8000-000000000001",
            "scans": "a0000000-0000-4000-8000-000000000002",
            "assets": "a0000000-0000-4000-8000-000000000003",
            "findings": "a0000000-0000-4000-8000-000000000005",
            "scan_jobs": "a0000000-0000-4000-8000-000000000007",
            "audit_logs": "a0000000-0000-4000-8000-000000000008",
            "subscriptions": "a0000000-0000-4000-8000-000000000009",
            "teams": "a0000000-0000-4000-8000-00000000000e",
            "team_members": "a0000000-0000-4000-8000-00000000000f",
            "api_keys": "a0000000-0000-4000-8000-00000000000b",
            "notifications": "a0000000-0000-4000-8000-00000000000a",
            "support_tickets": "a0000000-0000-4000-8000-00000000000c",
            "attack_paths": "a0000000-0000-4000-8000-00000000000d",
        }
        for table, row_id in seed_id.items():
            status, rows, _ = probe(
                uri,
                "authenticated",
                USER_A,
                f"SELECT id FROM public.{table} WHERE id = %s",
                (row_id,),
            )
            results.check(
                f"authenticated SELECTs own {table} seed row",
                status == "ok" and len(rows) == 1,
                f"status={status} rows={rows}",
            )

        # --- G8: authenticated writes FAIL (42501) on the 8 read-only
        # tables — the 0004 REVOKEs, re-asserted in 0005, hold GIVEN
        # the 0005 grants. A missing GRANT would also fail here, so
        # G5 (SELECT present, writes absent) is what distinguishes
        # "revoked" from "never granted".
        write_sql = {
            "INSERT": "INSERT INTO public.{t} (id) VALUES ('00000000-0000-4000-8000-000000000000')",
            "UPDATE": "UPDATE public.{t} SET id = id WHERE id = '00000000-0000-4000-8000-000000000000'",
            "DELETE": "DELETE FROM public.{t} WHERE id = '00000000-0000-4000-8000-000000000000'",
        }
        for table in READ_ONLY_FOR_USERS:
            for verb, template in write_sql.items():
                status, exc, _ = probe(
                    uri, "authenticated", USER_A, template.format(t=table)
                )
                results.check(
                    f"authenticated {verb} on {table} denied (42501)",
                    status == "err"
                    and isinstance(exc, pg_errors.InsufficientPrivilege),
                    f"status={status} exc={exc!r}",
                )

        # --- G9: authenticated writes SUCCEED on the user-writable
        # tables (scratch tenant C — no seed rows, so no cap/index
        # collisions). Proves the grants are not just present but
        # usable through RLS.
        status, rows, _ = probe(
            uri,
            "authenticated",
            USER_C,
            "INSERT INTO public.targets (user_id, domain) VALUES (%s, 'c.example.com') RETURNING id",
            (USER_C,),
        )
        c_target = rows[0][0] if status == "ok" and rows else None
        results.check(
            "authenticated INSERTs own target",
            status == "ok" and c_target is not None,
            f"{status} {rows}",
        )
        status, rows, _ = probe(
            uri,
            "authenticated",
            USER_C,
            "UPDATE public.targets SET domain = 'c2.example.com' WHERE id = %s RETURNING domain",
            (str(c_target),),
        )
        results.check(
            "authenticated UPDATEs own pending target (non-verification field)",
            status == "ok" and rows and rows[0][0] == "c2.example.com",
            f"{status} {rows}",
        )
        for table, query, params in [
            (
                "notifications",
                "INSERT INTO public.notifications (user_id, type) VALUES (%s, 'diff') RETURNING id",
                (USER_C,),
            ),
            (
                "support_tickets",
                "INSERT INTO public.support_tickets (user_id, subject) VALUES (%s, 'validator probe') RETURNING id",
                (USER_C,),
            ),
            (
                "teams",
                "INSERT INTO public.teams (name, owner_id) VALUES ('Validator team', %s) RETURNING id",
                (USER_C,),
            ),
        ]:
            status, rows, _ = probe(uri, "authenticated", USER_C, query, params)
            results.check(
                f"authenticated INSERTs own {table} row",
                status == "ok" and len(rows) == 1,
                f"{status} {rows}",
            )
            if table == "teams":
                c_team = rows[0][0] if status == "ok" and rows else None
        status, rows, _ = probe(
            uri,
            "authenticated",
            USER_C,
            "INSERT INTO public.team_members (team_id, user_id, role) VALUES (%s, %s, 'owner') RETURNING id",
            (str(c_team), USER_C),
        )
        results.check(
            "authenticated INSERTs team_member on own team",
            status == "ok" and len(rows) == 1,
            f"{status} {rows}",
        )
        status, rows, rc = probe(
            uri,
            "authenticated",
            USER_C,
            "DELETE FROM public.targets WHERE id = %s",
            (str(c_target),),
        )
        results.check(
            "authenticated DELETEs own target",
            status == "ok" and rc == 1,
            f"{status} rowcount={rc}",
        )

        # --- G10: service_role full DML works (scratch tenant D).
        status, rows, _ = probe(
            uri,
            "service_role",
            None,
            "INSERT INTO public.targets (user_id, domain, verification_status) VALUES (%s, 'd.example.com', 'verified') RETURNING id",
            (USER_D,),
        )
        d_target = rows[0][0] if status == "ok" and rows else None
        results.check(
            "service_role INSERTs target",
            status == "ok" and d_target is not None,
            f"{status} {rows}",
        )
        status, rows, _ = probe(
            uri,
            "service_role",
            None,
            "INSERT INTO public.scans (target_id, user_id, status) VALUES (%s, %s, 'queued') RETURNING id",
            (str(d_target), USER_D),
        )
        d_scan = rows[0][0] if status == "ok" and rows else None
        results.check(
            "service_role INSERTs scan",
            status == "ok" and d_scan is not None,
            f"{status} {rows}",
        )
        status, rows, _ = probe(
            uri,
            "service_role",
            None,
            "SELECT id FROM public.scans WHERE id = %s",
            (str(d_scan),),
        )
        results.check(
            "service_role SELECTs scan",
            status == "ok" and len(rows) == 1,
            f"{status} {rows}",
        )
        status, rows, rc = probe(
            uri,
            "service_role",
            None,
            "UPDATE public.scans SET status = 'done' WHERE id = %s",
            (str(d_scan),),
        )
        results.check(
            "service_role UPDATEs scan",
            status == "ok" and rc == 1,
            f"{status} rowcount={rc}",
        )
        status, _, rc = probe(
            uri,
            "service_role",
            None,
            "DELETE FROM public.scans WHERE id = %s",
            (str(d_scan),),
        )
        results.check(
            "service_role DELETEs scan",
            status == "ok" and rc == 1,
            f"{status} rowcount={rc}",
        )
        status, _, rc = probe(
            uri,
            "service_role",
            None,
            "DELETE FROM public.targets WHERE id = %s",
            (str(d_target),),
        )
        results.check(
            "service_role DELETEs target",
            status == "ok" and rc == 1,
            f"{status} rowcount={rc}",
        )

        # --- G11: H4 triggers still fire for authenticated (they are
        # the enforcement for verification fields — grants cannot do
        # this; a column REVOKE is a no-op against a table UPDATE
        # grant). Forged-INSERT check runs BEFORE C owns a live target
        # so the one-live-target index cannot mask the trigger.
        status, exc, _ = probe(
            uri,
            "authenticated",
            USER_C,
            "INSERT INTO public.targets (user_id, domain, verification_status, verified_at) "
            "VALUES (%s, 'forged.example.com', 'verified', now())",
            (USER_C,),
        )
        results.check(
            "authenticated INSERT of pre-verified target blocked by trigger",
            status == "err" and isinstance(exc, pg_errors.RaiseException),
            f"status={status} exc={exc!r}",
        )
        status, rows, _ = probe(
            uri,
            "authenticated",
            USER_C,
            "INSERT INTO public.targets (user_id, domain) VALUES (%s, 'c3.example.com') RETURNING id",
            (USER_C,),
        )
        c_target2 = rows[0][0] if status == "ok" and rows else None
        results.check(
            "authenticated INSERTs second scratch target",
            status == "ok" and c_target2 is not None,
            f"{status} {rows}",
        )
        status, exc, _ = probe(
            uri,
            "authenticated",
            USER_C,
            "UPDATE public.targets SET verification_status = 'verified' WHERE id = %s",
            (str(c_target2),),
        )
        results.check(
            "authenticated UPDATE of verification_status blocked by trigger",
            status == "err" and isinstance(exc, pg_errors.RaiseException),
            f"status={status} exc={exc!r}",
        )
        # Verified-target retarget: D's target is inserted verified by
        # service_role (exempt), then D tries to retarget it.
        status, rows, _ = probe(
            uri,
            "service_role",
            None,
            "INSERT INTO public.targets (user_id, domain, verification_status) VALUES (%s, 'd2.example.com', 'verified') RETURNING id",
            (USER_D,),
        )
        d_target2 = rows[0][0] if status == "ok" and rows else None
        status, exc, _ = probe(
            uri,
            "authenticated",
            USER_D,
            "UPDATE public.targets SET domain = 'victim.example.com' WHERE id = %s",
            (str(d_target2),),
        )
        results.check(
            "authenticated retarget of verified target blocked by trigger",
            status == "err" and isinstance(exc, pg_errors.RaiseException),
            f"status={status} exc={exc!r}",
        )
        status, _, _ = probe(
            uri,
            "service_role",
            None,
            "DELETE FROM public.targets WHERE id = %s",
            (str(d_target2),),
        )

        # --- G12: cross-tenant isolation (RLS, not grants).
        status, rows, _ = probe(
            uri,
            "authenticated",
            USER_B,
            "SELECT id FROM public.targets WHERE id = 'a0000000-0000-4000-8000-000000000001'",
        )
        results.check(
            "tenant B cannot SELECT tenant A target",
            status == "ok" and len(rows) == 0,
            f"{status} {rows}",
        )
        status, _, rc = probe(
            uri,
            "authenticated",
            USER_B,
            "UPDATE public.targets SET domain = 'hijack.example.com' WHERE id = 'a0000000-0000-4000-8000-000000000001'",
        )
        results.check(
            "tenant B UPDATE of A target affects 0 rows",
            status == "ok" and rc == 0,
            f"{status} rowcount={rc}",
        )
        status, rows, _ = probe(
            uri,
            "authenticated",
            USER_B,
            "SELECT id FROM public.scans WHERE id = 'a0000000-0000-4000-8000-000000000002'",
        )
        results.check(
            "tenant B cannot SELECT tenant A scan",
            status == "ok" and len(rows) == 0,
            f"{status} {rows}",
        )

        # --- G13: soft-delete helpers (C's pending target from G11).
        status, rows, _ = probe(
            uri,
            "authenticated",
            USER_C,
            "SELECT public.soft_delete_target(%s)",
            (str(c_target2),),
        )
        results.check(
            "soft_delete_target returns true for own target",
            status == "ok" and rows and rows[0][0] is True,
            f"{status} {rows}",
        )
        status, rows, _ = probe(
            uri,
            "authenticated",
            USER_C,
            "SELECT id FROM public.targets WHERE id = %s",
            (str(c_target2),),
        )
        results.check(
            "soft-deleted target hidden from SELECT",
            status == "ok" and len(rows) == 0,
            f"{status} {rows}",
        )
        status, rows, _ = probe(
            uri,
            "authenticated",
            USER_C,
            "SELECT public.restore_target(%s)",
            (str(c_target2),),
        )
        results.check(
            "restore_target returns true for own target",
            status == "ok" and rows and rows[0][0] is True,
            f"{status} {rows}",
        )
        status, rows, _ = probe(
            uri,
            "authenticated",
            USER_C,
            "SELECT id FROM public.targets WHERE id = %s",
            (str(c_target2),),
        )
        results.check(
            "restored target visible again",
            status == "ok" and len(rows) == 1,
            f"{status} {rows}",
        )
        status, _, _ = probe(
            uri,
            "service_role",
            None,
            "DELETE FROM public.targets WHERE id = %s",
            (str(c_target2),),
        )

        # --- G14: partial unique indexes (M3/M4).
        status, exc, _ = probe(
            uri,
            "service_role",
            None,
            "INSERT INTO public.targets (user_id, domain) VALUES (%s, 'second-a.example.com')",
            (USER_A,),
        )
        results.check(
            "second live target for A violates targets_one_live_per_user",
            status == "err"
            and isinstance(exc, pg_errors.UniqueViolation)
            and "targets_one_live_per_user" in str(exc),
            f"status={status} exc={exc!r}",
        )
        status, rows, _ = probe(
            uri,
            "service_role",
            None,
            "INSERT INTO public.scans (target_id, user_id, status) VALUES ('a0000000-0000-4000-8000-000000000001', %s, 'queued') RETURNING id",
            (USER_A,),
        )
        a_active_scan = rows[0][0] if status == "ok" and rows else None
        results.check(
            "first active scan for A inserts",
            status == "ok" and a_active_scan is not None,
            f"{status} {rows}",
        )
        status, exc, _ = probe(
            uri,
            "service_role",
            None,
            "INSERT INTO public.scans (target_id, user_id, status) VALUES ('a0000000-0000-4000-8000-000000000001', %s, 'recon')",
            (USER_A,),
        )
        results.check(
            "second active scan for A violates scans_one_active_per_user_key",
            status == "err"
            and isinstance(exc, pg_errors.UniqueViolation)
            and "scans_one_active_per_user_key" in str(exc),
            f"status={status} exc={exc!r}",
        )
        status, _, _ = probe(
            uri,
            "service_role",
            None,
            "DELETE FROM public.scans WHERE id = %s",
            (str(a_active_scan),),
        )

        # --- G15: 0005 grants anon nothing, in the file itself.
        # (Check code lines only — the header comment mentions anon
        # in prose and in a commented-out USAGE example.)
        text0005 = (MIGRATIONS_DIR / "0005_grants.sql").read_text(encoding="utf-8")
        code0005 = "\n".join(
            line for line in text0005.splitlines() if not line.strip().startswith("--")
        )
        results.check("0005 grants nothing TO anon", "TO anon" not in code0005)
        results.check(
            "0005 re-asserts all eight 0004 REVOKEs",
            text0005.count("REVOKE INSERT, UPDATE, DELETE") == 8
            and all(
                f"ON public.{t} FROM authenticated" in text0005
                for t in READ_ONLY_FOR_USERS
            ),
            f"REVOKE count = {text0005.count('REVOKE INSERT, UPDATE, DELETE')}",
        )

        # --- G16: 0006 policy cleanup (F-L1). The six server-created
        # tables keep ONLY their SELECT policy; no INSERT/UPDATE/DELETE
        # policy survives on them (or on subscriptions/api_keys, whose
        # write policies 0004 already dropped). The write policies are
        # gone from the catalog, not just unenforced — a future broad
        # re-grant alone can no longer re-open a forged write, because
        # RLS with no policy for a command denies it by default.
        # (The superuser connection from G1–G6 is closed by now — G7+
        # use probe() — so open a fresh one for the catalog query.)
        with psycopg.connect(uri, autocommit=True) as conn2, conn2.cursor() as cur:
            for table in POLICY_CLEANUP_TABLES + ["subscriptions", "api_keys"]:
                cur.execute(
                    "SELECT policyname, cmd FROM pg_policies "
                    "WHERE schemaname = 'public' AND tablename = %s ORDER BY policyname",
                    (table,),
                )
                policies = cur.fetchall()
                results.check(
                    f"0006: only SELECT policy remains on {table}",
                    len(policies) == 1
                    and policies[0][0] == f"{table}_select_own"
                    and policies[0][1] == "SELECT",
                    f"policies={policies}",
                )
        text0006 = (MIGRATIONS_DIR / "0006_policy_cleanup.sql").read_text(encoding="utf-8")
        drop_lines = [
            line
            for line in text0006.splitlines()
            if line.strip().startswith("DROP POLICY IF EXISTS")
        ]
        results.check(
            "0006 drops exactly the 16 write policies (3x5 + audit_logs INSERT)",
            len(drop_lines) == 16,
            f"DROP POLICY count = {len(drop_lines)}",
        )
        results.check(
            "0006 drops every expected write policy name",
            all(
                f"DROP POLICY IF EXISTS {name} ON public.{table};" in text0006
                for table, names in POLICY_CLEANUP_DROPS.items()
                for name in names
            ),
        )
        results.check(
            "0006 drops no SELECT policy",
            not any("_select_own" in line for line in drop_lines),
        )
        return results.summary()
    finally:
        server.cleanup()


if __name__ == "__main__":
    sys.exit(main())
