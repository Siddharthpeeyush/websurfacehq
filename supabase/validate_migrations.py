#!/usr/bin/env python3
"""Validate WebSurfaceHQ Supabase migrations 0001-0007 on a FRESH database.

Methodology (fixed 11 Nov 2026 — see "Why no pre-grant" below):
  1. Start an ephemeral local Postgres (pgserver) — a brand-new,
     empty cluster. Nothing is pre-granted.
  2. Create ONLY the stubs Supabase itself provides: the roles
     ``anon`` / ``authenticated`` / ``service_role``, the ``auth``
     schema with ``auth.users`` and ``auth.uid()`` (the stub reads
     the ``app.test_uid`` session setting, standing in for the JWT
     ``sub`` claim Supabase's real ``auth.uid()`` reads).
  3. Apply the migrations in order 0001 -> 0002 -> 0003 -> 0004
     -> 0005 -> 0006 -> 0007, then the seed, exactly as the parent applies them live
     via the dashboard SQL editor — with NO grant of any kind issued
     by this script before or between the migrations.
  4. Assert, per table and per role, with ``has_table_privilege``:
     grants are PRESENT where the design requires them (0005, 0007)
     AND the 0004 REVOKEs hold (no write privilege on the server-created
     and read-only tables) AND the 0007 audit REVOKEs hold (no UPDATE /
     DELETE on audit_logs for ANY role, service_role included) AND the
     staff tables grant nothing to authenticated/anon. Then prove the
     same behaviourally: real INSERT/UPDATE/DELETE attempts as
     ``authenticated`` fail with 42501 on the read-only tables and on
     the staff tables, real SELECTs as ``authenticated`` return the
     owner's own seed rows, the H4 triggers still fire, the single-Owner
     trigger fires, the audit UPDATE/DELETE trigger fires, and the
     invite atomic claim works. Then assert the 0006 policy cleanup:
     the six server-created tables keep ONLY their SELECT policy (no
     write policy survives to re-open a forged write if a future grant
     ever forgot the REVOKE), and the staff tables keep NO policy at
     all (service_role only, by RLS default-deny).
  5. Control run: ``--exclude 0005_grants.sql 0006_policy_cleanup.sql``
     applies 0001–0004 only (the pre-fix state) and must FAIL — the
     harness catches the missing-grant bug (and the surviving write
     policies) instead of passing vacuously. ``--exclude
     0007_admin_foundation.sql`` likewise must FAIL (no staff tables,
     no audit trigger, service_role still holds UPDATE/DELETE on
     audit_logs).

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

import hashlib
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
    "0007_admin_foundation.sql",
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
    "staff_roles",
    "staff_invites",
    "staff_sessions",
    "admin_settings",
]

# Staff tables (0007): service_role only. authenticated and anon hold
# NOTHING on them — not even SELECT — and RLS carries no policy for
# them at all (default-deny), so the staff role is never readable
# from the client. They are not in USER_WRITABLE / READ_ONLY_FOR_USERS
# (those describe the authenticated SELECT-or-write split); they are a
# third class, asserted separately in G4/G5/G8/G17.
STAFF_TABLES = ["staff_roles", "staff_invites", "staff_sessions", "admin_settings"]

# Tables an authenticated user may write (their RLS policies allow
# user INSERT/UPDATE/DELETE). Every other table is SELECT-only for
# authenticated per 0004: server-created rows (scans, findings,
# scan_jobs, assets, audit_logs, attack_paths) and user-read-only
# billing tables (subscriptions, api_keys). Staff tables (0007) are
# NOT in this list either — they are a third class (no privilege at
# all, not even SELECT); see STAFF_TABLES.
USER_WRITABLE = {"targets", "teams", "team_members", "notifications", "support_tickets"}
READ_ONLY_FOR_USERS = [
    t for t in TABLES if t not in USER_WRITABLE and t not in STAFF_TABLES
]
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
                        # A missing table (control run without 0007)
                        # raises UndefinedTable from has_table_privilege
                        # — that is a FAILED check, not a harness crash:
                        # the control run must end with a summary and a
                        # non-zero exit, not a traceback.
                        try:
                            cur.execute(
                                "SELECT has_table_privilege('service_role', %s, %s)",
                                (f"public.{table}", priv),
                            )
                            got = bool(cur.fetchone()[0])
                        except Exception as exc:  # noqa: BLE001 - missing table is a failed check
                            results.check(
                                f"service_role has {priv} on {table}",
                                False,
                                f"privilege query failed: {exc!r}",
                            )
                            continue
                        # 0007 revokes UPDATE/DELETE on audit_logs from
                        # service_role too (append-only: the API only
                        # INSERTs audit rows) — every other table keeps
                        # full DML for service_role.
                        want = not (
                            table == "audit_logs" and priv in ("UPDATE", "DELETE")
                        )
                        results.check(
                            f"service_role has {priv} on {table} == {want}",
                            got == want,
                            "0005/0007 grant state contradicts the design",
                        )
                for table in TABLES:
                    for priv in PRIVILEGES:
                        try:
                            cur.execute(
                                "SELECT has_table_privilege('authenticated', %s, %s)",
                                (f"public.{table}", priv),
                            )
                            got = bool(cur.fetchone()[0])
                        except Exception as exc:  # noqa: BLE001 - missing table is a failed check
                            results.check(
                                f"authenticated {priv} on {table}",
                                False,
                                f"privilege query failed: {exc!r}",
                            )
                            continue
                        # Staff tables (0007): authenticated holds
                        # NOTHING, not even SELECT. Every other table
                        # keeps the 0004/0005 split (full DML on the
                        # five user-writable tables, SELECT-only on
                        # the rest).
                        want = bool(
                            table in USER_WRITABLE
                            or (priv == "SELECT" and table not in STAFF_TABLES)
                        )
                        results.check(
                            f"authenticated {priv} on {table} == {want}",
                            got == want,
                            "grant state contradicts 0004/0005 design",
                        )
                for table in TABLES:
                    for priv in PRIVILEGES:
                        try:
                            cur.execute(
                                "SELECT has_table_privilege('anon', %s, %s)",
                                (f"public.{table}", priv),
                            )
                            got = bool(cur.fetchone()[0])
                        except Exception as exc:  # noqa: BLE001 - missing table is a failed check
                            results.check(
                                f"anon has no {priv} on {table}",
                                False,
                                f"privilege query failed: {exc!r}",
                            )
                            continue
                        results.check(
                            f"anon has no {priv} on {table}",
                            not got,
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

        # Staff tables need their own write SQL: the generic templates
        # above reference an `id` column, which staff_roles has no
        # (its PK is user_id) — column resolution would fail with
        # 42703 before the privilege check, so the probe would not
        # prove the denial. These use real columns, so a 42501 here
        # proves the missing grant.
        staff_write_probes = [
            (
                "staff_roles",
                "INSERT",
                "INSERT INTO public.staff_roles (user_id, email, role) "
                "VALUES (%s, 'a@example.com', 'admin')",
                (USER_A,),
            ),
            (
                "staff_roles",
                "UPDATE",
                "UPDATE public.staff_roles SET status = 'suspended' WHERE user_id = %s",
                (USER_A,),
            ),
            (
                "staff_roles",
                "DELETE",
                "DELETE FROM public.staff_roles WHERE user_id = %s",
                (USER_A,),
            ),
            (
                "staff_invites",
                "INSERT",
                "INSERT INTO public.staff_invites (token_hash, email, role, expires_at) "
                "VALUES (%s, 'a@example.com', 'admin', now())",
                ("validator-probe-hash",),
            ),
            (
                "staff_invites",
                "UPDATE",
                "UPDATE public.staff_invites SET used_at = now() WHERE id = %s",
                ("00000000-0000-4000-8000-000000000000",),
            ),
            (
                "staff_invites",
                "DELETE",
                "DELETE FROM public.staff_invites WHERE id = %s",
                ("00000000-0000-4000-8000-000000000000",),
            ),
            (
                "staff_sessions",
                "INSERT",
                "INSERT INTO public.staff_sessions (user_id) VALUES (%s)",
                (USER_A,),
            ),
            (
                "staff_sessions",
                "UPDATE",
                "UPDATE public.staff_sessions SET revoked_at = now() WHERE id = %s",
                ("00000000-0000-4000-8000-000000000000",),
            ),
            (
                "staff_sessions",
                "DELETE",
                "DELETE FROM public.staff_sessions WHERE id = %s",
                ("00000000-0000-4000-8000-000000000000",),
            ),
        ]
        for table, verb, query, params in staff_write_probes:
            status, exc, _ = probe(uri, "authenticated", USER_A, query, params)
            results.check(
                f"authenticated {verb} on {table} denied (42501)",
                status == "err" and isinstance(exc, pg_errors.InsufficientPrivilege),
                f"status={status} exc={exc!r}",
            )

        # --- G8b: authenticated cannot even SELECT a staff table (0007:
        # no grant at all, not just no write grant — the staff role is
        # never readable from the client). A missing grant fails with
        # 42501, not an empty page: the denial is at the GRANT layer,
        # before RLS is even evaluated.
        for table, column in [
            ("staff_roles", "user_id"),
            ("staff_invites", "id"),
            ("staff_sessions", "id"),
            ("admin_settings", "key"),
        ]:
            status, exc, _ = probe(
                uri, "authenticated", USER_A, f"SELECT {column} FROM public.{table} LIMIT 1"
            )
            results.check(
                f"authenticated SELECT on {table} denied (42501)",
                status == "err" and isinstance(exc, pg_errors.InsufficientPrivilege),
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

        # --- G17: admin foundation (0007). Staff tables (service_role
        # only), the single-Owner trigger, the invite atomic claim, and
        # the append-only audit log (trigger + REVOKEs). Probes run as
        # service_role unless stated — authenticated holds nothing on
        # the staff tables (proven in G4/G5/G8/G8b), so its denials
        # need no re-proof here.
        text0007 = (MIGRATIONS_DIR / "0007_admin_foundation.sql").read_text(encoding="utf-8")
        code0007 = "\n".join(
            line for line in text0007.splitlines() if not line.strip().startswith("--")
        )
        results.check("0007 grants nothing TO anon", "TO anon" not in code0007)
        results.check(
            "0007 grants nothing TO authenticated", "TO authenticated" not in code0007
        )
        for table in STAFF_TABLES:
            results.check(
                f"0007 grants full DML on {table} TO service_role",
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.{table} TO service_role;"
                in text0007,
            )
        results.check(
            "0007 revokes UPDATE/DELETE on audit_logs from service_role",
            "REVOKE UPDATE, DELETE ON public.audit_logs FROM service_role;" in text0007,
        )
        results.check(
            "0007 revokes UPDATE/DELETE on audit_logs from authenticated",
            "REVOKE UPDATE, DELETE ON public.audit_logs FROM authenticated;" in text0007,
        )
        results.check(
            "0007 revokes TRUNCATE on audit_logs from service_role",
            "REVOKE TRUNCATE ON public.audit_logs FROM service_role;" in text0007,
        )
        results.check(
            "0007 revokes TRUNCATE on audit_logs from PUBLIC",
            "REVOKE TRUNCATE ON public.audit_logs FROM PUBLIC;" in text0007,
        )
        results.check(
            "0007 creates the admin_settings table + seeds prefix_version = 1",
            "CREATE TABLE public.admin_settings" in text0007
            and "INSERT INTO public.admin_settings (key, value) VALUES ('prefix_version', '1')"
            in text0007,
        )
        results.check(
            "0007 creates the audit UPDATE + DELETE triggers",
            "CREATE TRIGGER audit_logs_prevent_update" in text0007
            and "CREATE TRIGGER audit_logs_prevent_delete" in text0007,
        )
        results.check(
            "0007 creates the single-Owner trigger",
            "CREATE TRIGGER staff_roles_enforce_single_owner" in text0007,
        )
        results.check(
            "0007 creates the partial unique single-Owner index",
            "CREATE UNIQUE INDEX staff_roles_single_owner_idx" in text0007
            and "WHERE role = 'owner'" in text0007,
        )

        # --- G17a: 0007 schema shape + triggers + zero staff policies.
        with psycopg.connect(uri, autocommit=True) as conn3, conn3.cursor() as cur:
            for table, columns in {
                "staff_roles": [
                    "user_id",
                    "role",
                    "status",
                    "invited_by",
                    "current_factor_id",
                    "pending_factor_id",
                    "created_at",
                    "updated_at",
                ],
                "staff_invites": [
                    "id",
                    "token_hash",
                    "email",
                    "role",
                    "invited_by",
                    "expires_at",
                    "used_at",
                    "created_at",
                ],
                "staff_sessions": [
                    "id",
                    "user_id",
                    "issued_at",
                    "last_seen_at",
                    "revoked_at",
                    "ip",
                    "user_agent",
                    "prefix_version",
                    "step_up_verified_at",
                ],
                "admin_settings": ["key", "value", "updated_at"],
            }.items():
                for column in columns:
                    cur.execute(
                        "SELECT 1 FROM information_schema.columns WHERE "
                        "table_schema = 'public' AND table_name = %s AND column_name = %s",
                        (table, column),
                    )
                    results.check(
                        f"0007: column {table}.{column} exists",
                        cur.fetchone() is not None,
                    )
            for trigger in (
                "staff_roles_enforce_single_owner",
                "audit_logs_prevent_update",
                "audit_logs_prevent_delete",
            ):
                cur.execute(
                    "SELECT 1 FROM pg_trigger WHERE tgname = %s AND NOT tgisinternal",
                    (trigger,),
                )
                results.check(f"0007: trigger {trigger} exists", cur.fetchone() is not None)
            # Partial unique single-Owner index (Child F race closer):
            # unique, on (role), predicated to Owner rows only. The
            # catalog (not just the file text) is the proof — the
            # sequential second-Owner probe in G17b hits the trigger
            # first (BEFORE INSERT fires before the index check), so
            # only the catalog can prove the index itself exists.
            cur.execute(
                "SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' "
                "AND indexname = 'staff_roles_single_owner_idx'"
            )
            row = cur.fetchone()
            indexdef = row[0] if row else ""
            results.check(
                "0007: partial unique index staff_roles_single_owner_idx exists",
                row is not None,
                f"indexdef={indexdef!r}",
            )
            results.check(
                "0007: single-Owner index is UNIQUE on (role) WHERE role = 'owner'",
                "UNIQUE INDEX" in indexdef
                and "(role)" in indexdef
                and "WHERE" in indexdef
                and "role = 'owner'" in indexdef,
                f"indexdef={indexdef!r}",
            )
            # to_regclass (not a ::regclass cast) so the exclude-0007
            # control run fails this check gracefully instead of
            # raising UndefinedTable — the control must end with a
            # summary + non-zero exit, not a traceback.
            cur.execute(
                "SELECT indisunique FROM pg_index WHERE indexrelid = "
                "to_regclass('public.staff_roles_single_owner_idx')"
            )
            row = cur.fetchone()
            results.check(
                "0007: single-Owner index is unique in pg_index",
                row is not None and bool(row[0]),
                f"row={row!r}",
            )
            for table in STAFF_TABLES:
                cur.execute(
                    "SELECT policyname FROM pg_policies "
                    "WHERE schemaname = 'public' AND tablename = %s",
                    (table,),
                )
                results.check(
                    f"0007: no RLS policy at all on {table} (service_role only)",
                    cur.fetchall() == [],
                )

        # --- G17b: single-Owner trigger. Scratch users C (admin) and D
        # (first Owner); B is the would-be second Owner.
        status, rows, _ = probe(
            uri,
            "service_role",
            None,
            "INSERT INTO public.staff_roles (user_id, email, role, invited_by) "
            "VALUES (%s, 'staff-c@example.com', 'admin', %s) RETURNING user_id",
            (USER_C, USER_D),
        )
        results.check(
            "service_role INSERTs staff_roles admin row",
            status == "ok" and len(rows) == 1,
            f"{status} {rows}",
        )
        # MFA factor-id columns (Child F): the login flow stores the
        # verified / pending GoTrue factor ids here; NULL by default,
        # writable by service_role, readable back.
        status, rows, _ = probe(
            uri,
            "service_role",
            None,
            "UPDATE public.staff_roles SET current_factor_id = 'factor-current', "
            "pending_factor_id = 'factor-pending' WHERE user_id = %s "
            "RETURNING current_factor_id, pending_factor_id",
            (USER_C,),
        )
        results.check(
            "staff_roles current/pending factor ids round-trip",
            status == "ok"
            and rows
            and rows[0][0] == "factor-current"
            and rows[0][1] == "factor-pending",
            f"{status} {rows}",
        )
        status, _, rc = probe(
            uri,
            "service_role",
            None,
            "UPDATE public.staff_roles SET current_factor_id = NULL, "
            "pending_factor_id = NULL WHERE user_id = %s",
            (USER_C,),
        )
        results.check(
            "staff_roles factor ids clear back to NULL (MFA re-enrollment)",
            status == "ok" and rc == 1,
            f"{status} rc={rc}",
        )
        status, rows, _ = probe(
            uri,
            "service_role",
            None,
            "INSERT INTO public.staff_roles (user_id, email, role) "
            "VALUES (%s, 'owner-d@example.com', 'owner') RETURNING user_id",
            (USER_D,),
        )
        results.check(
            "service_role INSERTs first Owner",
            status == "ok" and len(rows) == 1,
            f"{status} {rows}",
        )
        status, exc, _ = probe(
            uri,
            "service_role",
            None,
            "INSERT INTO public.staff_roles (user_id, email, role) "
            "VALUES (%s, 'staff-b@example.com', 'owner')",
            (USER_B,),
        )
        results.check(
            "second Owner INSERT blocked by trigger",
            status == "err"
            and isinstance(exc, pg_errors.RaiseException)
            and "only one Owner" in str(exc),
            f"status={status} exc={exc!r}",
        )
        status, exc, _ = probe(
            uri,
            "service_role",
            None,
            "UPDATE public.staff_roles SET role = 'owner' WHERE user_id = %s",
            (USER_C,),
        )
        results.check(
            "re-role to Owner while one exists blocked by trigger",
            status == "err"
            and isinstance(exc, pg_errors.RaiseException)
            and "only one Owner" in str(exc),
            f"status={status} exc={exc!r}",
        )
        # Updating the existing Owner's own row (a status change) must
        # pass — the trigger excludes the row itself.
        status, _, rc = probe(
            uri,
            "service_role",
            None,
            "UPDATE public.staff_roles SET status = 'suspended' WHERE user_id = %s",
            (USER_D,),
        )
        results.check(
            "Owner status change passes the trigger",
            status == "ok" and rc == 1,
            f"{status} rc={rc}",
        )
        # The Owner stepping down to admin is allowed (zero owners is
        # a setup invariant, not a trigger rule); a new Owner can then
        # be created.
        status, _, rc = probe(
            uri,
            "service_role",
            None,
            "UPDATE public.staff_roles SET role = 'admin', status = 'active' "
            "WHERE user_id = %s",
            (USER_D,),
        )
        results.check(
            "Owner stepping down to admin passes",
            status == "ok" and rc == 1,
            f"{status} rc={rc}",
        )
        status, rows, _ = probe(
            uri,
            "service_role",
            None,
            "INSERT INTO public.staff_roles (user_id, email, role) "
            "VALUES (%s, 'staff-b@example.com', 'owner') RETURNING user_id",
            (USER_B,),
        )
        results.check(
            "Owner INSERT after step-down passes",
            status == "ok" and len(rows) == 1,
            f"{status} {rows}",
        )
        for uid in (USER_B, USER_C, USER_D):
            probe(
                uri,
                "service_role",
                None,
                "DELETE FROM public.staff_roles WHERE user_id = %s",
                (uid,),
            )
        # Email uniqueness (C2 fix): one staff row per email.
        status, rows, _ = probe(
            uri,
            "service_role",
            None,
            "INSERT INTO public.staff_roles (user_id, email, role) "
            "VALUES (%s, 'dup@example.com', 'admin') RETURNING user_id",
            (USER_C,),
        )
        results.check(
            "service_role INSERTs staff_roles row with email",
            status == "ok" and len(rows) == 1,
            f"{status} {rows}",
        )
        status, exc, _ = probe(
            uri,
            "service_role",
            None,
            "INSERT INTO public.staff_roles (user_id, email, role) "
            "VALUES (%s, 'dup@example.com', 'support')",
            (USER_D,),
        )
        results.check(
            "duplicate staff email blocked by unique index",
            status == "err"
            and isinstance(exc, pg_errors.UniqueViolation)
            and "staff_roles_email_key" in str(exc),
            f"status={status} exc={exc!r}",
        )
        probe(
            uri,
            "service_role",
            None,
            "DELETE FROM public.staff_roles WHERE user_id = %s",
            (USER_C,),
        )

        # --- G17c: staff_invites — insert, unique token_hash, atomic
        # single-use claim (UPDATE ... WHERE used_at IS NULL RETURNING).
        invite_hash = hashlib.sha256(b"validator-invite-token").hexdigest()
        status, rows, _ = probe(
            uri,
            "service_role",
            None,
            "INSERT INTO public.staff_invites (token_hash, email, role, invited_by, expires_at) "
            "VALUES (%s, 'staff-c@example.com', 'admin', %s, now() + interval '72 hours') "
            "RETURNING id",
            (invite_hash, USER_D),
        )
        invite_id = rows[0][0] if status == "ok" and rows else None
        results.check(
            "service_role INSERTs staff_invite",
            status == "ok" and invite_id is not None,
            f"{status} {rows}",
        )
        status, exc, _ = probe(
            uri,
            "service_role",
            None,
            "INSERT INTO public.staff_invites (token_hash, email, role, expires_at) "
            "VALUES (%s, 'staff-d@example.com', 'admin', now() + interval '72 hours')",
            (invite_hash,),
        )
        results.check(
            "duplicate token_hash violates staff_invites_token_hash_key",
            status == "err"
            and isinstance(exc, pg_errors.UniqueViolation)
            and "staff_invites_token_hash_key" in str(exc),
            f"status={status} exc={exc!r}",
        )
        # The claim checks below need the invite row; if the insert
        # failed (control run), record them as failed and skip — do
        # not probe with a None id (that only produces uuid-parse
        # noise instead of the real failure).
        if invite_id is None:
            for name in (
                "atomic claim of unused invite returns the row",
                "second claim of the same invite returns 0 rows",
            ):
                results.check(name, False, "prerequisite invite insert failed")
        else:
            status, rows, _ = probe(
                uri,
                "service_role",
                None,
                "UPDATE public.staff_invites SET used_at = now() "
                "WHERE id = %s AND used_at IS NULL RETURNING id",
                (str(invite_id),),
            )
            results.check(
                "atomic claim of unused invite returns the row",
                status == "ok" and len(rows) == 1,
                f"{status} {rows}",
            )
            status, rows, _ = probe(
                uri,
                "service_role",
                None,
                "UPDATE public.staff_invites SET used_at = now() "
                "WHERE id = %s AND used_at IS NULL RETURNING id",
                (str(invite_id),),
            )
            results.check(
                "second claim of the same invite returns 0 rows",
                status == "ok" and len(rows) == 0,
                f"{status} {rows}",
            )
            probe(
                uri,
                "service_role",
                None,
                "DELETE FROM public.staff_invites WHERE id = %s",
                (str(invite_id),),
            )

        # --- G17d: staff_sessions — defaults (prefix_version 1,
        # revoked_at NULL, step_up_verified_at NULL), last_seen update,
        # step-up mark, revoke.
        status, rows, _ = probe(
            uri,
            "service_role",
            None,
            "INSERT INTO public.staff_sessions (user_id, ip, user_agent) "
            "VALUES (%s, '203.0.113.7', 'validator/1.0') "
            "RETURNING id, prefix_version, revoked_at, step_up_verified_at",
            (USER_C,),
        )
        session_id = rows[0][0] if status == "ok" and rows else None
        results.check(
            "service_role INSERTs staff_session with prefix_version 1, "
            "revoked_at NULL, step_up_verified_at NULL",
            status == "ok"
            and rows
            and rows[0][1] == 1
            and rows[0][2] is None
            and rows[0][3] is None,
            f"{status} {rows}",
        )
        # The updates below need the session row; if the insert failed
        # (control run), record them as failed and skip.
        if session_id is None:
            for name in (
                "staff_session last_seen_at updates",
                "staff_session step_up_verified_at sets",
                "staff_session revokes (revoked_at set)",
            ):
                results.check(name, False, "prerequisite session insert failed")
        else:
            status, _, rc = probe(
                uri,
                "service_role",
                None,
                "UPDATE public.staff_sessions SET last_seen_at = now() WHERE id = %s",
                (str(session_id),),
            )
            results.check(
                "staff_session last_seen_at updates",
                status == "ok" and rc == 1,
                f"{status} rc={rc}",
            )
            # Step-up mark: POST /staff/auth/step-up/verify sets this when
            # a fresh MFA check passes; the Founder gate reads it. The
            # store writes it only when a step-up time is set (Child B) —
            # the column must simply accept the write.
            status, _, rc = probe(
                uri,
                "service_role",
                None,
                "UPDATE public.staff_sessions SET step_up_verified_at = now() WHERE id = %s",
                (str(session_id),),
            )
            results.check(
                "staff_session step_up_verified_at sets",
                status == "ok" and rc == 1,
                f"{status} rc={rc}",
            )
            status, _, rc = probe(
                uri,
                "service_role",
                None,
                "UPDATE public.staff_sessions SET revoked_at = now() WHERE id = %s",
                (str(session_id),),
            )
            results.check(
                "staff_session revokes (revoked_at set)",
                status == "ok" and rc == 1,
                f"{status} rc={rc}",
            )
            probe(
                uri,
                "service_role",
                None,
                "DELETE FROM public.staff_sessions WHERE id = %s",
                (str(session_id),),
            )

        # --- G17e: audit_logs append-only. service_role INSERT still
        # works; service_role UPDATE/DELETE fail at the GRANT layer
        # (42501, the 0007 REVOKEs); the table owner (superuser — the
        # one role that still holds the grant) hits the TRIGGER instead
        # (RaiseException). The probe row is left in place: nothing can
        # delete it, which is the point — the database is ephemeral and
        # the seed counts were already asserted in G2.
        status, rows, _ = probe(
            uri,
            "service_role",
            None,
            "INSERT INTO public.audit_logs (user_id, action, target_domain, metadata) "
            "VALUES (%s, 'admin.test', NULL, '{}'::jsonb) RETURNING id",
            (USER_C,),
        )
        audit_id = rows[0][0] if status == "ok" and rows else None
        results.check(
            "service_role INSERTs audit row",
            status == "ok" and audit_id is not None,
            f"{status} {rows}",
        )
        # The checks below need the audit row; if the insert failed
        # (control run without 0005 grants), record them as failed
        # and skip — do not probe with a None id.
        if audit_id is None:
            for name in (
                "service_role UPDATE of audit row denied (42501, 0007 REVOKE)",
                "service_role DELETE of audit row denied (42501, 0007 REVOKE)",
                "owner UPDATE of audit row blocked by trigger",
                "owner DELETE of audit row blocked by trigger",
            ):
                results.check(name, False, "prerequisite audit insert failed")
        else:
            status, exc, _ = probe(
                uri,
                "service_role",
                None,
                "UPDATE public.audit_logs SET action = 'tampered' WHERE id = %s",
                (str(audit_id),),
            )
            results.check(
                "service_role UPDATE of audit row denied (42501, 0007 REVOKE)",
                status == "err" and isinstance(exc, pg_errors.InsufficientPrivilege),
                f"status={status} exc={exc!r}",
            )
            status, exc, _ = probe(
                uri,
                "service_role",
                None,
                "DELETE FROM public.audit_logs WHERE id = %s",
                (str(audit_id),),
            )
            results.check(
                "service_role DELETE of audit row denied (42501, 0007 REVOKE)",
                status == "err" and isinstance(exc, pg_errors.InsufficientPrivilege),
                f"status={status} exc={exc!r}",
            )
            with psycopg.connect(uri, autocommit=True) as conn4, conn4.cursor() as cur:
                for verb, query in [
                    ("UPDATE", "UPDATE public.audit_logs SET action = 'tampered' WHERE id = %s"),
                    ("DELETE", "DELETE FROM public.audit_logs WHERE id = %s"),
                ]:
                    try:
                        cur.execute(query, (str(audit_id),))
                        results.check(
                            f"owner {verb} of audit row blocked by trigger",
                            False,
                            "no exception raised",
                        )
                    except pg_errors.RaiseException as exc:
                        results.check(
                            f"owner {verb} of audit row blocked by trigger",
                            "append-only" in str(exc),
                            f"exc={exc!r}",
                        )
                    except Exception as exc:  # noqa: BLE001 - probe outcome is the point
                        results.check(
                            f"owner {verb} of audit row blocked by trigger",
                            False,
                            f"wrong exception: {exc!r}",
                        )

        # --- G17f: admin_settings (C3 fix) + TRUNCATE revoke (N6 fix).
        # The migration seeds prefix_version = 1; service_role can
        # read/write settings (the API's rotation path); TRUNCATE on
        # audit_logs is denied to service_role at the GRANT layer
        # (42501). The table OWNER can still TRUNCATE (inherent —
        # no probe asserts otherwise; the residual is documented in
        # the migration header).
        status, rows, _ = probe(
            uri,
            "service_role",
            None,
            "SELECT value FROM public.admin_settings WHERE key = 'prefix_version'",
        )
        results.check(
            "admin_settings seeds prefix_version = 1",
            status == "ok" and rows and rows[0][0] == "1",
            f"{status} {rows}",
        )
        status, rows, _ = probe(
            uri,
            "service_role",
            None,
            "INSERT INTO public.admin_settings (key, value) VALUES "
            "('validator_probe', 'v1') RETURNING key, value",
        )
        results.check(
            "service_role INSERTs admin_settings row",
            status == "ok" and rows and rows[0] == ("validator_probe", "v1"),
            f"{status} {rows}",
        )
        status, rows, _ = probe(
            uri,
            "service_role",
            None,
            "UPDATE public.admin_settings SET value = 'v2' "
            "WHERE key = 'validator_probe' RETURNING value",
        )
        results.check(
            "service_role UPDATEs admin_settings row",
            status == "ok" and rows and rows[0][0] == "v2",
            f"{status} {rows}",
        )
        status, _, rc = probe(
            uri,
            "service_role",
            None,
            "DELETE FROM public.admin_settings WHERE key = 'validator_probe'",
        )
        results.check(
            "service_role DELETEs admin_settings row",
            status == "ok" and rc == 1,
            f"{status} rc={rc}",
        )
        status, exc, _ = probe(
            uri,
            "service_role",
            None,
            "TRUNCATE public.audit_logs",
        )
        results.check(
            "service_role TRUNCATE of audit_logs denied (42501, 0007 REVOKE)",
            status == "err" and isinstance(exc, pg_errors.InsufficientPrivilege),
            f"status={status} exc={exc!r}",
        )

        return results.summary()
    finally:
        server.cleanup()


if __name__ == "__main__":
    sys.exit(main())
