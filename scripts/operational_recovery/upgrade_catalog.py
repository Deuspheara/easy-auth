"""Owned schema37/38 catalog assertions and deliberately conflicting index fixture."""
import json
import time
from urllib.parse import urlsplit, urlunsplit

from .restore_fixture import snapshot

CATALOG = """SELECT jsonb_build_object(
 'grant_table',to_regclass('public.auth_apple_grants') IS NOT NULL,
 'grant_constraint',EXISTS(SELECT 1 FROM pg_constraint
   WHERE conname='auth_oidc_identity_grant_source' AND conrelid='auth_oidc_identities'::regclass),
 'grant_trigger',EXISTS(SELECT 1 FROM pg_trigger
   WHERE tgname='auth_queue_apple_identity_grants' AND NOT tgisinternal),
 'conflict_index',EXISTS(SELECT 1 FROM pg_index
   WHERE indexrelid=to_regclass('public.auth_apple_grants_due')
   AND indrelid='owned_auth49_restore_probe'::regclass))"""


def history(services, database, version):
    rows = snapshot(services, database)["_sqlx_migrations"]
    if [row["version"] for row in sorted(rows, key=lambda row: row["version"])] != list(range(1, version + 1)) \
            or not all(row["success"] for row in rows):
        raise ValueError("owned upgrade migration history mismatch")


def wait_for_drain(services, roles):
    deadline = time.monotonic() + 5
    query = "SELECT count(*) FROM pg_stat_activity WHERE datname='" + roles.database \
        + "' AND usename IN ('" + roles.runtime + "','" + roles.migration + "')"
    while services.sql("fixture_admin", query, label="upgrade-writer-drain") != "0":
        if time.monotonic() >= deadline:
            raise ValueError("owned upgrade writers did not drain")
        time.sleep(0.1)


def install_conflict(services, roles):
    services.sql(roles.database,
        "CREATE INDEX auth_apple_grants_due ON owned_auth49_restore_probe(realm_id)",
        user=roles.migration, password=roles.migration_password, label="owned-upgrade-conflict")


def assert_failed_atomicity(services, roles, before):
    observed = json.loads(services.sql(roles.database, CATALOG, label="failed-upgrade-catalog"))
    if observed != dict(grant_table=False, grant_constraint=False, grant_trigger=False, conflict_index=True):
        raise ValueError("failed migration retained partial DDL or lost the original conflict")
    if snapshot(services, roles.database) != before:
        raise ValueError("failed migration changed legacy rows or history")
    history(services, roles.database, 37)
    locks = services.sql("fixture_admin", "SELECT count(*) FROM pg_locks WHERE locktype='advisory' "
        "AND database=(SELECT oid FROM pg_database WHERE datname='" + roles.database + "')",
        label="failed-upgrade-locks")
    if locks != "0":
        raise ValueError("failed migration left an advisory lock")


def remove_owned_conflict(services, roles):
    observed = json.loads(services.sql(roles.database, CATALOG, label="owned-conflict-inspection"))
    if not observed["conflict_index"] or observed["grant_table"]:
        raise ValueError("refusing removal of an unexpected migration conflict")
    services.sql(roles.database, "DROP INDEX auth_apple_grants_due", user=roles.migration,
                 password=roles.migration_password, label="owned-conflict-removal")


def clone_url(pg, roles, clone):
    if clone not in pg.clones:
        raise ValueError("unknown owned upgrade clone")
    value = urlsplit(roles.url(roles.migration, roles.migration_password))
    return urlunsplit(value._replace(path="/" + clone))


def assert_upgraded_data(services, database, before):
    current = snapshot(services, database)
    if current.pop("auth_apple_grants", None) != []:
        raise ValueError("new grant table was not empty after upgrade")
    current.pop("_sqlx_migrations")
    legacy = {name: rows for name, rows in before.items() if name != "_sqlx_migrations"}
    if current != legacy:
        raise ValueError("upgrade changed legacy table contents")
    history(services, database, 38)
