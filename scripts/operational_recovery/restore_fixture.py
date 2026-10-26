"""Actual SMTP accounts and complete private table snapshots in an owned cluster."""
import json
import os
import re
import uuid

from . import mailbox

PROBE_BYTES_PER_REALM = 100000


def sign_in_realms(services, roles, processes):
    realms = [uuid.uuid4(), uuid.uuid4()]
    results, messages = [], []
    for realm in realms:
        origin = processes.start(roles.url(roles.runtime, roles.runtime_password), realm)
        signed, message = mailbox.sign_in(origin, services.mail_origin)
        if signed[2]["realm_id"] != str(realm):
            raise ValueError("backup fixture realm mismatch")
        results.append(signed)
        messages.append(message)
    if results[0][2]["id"] == results[1][2]["id"]:
        raise ValueError("backup fixture accounts are not distinct")
    return realms, results, messages


def seed_probe(services, roles, realms):
    values = ",".join("('" + str(realm) + "',decode('" + os.urandom(PROBE_BYTES_PER_REALM).hex()
                      + "','hex'))" for realm in realms)
    # Only this disposable DB gets the fixture table. Incompressible owned data
    # makes the real archive exceed one authenticated age chunk.
    services.sql(roles.database,
        "CREATE TABLE owned_auth49_restore_probe(realm_id uuid PRIMARY KEY, payload bytea NOT NULL); "
        "INSERT INTO owned_auth49_restore_probe VALUES " + values,
        user=roles.migration, password=roles.migration_password, label="owned-restore-probe")


def snapshot(services, database):
    names = json.loads(services.sql(database,
        "SELECT json_agg(tablename ORDER BY tablename) FROM pg_tables WHERE schemaname='public'",
        label="snapshot-tables"))
    if not names or not all(re.fullmatch(r"auth_[a-z0-9_]+|_sqlx_migrations|owned_auth49_restore_probe", name) for name in names):
        raise ValueError("unexpected owned snapshot table")
    rows = ["SELECT '" + name + "' AS name,(SELECT coalesce(jsonb_agg(to_jsonb(item) "
            "ORDER BY to_jsonb(item)::text),'[]'::jsonb) FROM " + name + " item) AS contents" for name in names]
    # One statement gives all tables a single database snapshot. Private rows
    # remain in memory for equality; they are never printed or included in receipts.
    return json.loads(services.sql(database, "SELECT jsonb_object_agg(name,contents) FROM ("
                                   + " UNION ALL ".join(rows) + ") tables",
                                   label="snapshot-data"))


def revoke_live_session(first, origin):
    client = first[0]
    if mailbox.request(client, origin + "/v1/session")[0] != 200:
        raise ValueError("backup source session lost its positive control")
    if mailbox.request(client, origin + "/v1/logout", method="POST", origin=origin)[0] != 204 \
            or mailbox.request(client, origin + "/v1/session")[0] != 401:
        raise ValueError("backup source logout failed")


def assert_snapshots(old, current, realms, first):
    if len(old["auth_users"]) != 2 or len(old["auth_sessions"]) != 2 \
            or len(old["_sqlx_migrations"]) != 38 or len(current["_sqlx_migrations"]) != 38:
        raise ValueError("backup source cardinality mismatch")
    for content, expected_revoked in [(old, False), (current, True)]:
        selected = [row for row in content["auth_sessions"]
                    if row["realm_id"] == str(realms[0]) and row["user_id"] == first[2]["id"]]
        if len(selected) != 1 or (selected[0]["revoked_at"] is not None) != expected_revoked:
            raise ValueError("backup does not preserve its exact revocation point")
        if {row["realm_id"] for row in content["auth_users"]} != {str(realm) for realm in realms}:
            raise ValueError("backup source realm scope mismatch")
