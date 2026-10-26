"""Custom-archive smoke against a newly created, never-served database clone."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid

COUNTS = """SELECT json_build_object(
 'users',(SELECT count(*) FROM auth_users),
 'sessions',(SELECT count(*) FROM auth_sessions),
 'revoked',(SELECT count(*) FROM auth_sessions WHERE revoked_at IS NOT NULL),
 'audits',(SELECT count(*) FROM auth_audit),
 'migrations',(SELECT count(*) FROM _sqlx_migrations),
 'failed_migrations',(SELECT count(*) FROM _sqlx_migrations WHERE NOT success),
 'owners',(SELECT coalesce(json_agg(id ORDER BY id),'[]'::json) FROM auth_users))"""


def check(stack):
    container = stack.containers()["postgres"]["Id"]
    base = ["docker", "exec", "-i", container]
    clone = "auth_restore_check_" + uuid.uuid4().hex
    archive = stack.directory / "auth.dump"
    created = False
    try:
        with os.fdopen(os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
            dumped = subprocess.run(base + ["pg_dump", "--username=auth", "--format=custom",
                                   "--no-owner", "--no-acl", "auth"], stdout=output,
                           stderr=subprocess.PIPE, check=True, timeout=90)
        if dumped.stderr:
            raise ValueError("owned dump emitted diagnostics")
        if archive.stat().st_mode & 0o077 or archive.read_bytes()[:5] != b"PGDMP":
            raise ValueError("private custom archive missing")
        subprocess.run(base + ["createdb", "--username=auth", clone], capture_output=True, check=True, timeout=30)
        created = True
        with archive.open("rb") as source:
            restored_archive = subprocess.run(base + ["pg_restore", "--username=auth", "--dbname=" + clone,
                                   "--no-owner", "--no-acl", "--single-transaction", "--exit-on-error"],
                           stdin=source, capture_output=True, check=True, timeout=90)
        if restored_archive.stderr:
            raise ValueError("owned restore emitted diagnostics")
        original, restored = [json.loads(subprocess.check_output(
            base + ["psql", "--username=auth", "--dbname=" + database, "--set=ON_ERROR_STOP=1",
                    "--tuples-only", "--no-align", "--command=" + COUNTS], timeout=30))
            for database in ("auth", clone)]
        if original != restored or original["users"] != 1 or original["failed_migrations"]:
            raise ValueError("restored smoke invariants differ")
        return {"private_archive": True, "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "owners_preserved": True, "users": original["users"],
                "migrations": original["migrations"], "clone_never_served": True}
    finally:
        if created:
            subprocess.run(base + ["dropdb", "--username=auth", clone], capture_output=True, check=True, timeout=30)
        archive.unlink(missing_ok=True)
