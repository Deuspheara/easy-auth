"""Disposable local PostgreSQL credentials, shared by the guide and owned smoke."""
import secrets
from urllib.parse import urlunsplit
import uuid


def development_settings():
    password = secrets.token_urlsafe(32)
    authority = "auth:" + password + "@postgres:5432"
    return {"EASY_AUTH_LOCAL_DB_PASSWORD": password,
            "EASY_AUTH_LOCAL_DATABASE_URL": urlunsplit(("postgres", authority, "/auth", "", "")),
            "EASY_AUTH_LOCAL_REALM_ID": str(uuid.uuid4())}
