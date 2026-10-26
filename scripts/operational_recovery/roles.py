"""Provision only the fresh fixture database's distinct migration/runtime principals."""
import secrets
from urllib.parse import quote
import uuid


class Roles:
    def __init__(self, services):
        self.services = services
        suffix = uuid.uuid4().hex
        self.database = "auth49_" + suffix
        self.migration = "auth49_migrate_" + suffix
        self.runtime = "auth49_runtime_" + suffix
        self.migration_password = secrets.token_urlsafe(32)
        self.runtime_password = secrets.token_urlsafe(32)

    def url(self, user, password):
        return "postgres://" + quote(user, safe="") + ":" + quote(password, safe="") \
            + "@127.0.0.1:" + str(self.services.pg_port) + "/" + self.database

    def provision(self):
        # Generated base64url passwords and UUID identifiers cannot contain SQL
        # quoting/control syntax. The client never echoes SQL; this fresh server
        # omits statement/parameter logging, including error statements.
        self.services.sql("fixture_admin", f"""
CREATE ROLE {self.migration} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
 NOREPLICATION NOBYPASSRLS PASSWORD '{self.migration_password}';
CREATE ROLE {self.runtime} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
 NOREPLICATION NOBYPASSRLS PASSWORD '{self.runtime_password}';
CREATE DATABASE {self.database} OWNER {self.migration};
REVOKE ALL ON DATABASE {self.database} FROM PUBLIC;
GRANT CONNECT ON DATABASE {self.database} TO {self.runtime};
""", label="role-provision")

    def runtime_grants(self):
        self.services.sql(self.database, f"""
BEGIN;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO {self.runtime};
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO {self.runtime};
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO {self.runtime};
REVOKE INSERT,UPDATE,DELETE ON _sqlx_migrations FROM {self.runtime};
ALTER DEFAULT PRIVILEGES FOR ROLE {self.migration} IN SCHEMA public
 GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO {self.runtime};
ALTER DEFAULT PRIVILEGES FOR ROLE {self.migration} IN SCHEMA public
 GRANT USAGE,SELECT ON SEQUENCES TO {self.runtime};
COMMIT;
""", label="runtime-grants")

    def assert_privileges(self):
        actual = self.services.sql(self.database, "SELECT current_user", user=self.runtime,
                                   password=self.runtime_password, label="actual-runtime-login")
        if actual != self.runtime:
            raise ValueError("runtime principal mismatch")
        attributes = self.services.sql(self.database,
            "SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) "
            "AND rolcanlogin AND NOT rolinherit FROM pg_roles WHERE rolname=current_user",
            user=self.runtime, password=self.runtime_password, label="actual-runtime-attributes")
        if attributes != "t":
            raise ValueError("runtime principal has unexpected attributes")
        for statement in ["CREATE TABLE forbidden_runtime_ddl(id integer)",
                          "UPDATE _sqlx_migrations SET success=false WHERE version=1",
                          "CREATE TEMP TABLE forbidden_runtime_temporary(id integer)",
                          "SET ROLE " + self.migration]:
            self.services.sql(self.database, statement, user=self.runtime,
                              password=self.runtime_password, expected_error=True)
        return dict(actual_login=True, restricted_attributes=True, ddl_refused=True, migration_history_write_refused=True,
                    temporary_objects_refused=True, migration_role_switch_refused=True)
