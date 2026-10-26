"""Schema37 failure/recovery and current-schema replica replacement with owned users."""
from pathlib import Path
import subprocess
import uuid

from . import mailbox, restore_fixture, upgrade_catalog
from .archive_postgres import ArchivePostgres
from .processes import Processes
from .roles import Roles
from .upgrade_probe import SessionProbe


class UpgradeJourney:
    def __init__(self, services, directory, old_binary, prior_binary, current_binary, cipher):
        self.services, self.directory, self.cipher = services, Path(directory), cipher
        self.old_binary, self.current_binary = old_binary, current_binary
        self.prior_binary = prior_binary
        self.roles = Roles(services)
        self.processes, self.origins = {}, {}
        self.realms = [uuid.uuid4(), uuid.uuid4()]
        self.users, self.messages = [], []

    def _process(self, name, *, profile="current"):
        if name in self.processes:
            raise ValueError("duplicate owned upgrade actor")
        directory = self.directory / name
        directory.mkdir(mode=0o700)
        binaries = {"schema37": self.old_binary, "schema38": self.prior_binary, "current": self.current_binary}
        if profile not in binaries:
            raise ValueError("unknown owned replica version")
        actor = Processes(binaries[profile], directory, self.services.smtp_port)
        self.processes[name] = actor
        return actor

    def _start(self, name, realm, *, profile="current", expected_success=True):
        roles = self.roles
        url = roles.url(roles.migration, roles.migration_password) if profile != "current" \
            else roles.url(roles.runtime, roles.runtime_password)
        origin = self._process(name, profile=profile).start(url, realm, mode="verify" if profile == "current" else "run",
                                                   expected_success=expected_success)
        self.origins[name] = origin
        return origin

    def bootstrap_legacy(self):
        self.roles.provision()
        first = self._start("old-a1", self.realms[0], profile="schema37")
        peer = self._start("old-a2", self.realms[0], profile="schema37")
        second = self._start("old-b", self.realms[1], profile="schema37")
        for origin in (first, second):
            signed, message = mailbox.sign_in(origin, self.services.mail_origin)
            self.users.append(signed)
            self.messages.append(message)
        self._assert_session(self.users[0], peer)
        restore_fixture.seed_probe(self.services, self.roles, self.realms)
        for name in ("old-a1", "old-a2", "old-b"):
            self.processes[name].close()
        upgrade_catalog.wait_for_drain(self.services, self.roles)
        self.roles.runtime_grants()
        self.roles.assert_privileges()
        self.before = restore_fixture.snapshot(self.services, self.roles.database)
        upgrade_catalog.history(self.services, self.roles.database, 37)
        self._start("current-refuses-37", self.realms[0], expected_success=False)
        upgrade_catalog.wait_for_drain(self.services, self.roles)
        if restore_fixture.snapshot(self.services, self.roles.database) != self.before:
            raise ValueError("current verification changed the legacy schema data")

    def failure_and_recovery(self):
        pg = ArchivePostgres(self.services, self.roles, self.directory)
        key, archive = self.directory / "upgrade.key", self.directory / "schema37.dump.age"
        recipient = self.cipher.new_identity(key)
        expected = pg.encrypted_dump(self.cipher, recipient, archive)
        upgrade_catalog.install_conflict(self.services, self.roles)
        admin = self._process("administration")
        url = self.roles.url(self.roles.migration, self.roles.migration_password)
        admin.one_shot(url, expected_success=False, failure_kind="migration")
        upgrade_catalog.wait_for_drain(self.services, self.roles)
        upgrade_catalog.assert_failed_atomicity(self.services, self.roles, self.before)
        clone = pg.restore_selected(self.cipher, archive, key, expected)
        if restore_fixture.snapshot(self.services, clone) != self.before:
            raise ValueError("encrypted pre-failure snapshot changed during restoration")
        admin.one_shot(upgrade_catalog.clone_url(pg, self.roles, clone), expected_success=True)
        upgrade_catalog.assert_upgraded_data(self.services, clone, self.before)
        pg.assert_quarantined(clone)
        upgrade_catalog.remove_owned_conflict(self.services, self.roles)
        admin.one_shot(url, expected_success=True)
        upgrade_catalog.assert_upgraded_data(self.services, self.roles.database, self.before)
        self.roles.runtime_grants()
        upgraded = restore_fixture.snapshot(self.services, self.roles.database)
        self._start("old-refuses-38", self.realms[0], profile="schema37", expected_success=False)
        upgrade_catalog.wait_for_drain(self.services, self.roles)
        if restore_fixture.snapshot(self.services, self.roles.database) != upgraded:
            raise ValueError("old future-schema refusal changed upgraded data")
        return dict(atomic_failed_ddl=True, unchanged_history_and_legacy_rows=True,
            no_abandoned_schema_lock=True, backup_restore_then_migrate=True,
            restored_clone_never_served=True, restored_runtime_connect_refused=True,
            inspected_conflict_roll_forward=True, history_never_edited=True,
            old_version_future_schema_refused=True, ciphertext_sha256=expected)

    def replace_prior_software(self):
        old_first = self._start("prior-a1", self.realms[0], profile="schema38")
        old_peer = self._start("prior-a2", self.realms[0], profile="schema38")
        old_other = self._start("prior-b", self.realms[1], profile="schema38")
        for origin in (old_first, old_peer):
            self._assert_session(self.users[0], origin)
        self._assert_session(self.users[1], old_other)
        with SessionProbe(self.users[0], old_peer) as legacy_probe:
            first = self._start("current-a1", self.realms[0])
            self._assert_session(self.users[0], first)
            self.processes["prior-a1"].close()
            legacy_probe.require_more()
        with SessionProbe(self.users[0], first) as current_probe:
            peer = self._start("current-a2", self.realms[0])
            self._assert_session(self.users[0], peer)
            self._assert_session(self.users[0], old_peer)
            self.processes["prior-a2"].close()
            current_probe.require_more()
        self.availability_requests = legacy_probe.count + current_probe.count
        second = self._start("current-b", self.realms[1])
        self._assert_session(self.users[1], second)
        self._assert_session(self.users[1], old_other)
        self.processes["prior-b"].close()
        return first, peer, second

    def rolling_replacement(self):
        first, peer, second = self.replace_prior_software()
        with SessionProbe(self.users[0], peer) as replacement_probe:
            replacement = self._start("current-a3", self.realms[0])
            self.processes["current-a1"].close()
            replacement_probe.require_more()
        self._assert_session(self.users[0], replacement)
        # The separate foreign-origin request must not clear the original jar.
        mailbox.isolation_and_logout(self.users[0], second, replacement)
        if mailbox.request(self.users[0][0], peer + "/v1/session")[0] != 401:
            raise ValueError("logout did not propagate to the surviving replica")
        self._assert_session(self.users[1], second)
        mailbox.remove_messages(self.services.mail_origin, self.messages)
        return dict(legacy_owners_preserved=True, current_verification=True,
            selected_schema38_software_upgrade=True, old_new_replicas_served_during_overlap=True,
            concurrent_availability_requests=self.availability_requests + replacement_probe.count,
            availability_failures=0,
            current_schema_replica_replacement=True, surviving_replica_served=True,
            cross_realm_refused=True, logout_shared_across_replicas=True,
            other_realm_unchanged=True, owned_messages_removed=2)

    def _assert_session(self, signed, origin):
        status, user = mailbox.request(signed[0], origin + "/v1/session")
        if status != 200 or user["id"] != signed[2]["id"] or user["realm_id"] != signed[2]["realm_id"]:
            raise ValueError("owned upgrade session identity changed")

    def close(self):
        failures = []
        for name, actor in reversed(list(self.processes.items())):
            try:
                actor.close()
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                failures.append(dict(actor=name, category=type(error).__name__))
        return failures
