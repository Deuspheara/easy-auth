"""Real restricted-role retention beside two live owned SMTP/HTTP accounts."""
from . import mailbox, restore_fixture


def qualify(services, roles, processes, realms, accounts, origins):
    for realm in realms:
        services.sql(roles.database,
            "INSERT INTO auth_email_challenges(realm_id,token_hash,browser_hash,email,expires_at) "
            "VALUES('" + str(realm) + "',sha256(convert_to(gen_random_uuid()::text,'UTF8')),"
            "sha256(convert_to(gen_random_uuid()::text,'UTF8')),'owned-retention@example.test',"
            "statement_timestamp()-interval '1 second')",
            user=roles.migration, password=roles.migration_password, label="owned-expired-retention-proof")
    before = restore_fixture.snapshot(services, roles.database)
    if len(before["auth_email_challenges"]) != 2:
        raise ValueError("owned retention fixture did not contain both expired realm proofs")
    runtime_url = roles.url(roles.runtime, roles.runtime_password)
    effects = processes.retention(runtime_url, realms[0])
    if effects.get(b"EmailChallenges") != (1, 0, 0) \
            or any(value != (0, 0, 0) for category, value in effects.items() if category != b"EmailChallenges"):
        raise ValueError("owned restricted-role retention changed unexpected categories")
    expected = dict(before)
    expected["auth_email_challenges"] = [row for row in before["auth_email_challenges"]
                                         if row["realm_id"] != str(realms[0])]
    if restore_fixture.snapshot(services, roles.database) != expected:
        raise ValueError("retention changed live, foreign or durable fixture data")
    if any(value != (0, 0, 0) for value in processes.retention(runtime_url, realms[0]).values()):
        raise ValueError("owned retention rerun was not idempotent")
    if restore_fixture.snapshot(services, roles.database) != expected:
        raise ValueError("retention rerun changed fixture state")
    for account, origin in zip(accounts, origins, strict=True):
        status, user = mailbox.request(account[0], origin + "/v1/session")
        if status != 200 or user["id"] != account[2]["id"] or user["realm_id"] != account[2]["realm_id"]:
            raise ValueError("retention lost a real live session")
    return dict(runtime_role_dml=True, full_schema_verification=True, explicit_keep_horizons=True,
        selected_expired_proof_deleted=1, foreign_expired_proof_retained=1,
        every_other_stored_value_preserved=True, both_real_sessions_retained=True,
        one_shot_idempotent=True, scalar_output_only=True)
