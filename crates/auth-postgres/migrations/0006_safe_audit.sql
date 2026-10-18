-- Historical rows lack actor/target provenance. Keep them at version 0 rather than inventing it.
ALTER TABLE auth_audit
    ADD COLUMN schema_version smallint NOT NULL DEFAULT 0,
    ADD COLUMN actor_session_id uuid,
    ADD COLUMN session_id uuid,
    ADD COLUMN subject_erased boolean NOT NULL DEFAULT false;

-- Old schema permitted dangling or cross-realm subject IDs; never attribute them to another user.
UPDATE auth_audit a SET user_id=NULL
WHERE kind='account_deleted' OR (user_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM auth_users u WHERE u.realm_id=a.realm_id AND u.id=a.user_id
));
UPDATE auth_audit SET subject_erased=(user_id IS NULL);
ALTER TABLE auth_audit ALTER COLUMN schema_version SET DEFAULT 1;
ALTER TABLE auth_audit
    ADD CONSTRAINT auth_audit_version CHECK (schema_version IN (0,1)),
    ADD CONSTRAINT auth_audit_subject_state CHECK (subject_erased=(user_id IS NULL)),
    ADD CONSTRAINT auth_audit_erased_references CHECK (
        NOT subject_erased OR (actor_session_id IS NULL AND session_id IS NULL)
    ),
    ADD CONSTRAINT auth_audit_deleted_subject CHECK (kind<>'account_deleted' OR subject_erased),
    ADD CONSTRAINT auth_audit_user FOREIGN KEY (realm_id,user_id)
        REFERENCES auth_users(realm_id,id),
    ADD CONSTRAINT auth_audit_actor_owner FOREIGN KEY (realm_id,actor_session_id,user_id)
        REFERENCES auth_sessions(realm_id,id,user_id),
    ADD CONSTRAINT auth_audit_session_owner FOREIGN KEY (realm_id,session_id,user_id)
        REFERENCES auth_sessions(realm_id,id,user_id),
    ADD CONSTRAINT auth_audit_event_shape CHECK (
        (schema_version=0 AND actor_session_id IS NULL AND session_id IS NULL)
        OR (schema_version=1 AND (
            subject_erased
            OR (kind IN ('email_authenticated','password_authenticated')
                AND actor_session_id IS NULL AND session_id IS NOT NULL)
            OR (kind='password_enrolled' AND actor_session_id IS NOT NULL
                AND session_id IS NOT NULL AND actor_session_id<>session_id)
            OR (kind='password_reset' AND actor_session_id IS NULL AND session_id IS NULL)
            OR (kind='session_revoked' AND actor_session_id IS NOT NULL AND session_id IS NOT NULL)
            OR (kind IN ('all_sessions_revoked','email_changed')
                AND actor_session_id IS NOT NULL AND session_id IS NULL)
        ))
    );
CREATE INDEX auth_audit_subject_page ON auth_audit(realm_id,user_id,id);
