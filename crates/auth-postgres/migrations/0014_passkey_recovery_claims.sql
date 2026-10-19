ALTER TABLE auth_passkey_recovery_codes ADD COLUMN consumed_at timestamptz
    CHECK (consumed_at IS NULL OR isfinite(consumed_at));

CREATE TABLE auth_passkey_recovery_claims (
    realm_id uuid NOT NULL,
    user_id uuid NOT NULL,
    rp_id text NOT NULL,
    id uuid NOT NULL,
    code_version uuid NOT NULL,
    browser_hash bytea NOT NULL CHECK (octet_length(browser_hash)=32),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at) AND expires_at>created_at),
    delay_seconds integer NOT NULL CHECK (delay_seconds>0),
    notification_required boolean NOT NULL,
    notified_at timestamptz,
    not_before timestamptz,
    cancelled_at timestamptz CHECK (cancelled_at IS NULL OR (isfinite(cancelled_at) AND cancelled_at>=created_at)),
    PRIMARY KEY (realm_id,user_id,rp_id),
    UNIQUE (realm_id,id),
    UNIQUE (realm_id,id,user_id),
    FOREIGN KEY (realm_id,user_id,rp_id) REFERENCES auth_passkey_recovery_codes(realm_id,user_id,rp_id) ON DELETE CASCADE,
    CHECK (
        (notification_required AND (
            (notified_at IS NULL AND not_before IS NULL)
            OR (notified_at IS NOT NULL AND not_before IS NOT NULL
                AND isfinite(notified_at) AND isfinite(not_before) AND notified_at>=created_at
                AND not_before=notified_at+make_interval(secs=>delay_seconds))))
        OR (NOT notification_required AND notified_at IS NULL AND not_before IS NOT NULL
            AND isfinite(not_before) AND not_before=created_at+make_interval(secs=>delay_seconds))
    )
);
CREATE INDEX auth_passkey_recovery_claim_expiry ON auth_passkey_recovery_claims(expires_at);

ALTER TABLE auth_security_notifications ADD COLUMN recovery_claim_id uuid;
ALTER TABLE auth_security_notifications ADD CONSTRAINT auth_notice_recovery_owner
    FOREIGN KEY (realm_id,recovery_claim_id,user_id)
    REFERENCES auth_passkey_recovery_claims(realm_id,id,user_id) ON DELETE CASCADE;
CREATE INDEX auth_notice_recovery_claim ON auth_security_notifications(realm_id,recovery_claim_id)
    WHERE recovery_claim_id IS NOT NULL;
ALTER TABLE auth_security_notifications DROP CONSTRAINT auth_security_notifications_kind_check;
ALTER TABLE auth_security_notifications ADD CONSTRAINT auth_security_notifications_kind_check
    CHECK (kind IN ('password_reset','email_changed','account_deleted','passkeys_changed',
        'passkey_recovery_changed','passkey_recovery_started','passkey_recovery_cancelled'));
ALTER TABLE auth_security_notifications ADD CONSTRAINT auth_notice_recovery_binding CHECK (
    (kind='passkey_recovery_started' AND recovery_claim_id IS NOT NULL AND user_id IS NOT NULL)
    OR (kind<>'passkey_recovery_started' AND recovery_claim_id IS NULL)
);

ALTER TABLE auth_audit ADD COLUMN recovery_claim_id uuid;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_recovery_target CHECK (
    (subject_erased AND recovery_claim_id IS NULL)
    OR (NOT subject_erased AND (
        (kind IN ('passkey_recovery_started','passkey_recovery_cancelled') AND recovery_claim_id IS NOT NULL)
        OR (kind NOT IN ('passkey_recovery_started','passkey_recovery_cancelled') AND recovery_claim_id IS NULL)
    ))
);
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_kind_check;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_kind_check
    CHECK (kind IN ('email_authenticated','session_revoked','password_enrolled',
        'password_authenticated','password_reset','email_changed','email_attached','account_deleted',
        'all_sessions_revoked','passkey_enrolled','passkey_authenticated','passkey_signed_up',
        'passkey_renamed','passkey_removed','passkey_recovery_configured',
        'passkey_recovery_started','passkey_recovery_cancelled'));
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_event_shape;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_event_shape CHECK (
    (schema_version=0 AND actor_session_id IS NULL AND session_id IS NULL)
    OR (schema_version=1 AND (
        subject_erased
        OR (kind IN ('email_authenticated','password_authenticated','passkey_authenticated','passkey_signed_up') AND actor_session_id IS NULL AND session_id IS NOT NULL)
        OR (kind IN ('password_enrolled','email_attached') AND actor_session_id IS NOT NULL AND session_id IS NOT NULL AND actor_session_id<>session_id)
        OR (kind IN ('password_reset','passkey_recovery_started') AND actor_session_id IS NULL AND session_id IS NULL)
        OR (kind='session_revoked' AND actor_session_id IS NOT NULL AND session_id IS NOT NULL)
        OR (kind='passkey_recovery_cancelled' AND session_id IS NULL)
        OR (kind IN ('all_sessions_revoked','email_changed','passkey_enrolled','passkey_renamed','passkey_removed','passkey_recovery_configured') AND actor_session_id IS NOT NULL AND session_id IS NULL)
    ))
);
ALTER TABLE auth_rate_buckets DROP CONSTRAINT auth_rate_buckets_dimension_check;
ALTER TABLE auth_rate_buckets ADD CONSTRAINT auth_rate_buckets_dimension_check
    CHECK (dimension IN ('email','source','password_email','password_source',
        'sensitive_user','sensitive_source',
        'passkey_enroll_user','passkey_enroll_source','passkey_finish_user','passkey_finish_source',
        'passkey_auth_start_browser','passkey_auth_start_source',
        'passkey_auth_finish_browser','passkey_auth_finish_source',
        'passkey_signup_start_browser','passkey_signup_start_source',
        'passkey_signup_finish_browser','passkey_signup_finish_source',
        'passkey_recovery_user','passkey_recovery_source','passkey_recovery_browser'));
