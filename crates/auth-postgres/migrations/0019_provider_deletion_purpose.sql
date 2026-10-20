-- A deletion exchange remains distinct from sign-in/linking and grants no action
-- without final verified provider identity, original session and fresh auth_time.
ALTER TABLE auth_oauth_transactions
    DROP CONSTRAINT auth_oauth_transactions_purpose_check,
    DROP CONSTRAINT auth_oauth_transactions_check;
ALTER TABLE auth_oauth_transactions
    ADD CONSTRAINT auth_oauth_transactions_purpose_check
        CHECK (purpose IN ('sign_in','link','delete_provider_account')),
    ADD CONSTRAINT auth_oauth_transactions_owner_binding
        CHECK ((purpose='sign_in' AND user_id IS NULL AND session_id IS NULL)
            OR (purpose IN ('link','delete_provider_account')
                AND user_id IS NOT NULL AND session_id IS NOT NULL));
