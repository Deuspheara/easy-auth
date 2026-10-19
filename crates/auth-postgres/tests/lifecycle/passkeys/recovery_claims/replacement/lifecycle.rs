use super::*;
use auth_core::{AuthenticationPolicy, PasskeySignIn};

#[sqlx::test(migrations = "./migrations")]
async fn recovery_requires_candidate_assertion_then_atomically_replaces_keys_and_sessions(
    pool: PgPool,
) {
    for email_free in [false, true] {
        let mut f = Replacement::new(pool.clone(), email_free).await;
        f.mature().await;
        let old_keys: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT credential_id FROM auth_passkeys WHERE realm_id=$1")
                .bind(f.c.f.realm)
                .fetch_all(&pool)
                .await
                .unwrap();
        // Simulate lost-key owners with no remaining live session. Neither the
        // claim nor replacement service accepts a prior session as authority.
        sqlx::query("UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1 AND revoked_at IS NULL")
            .bind(f.c.f.realm).execute(&pool).await.unwrap();
        let (id, response) = f.assertion().await;
        let before = f.c.snapshot().await;
        let session = f
            .flow
            .finish(f.target, id, &f.c.browser, SOURCE, &response)
            .await
            .unwrap();
        let user =
            f.c.f
                .store
                .authenticate(f.c.f.realm, session.verifier())
                .await
                .unwrap();
        assert_eq!(user.id, f.c.owner);
        assert_eq!(
            user.authentication_policy,
            if email_free {
                AuthenticationPolicy::PasskeyRequired
            } else {
                AuthenticationPolicy::Mailbox
            }
        );
        assert!(matches!(
            f.c.f
                .store
                .authenticate(f.c.f.realm, f.c.f.session.verifier())
                .await,
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            f.c.f
                .store
                .authenticate(f.c.f.realm, f.c.weak.verifier())
                .await,
            Err(Error::Unauthorized)
        ));
        let rows:Vec<(Vec<u8>,bool)>=sqlx::query_as("SELECT credential_id,last_used_at IS NOT NULL FROM auth_passkeys WHERE realm_id=$1 AND user_id=$2")
            .bind(f.c.f.realm).bind(f.c.owner).fetch_all(&pool).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].1 && !old_keys.contains(&rows[0].0));
        let facts:(i64,i64,i64,bool)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND user_id=$2 AND kind='passkey_recovered' AND actor_session_id IS NULL AND session_id IS NOT NULL AND recovery_claim_id=$3),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1 AND user_id=$2 AND revoked_at IS NULL AND authentication_method='passkey'),(SELECT count(*) FROM auth_passkey_recovery_replacements WHERE realm_id=$1),(SELECT consumed_at IS NOT NULL FROM auth_passkey_recovery_codes WHERE realm_id=$1 AND user_id=$2)")
            .bind(f.c.f.realm).bind(f.c.owner).bind(f.target.claim_id).fetch_one(&pool).await.unwrap();
        assert_eq!(facts, (1, 1, 0, true));
        assert!(before != f.c.snapshot().await);
        let done = f.c.snapshot().await;
        assert!(matches!(
            f.flow
                .finish(f.target, id, &f.c.browser, SOURCE, &response)
                .await,
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            f.c.flow.resume(f.c.owner, &f.c.browser, SOURCE).await,
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            f.c.flow
                .cancel_with_code(f.c.owner, &f.c.code, SOURCE)
                .await,
            Err(Error::Unauthorized)
        ));
        f.c.unchanged(done).await;
        // Loss of the finish response needs no replay grant: actual normal sign-in
        // with the installed key works and preserves the same account.
        let signin = PasskeySignIn::new(f.c.f.realm, f.c.f.service.clone(), f.c.f.store.clone());
        let next = signin
            .begin_account(f.c.owner, &f.c.browser, "signin-after-recovery")
            .await
            .unwrap();
        let signed = f
            .token
            .perform_auth(ORIGIN.parse().unwrap(), next.options.public_key, 120_000)
            .unwrap();
        let recovered = signin
            .finish(
                &f.c.browser,
                "signin-after-recovery",
                next.transaction,
                &signed,
            )
            .await
            .unwrap();
        assert_eq!(
            f.c.f
                .store
                .authenticate(f.c.f.realm, recovered.verifier())
                .await
                .unwrap()
                .id,
            f.c.owner
        );
        let notices: Vec<String> =
            sqlx::query_scalar("SELECT kind FROM auth_security_notifications WHERE realm_id=$1")
                .bind(f.c.f.realm)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            notices,
            if email_free {
                vec![]
            } else {
                vec!["passkey_recovery_completed".to_owned()]
            }
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn before_delay_or_receipt_no_private_candidate_or_session_is_created(pool: PgPool) {
    for email_free in [false, true] {
        let f = Replacement::new(pool.clone(), email_free).await;
        let before = f.c.snapshot().await;
        assert!(matches!(
            f.flow.begin(f.target, &f.c.browser, SOURCE).await,
            Err(Error::Unauthorized)
        ));
        f.c.unchanged(before).await;
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn registration_alone_does_not_change_sessions_or_publish_a_candidate(pool: PgPool) {
    let mut f = Replacement::new(pool.clone(), true).await;
    f.mature().await;
    let old: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT credential_id FROM auth_passkeys WHERE realm_id=$1")
            .bind(f.c.f.realm)
            .fetch_all(&pool)
            .await
            .unwrap();
    let (id, response) = f.assertion().await;
    let keys: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT credential_id FROM auth_passkeys WHERE realm_id=$1")
            .bind(f.c.f.realm)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(old, keys);
    let signin = PasskeySignIn::new(f.c.f.realm, f.c.f.service.clone(), f.c.f.store.clone());
    let pending = signin
        .begin_account(f.c.owner, &f.c.browser, "ordinary")
        .await
        .unwrap();
    assert!(matches!(
        signin
            .finish(&f.c.browser, "ordinary", pending.transaction, &response)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(
        f.c.f
            .store
            .authenticate(f.c.f.realm, f.c.f.session.verifier())
            .await
            .is_ok()
    );
    assert!(
        f.c.f
            .store
            .load_recovery_assertion(&f.request(id))
            .await
            .is_ok()
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_recovered'",
    )
    .bind(f.c.f.realm)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
}
