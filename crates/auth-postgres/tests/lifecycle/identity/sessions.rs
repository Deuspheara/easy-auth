use super::Fixture;
use auth_core::{AuthenticationPolicy, Error, Repository};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn email_free_identity_keeps_owned_session_controls_and_null_contact(pool: PgPool) {
    let f = Fixture::new(pool.clone(), None).await;
    let (current, _) = f.session("passkey").await;
    let (other, other_id) = f.session("passkey").await;
    let (_weak, _) = f.session("email").await;
    let user = f
        .store
        .authenticate(f.realm, current.verifier())
        .await
        .unwrap();
    assert_eq!(user.id, f.user);
    assert_eq!(user.realm_id, f.realm);
    assert_eq!(user.email, None);
    assert_eq!(user.display_name.as_deref(), Some("Example person"));
    assert_eq!(
        user.authentication_policy,
        AuthenticationPolicy::PasskeyRequired
    );
    let page = f
        .store
        .list_sessions(f.realm, current.verifier(), None)
        .await
        .unwrap();
    assert_eq!(page.sessions.len(), 2);
    let other_realm = Uuid::new_v4();
    f.store.ensure_realm(other_realm).await.unwrap();
    assert!(matches!(
        f.store.authenticate(other_realm, current.verifier()).await,
        Err(Error::Unauthorized)
    ));
    assert!(
        !f.store
            .revoke_session(f.realm, current.verifier(), other_id)
            .await
            .unwrap()
    );
    assert!(
        f.store
            .authenticate(f.realm, other.verifier())
            .await
            .is_err()
    );
    f.store
        .revoke_all_sessions(f.realm, current.verifier())
        .await
        .unwrap();
    assert!(
        f.store
            .authenticate(f.realm, current.verifier())
            .await
            .is_err()
    );
    let audits: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind IN ('session_revoked','all_sessions_revoked')")
        .bind(f.realm).fetch_one(&pool).await.unwrap();
    assert_eq!(audits, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn stronger_accounts_reject_weak_methods_and_stale_passkey_actions(pool: PgPool) {
    for email in [None, Some("alice@example.com")] {
        let f = Fixture::new(pool.clone(), email).await;
        for method in ["email", "password", "legacy_unknown"] {
            let (weak, _) = f.session(method).await;
            assert!(matches!(
                f.store.authenticate(f.realm, weak.verifier()).await,
                Err(Error::Unauthorized)
            ));
            assert!(matches!(
                f.store.list_sessions(f.realm, weak.verifier(), None).await,
                Err(Error::Unauthorized)
            ));
            assert!(matches!(
                f.store.revoke_all_sessions(f.realm, weak.verifier()).await,
                Err(Error::Unauthorized)
            ));
            // Logout can always dispose of the caller's own bearer.
            f.store.revoke(f.realm, weak.verifier()).await.unwrap();
        }
        let (current, _) = f.session("passkey").await;
        sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1")
            .bind(current.verifier().as_slice()).execute(&pool).await.unwrap();
        assert!(
            f.store
                .authenticate(f.realm, current.verifier())
                .await
                .is_ok()
        );
        assert!(matches!(
            f.store
                .revoke_all_sessions(f.realm, current.verifier())
                .await,
            Err(Error::Unauthorized)
        ));
    }
}
