use super::setup::Fixture;
use crate::support::signed_in;
use auth_core::{Error, OAuthPurpose, OAuthTransactionRepository, Repository, Secret};
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn signed_in_owner(f: &Fixture) -> (Uuid, Secret) {
    let session = signed_in(&f.store, f.connection.realm(), "oauth-owner@example.test").await;
    let user = f
        .store
        .authenticate(f.connection.realm(), session.verifier())
        .await
        .unwrap()
        .id;
    (user, session)
}

#[sqlx::test(migrations = "./migrations")]
async fn linking_binds_original_owned_session_and_rechecks_revocation(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (user, session) = signed_in_owner(&f).await;
    let purpose = OAuthPurpose::Link {
        user,
        session: session.verifier(),
    };
    let start = f.flow.begin(&f.intent(purpose.clone())).await.unwrap();
    let other = signed_in(&f.store, f.connection.realm(), "other@example.test").await;
    for wrong in [
        OAuthPurpose::SignIn,
        OAuthPurpose::Link {
            user,
            session: other.verifier(),
        },
        OAuthPurpose::Link {
            user: Uuid::new_v4(),
            session: session.verifier(),
        },
    ] {
        assert!(matches!(
            f.store.consume_oauth(&f.request(&start, wrong)).await,
            Err(Error::Unauthorized)
        ));
    }
    f.store
        .revoke(f.connection.realm(), session.verifier())
        .await
        .unwrap();
    assert!(matches!(
        f.store.consume_oauth(&f.request(&start, purpose)).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.pending().await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn stale_session_cannot_begin_or_consume_link_intent(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (user, session) = signed_in_owner(&f).await;
    let purpose = OAuthPurpose::Link {
        user,
        session: session.verifier(),
    };
    let start = f.flow.begin(&f.intent(purpose.clone())).await.unwrap();
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '6 minutes' WHERE realm_id=$1")
        .bind(f.connection.realm()).execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.flow.begin(&f.intent(purpose.clone())).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.store.consume_oauth(&f.request(&start, purpose)).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.pending().await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn stronger_account_link_intent_reuses_method_policy_without_creating_identity(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let user = Uuid::new_v4();
    sqlx::query("INSERT INTO auth_users(realm_id,id,email_verified_at,display_name,authentication_policy) VALUES ($1,$2,NULL,'Storage policy fixture','passkey_required')")
        .bind(f.connection.realm()).bind(user).execute(&f.pool).await.unwrap();
    // Storage-policy fixtures only; these rows are not native passkey evidence.
    for method in ["email", "password", "legacy_unknown", "passkey"] {
        let session = Secret::generate().unwrap();
        sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method) VALUES ($1,$2,$3,$4,$5)")
            .bind(f.connection.realm()).bind(Uuid::new_v4()).bind(user).bind(session.verifier().as_slice())
            .bind(method).execute(&f.pool).await.unwrap();
        let purpose = OAuthPurpose::Link {
            user,
            session: session.verifier(),
        };
        let result = f.flow.begin(&f.intent(purpose.clone())).await;
        if method == "passkey" {
            let start = result.unwrap();
            f.store
                .consume_oauth(&f.request(&start, purpose))
                .await
                .unwrap();
        } else {
            assert!(matches!(result, Err(Error::Unauthorized)));
        }
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_users")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(f.pending().await, 0);
}
