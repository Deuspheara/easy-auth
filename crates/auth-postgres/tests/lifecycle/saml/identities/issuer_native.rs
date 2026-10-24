use super::setup::{allow_jit, fixture, verify};
use auth_core::*;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test]
async fn genuine_saml_native_grant_keeps_signed_authentication_and_rechecks_registration_without_cookie_extension(
    pool: PgPool,
) {
    let (mut f, policy) = fixture(pool.clone()).await;
    let policy = allow_jit(&mut f, &policy).await;
    // The unchanged normal IdP producer/verifier and real identity commit only.
    let (user, current) = SamlSignIn::new(f.store.clone())
        .finish(policy.map(verify(&f, "normal").await).unwrap())
        .await
        .unwrap();
    let auth_time:i64=sqlx::query_scalar("SELECT (extract(epoch FROM authenticated_at)*1000000)::bigint FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2").bind(user.realm_id).bind(current.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
    let base = crate::support::issuer_tokens::Tokens::for_session(
        pool,
        f.store.clone(),
        user.realm_id,
        current,
    )
    .await;
    let native =
        crate::support::issuer_native_families::Fixture::for_base(base, Uuid::new_v4()).await;
    let consumer = crate::support::issuer_native_consumers::Consumer::new(&native).await;
    consumer.enable(&native).await;
    let code = native.code().await;
    let initial = native.exchange(&code).await.unwrap();
    assert!(
        consumer
            .inspect(&native, initial.access_token())
            .await
            .unwrap()
            .is_some()
    );
    sqlx::query("UPDATE auth_sessions SET last_seen_at=clock_timestamp()-interval '31 minutes' WHERE realm_id=$1 AND user_id=$2").bind(user.realm_id).bind(user.id).execute(&f.pool).await.unwrap();
    assert!(
        f.store
            .authenticate(user.realm_id, native.base.current.verifier())
            .await
            .is_err()
    );
    let next = native
        .refresher()
        .refresh(
            &native.authentication(),
            &initial.refresh_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert!(
        consumer
            .inspect(&native, next.access_token())
            .await
            .unwrap()
            .is_some()
    );
    let facts:(String,i64,bool)=sqlx::query_as("SELECT authentication_method,authenticated_at_us,generation=1 FROM auth_issuer_native_families WHERE realm_id=$1").bind(user.realm_id).fetch_one(&f.pool).await.unwrap();
    assert_eq!(facts, ("saml".into(), auth_time, true));
    assert!(sqlx::query_scalar::<_,bool>("SELECT last_seen_at<clock_timestamp()-interval '30 minutes' FROM auth_sessions WHERE realm_id=$1 AND user_id=$2").bind(user.realm_id).bind(user.id).fetch_one(&f.pool).await.unwrap());
    f.store
        .disable_saml_registration(
            user.realm_id,
            f.registration.connection(),
            f.registration.client(),
        )
        .await
        .unwrap();
    assert!(matches!(
        native
            .refresher()
            .refresh(
                &native.authentication(),
                &next.refresh_token().into(),
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    assert!(
        consumer
            .inspect(&native, next.access_token())
            .await
            .unwrap()
            .is_none()
    );
    native
        .refresher()
        .revoke(
            &native.authentication(),
            &next.refresh_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT revoked_at_us IS NOT NULL FROM auth_issuer_native_families WHERE realm_id=$1"
        )
        .bind(user.realm_id)
        .fetch_one(&f.pool)
        .await
        .unwrap()
    );
}
