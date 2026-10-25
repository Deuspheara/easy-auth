use super::setup::Fixture;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test]
async fn genuine_oidc_native_grant_keeps_original_authentication_without_cookie_idle_and_requires_current_source(
    pool: PgPool,
) {
    let f = Fixture::new(pool.clone(), OidcJitPolicy::Allow).await;
    let auth_time = f.now_seconds().await;
    let (user, current) = f
        .sign_in
        .finish(
            f.mapped("native-owner", json!({"auth_time":auth_time}))
                .await,
        )
        .await
        .unwrap();
    let base = crate::support::issuer_tokens::Tokens::for_session(
        pool,
        f.store.clone(),
        f.realm(),
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
    sqlx::query("UPDATE auth_sessions SET last_seen_at=clock_timestamp()-interval '31 minutes' WHERE realm_id=$1 AND user_id=$2").bind(f.realm()).bind(user.id).execute(&f.pool).await.unwrap();
    assert!(
        f.store
            .authenticate(f.realm(), native.base.current.verifier())
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
    let facts:(String,i64,bool)=sqlx::query_as("SELECT authentication_method,authenticated_at_us,generation=1 FROM auth_issuer_native_families WHERE realm_id=$1").bind(f.realm()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(facts, ("oidc".into(), auth_time * 1000000, true));
    assert!(sqlx::query_scalar::<_,bool>("SELECT last_seen_at<clock_timestamp()-interval '30 minutes' FROM auth_sessions WHERE realm_id=$1 AND user_id=$2").bind(f.realm()).bind(user.id).fetch_one(&f.pool).await.unwrap());
    sqlx::query(
        "UPDATE auth_users SET authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2",
    )
    .bind(f.realm())
    .bind(user.id)
    .execute(&f.pool)
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
    sqlx::query("UPDATE auth_users SET authentication_policy='provider_required' WHERE realm_id=$1 AND id=$2").bind(f.realm()).bind(user.id).execute(&f.pool).await.unwrap();
    let config = f.policy.configuration();
    f.store
        .disable_oauth_connection(f.realm(), config.connection(), config.client())
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
        .bind(f.realm())
        .fetch_one(&f.pool)
        .await
        .unwrap()
    );
}
