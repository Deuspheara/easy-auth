//! Persisted protocol state expiry; these fixtures do not construct verified identities.
use super::keeping;
use crate::support::realm;
use auth_core::{RetentionCategory, RetentionRepository};
use sqlx::PgPool;
use uuid::Uuid;

async fn state(pool: &PgPool, realm: Uuid, source: Uuid, client: Uuid) {
    let redirect = format!("https://rp.example.test/{realm}/return");
    sqlx::query("INSERT INTO auth_oauth_connections(realm_id,id,client_id,revision,issuer,provider_client,redirect_uri,defense,enabled) VALUES($1,$2,$3,gen_random_uuid(),'https://issuer.example.test','owned-client',$4,'dedicated_redirect',true)")
        .bind(realm).bind(source).bind(client).bind(&redirect).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO auth_oauth_transactions(realm_id,connection_id,client_id,revision,state_hash,browser_hash,nonce_hash,pkce_hash,purpose,created_at,expires_at,redirect_uri) SELECT realm_id,id,client_id,revision,sha256(convert_to(gen_random_uuid()::text,'UTF8')),decode(repeat('01',32),'hex'),decode(repeat('02',32),'hex'),decode(repeat('03',32),'hex'),'sign_in',statement_timestamp()-interval '3 minutes',statement_timestamp()+make_interval(secs=>seconds),redirect_uri FROM auth_oauth_connections CROSS JOIN (VALUES(-60),(60)) AS cases(seconds) WHERE realm_id=$1 AND id=$2")
        .bind(realm).bind(source).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO auth_saml_registrations(realm_id,id,client_id,revision,sp_entity,idp_entity,sso_url,acs_url) VALUES($1,$2,$3,gen_random_uuid(),'https://sp.example.test','https://idp.example.test','https://idp.example.test/sso','https://rp.example.test/acs')")
        .bind(realm).bind(source).bind(client).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO auth_saml_requests(realm_id,connection_id,client_id,revision,request_id,relay_hash,browser_hash,created_at,expires_at) SELECT realm_id,id,client_id,revision,'_'||replace(gen_random_uuid()::text,'-',''),sha256(convert_to(gen_random_uuid()::text,'UTF8')),decode(repeat('01',32),'hex'),statement_timestamp()-interval '3 minutes',statement_timestamp()+make_interval(secs=>seconds) FROM auth_saml_registrations CROSS JOIN (VALUES(-60),(60)) AS cases(seconds) WHERE realm_id=$1 AND id=$2")
        .bind(realm).bind(source).execute(pool).await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn expired_oauth_and_saml_state_is_pruned_without_configuration_or_realm_changes(
    pool: PgPool,
) {
    let (store, a) = realm(pool.clone()).await;
    let b = Uuid::new_v4();
    store.ensure_realm(b).await.unwrap();
    let source = Uuid::new_v4();
    let client = Uuid::new_v4();
    state(&pool, a, source, client).await;
    state(&pool, b, source, client).await;
    for (category, table, configuration) in [
        (
            RetentionCategory::OAuthTransactions,
            "auth_oauth_transactions",
            "auth_oauth_connections",
        ),
        (
            RetentionCategory::SamlRequests,
            "auth_saml_requests",
            "auth_saml_registrations",
        ),
    ] {
        assert_eq!(
            store
                .retain_batch(a, category, keeping())
                .await
                .unwrap()
                .deleted,
            1
        );
        let count = format!("SELECT count(*) FROM {table} WHERE realm_id=$1");
        let selected: i64 = sqlx::query_scalar(&count)
            .bind(a)
            .fetch_one(&pool)
            .await
            .unwrap();
        let foreign: i64 = sqlx::query_scalar(&count)
            .bind(b)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!((selected, foreign), (1, 2));
        let enabled = format!("SELECT count(*) FROM {configuration} WHERE enabled");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(&enabled)
                .fetch_one(&pool)
                .await
                .unwrap(),
            2
        );
    }
}
