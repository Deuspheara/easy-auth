mod configuration;
mod migration;
mod publication;

use auth_core::{
    Error, ISSUER_KEY_PROPAGATION_SECONDS, IssuerAuthority, IssuerKeyPublication, IssuerPublicKey,
    IssuerSigningKey,
};
use easy_auth_postgres::Postgres;
use josekit::{jwk::KeyPair, jws::RS256};
use sqlx::PgPool;
use uuid::Uuid;

async fn setup(pool: &PgPool) -> (Postgres, IssuerAuthority, IssuerKeyPublication) {
    let (store, realm) = crate::support::realm(pool.clone()).await;
    let authority = IssuerAuthority::new(realm, "https://issuer.example").unwrap();
    let publication = publication(pool, &authority).await;
    (store, authority, publication)
}
async fn publication(pool: &PgPool, authority: &IssuerAuthority) -> IssuerKeyPublication {
    // Ordinary unchanged library generation, not hostile/signature test material.
    let pair = RS256.generate_key_pair(2048).unwrap();
    let pem = String::from_utf8(pair.to_pem_private_key()).unwrap();
    let public = IssuerSigningKey::from_pkcs8_pem(Uuid::new_v4(), pem)
        .unwrap()
        .public_key()
        .unwrap();
    let now: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(pool)
            .await
            .unwrap();
    IssuerKeyPublication::new(
        authority.clone(),
        public,
        now - 1_000_000,
        now + 3_600_000_000,
        now + 3_900_000_000,
    )
    .unwrap()
}
fn alias(original: &IssuerKeyPublication) -> IssuerKeyPublication {
    // Reuse one valid ordinary public key with a distinct operator identifier.
    // Quota/realm tests need no new signatures or repeated key generation.
    let mut value = original.key().document().clone();
    value["kid"] = serde_json::json!(Uuid::new_v4());
    let key = IssuerPublicKey::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    IssuerKeyPublication::new(
        original.authority().clone(),
        key,
        original.sign_from_us(),
        original.sign_until_us(),
        original.verify_until_us(),
    )
    .unwrap()
}
async fn allow_rotation(pool: &PgPool, input: &IssuerKeyPublication) {
    sqlx::query("UPDATE auth_issuer_keys SET ready_at_us=ready_at_us-$4 WHERE realm_id=$1 AND issuer=$2 AND id=$3")
        .bind(input.authority().realm()).bind(input.authority().issuer()).bind(input.key().id()).bind(ISSUER_KEY_PROPAGATION_SECONDS*1_000_000)
        .execute(pool).await.unwrap();
}
mod commit_probe;
mod final_policy;
mod ledger_migration;
mod rollover;
use crate::support::issuer_tokens as token_setup;
#[cfg(feature = "issuer-token-management")]
mod token_status;
mod tokens;
