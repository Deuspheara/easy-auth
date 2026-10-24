use super::*;
use auth_core::{IssuerAuthority, IssuerKeyPublication, IssuerSigningKey};
use josekit::{jwk::KeyPair, jws::RS256};
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

fn normal_key(id: Uuid) -> Arc<IssuerSigningKey> {
    let pair = RS256.generate_key_pair(2048).unwrap();
    let pem = Zeroizing::new(pair.to_pem_private_key());
    Arc::new(
        IssuerSigningKey::from_pkcs8_pem(id, String::from_utf8(pem.to_vec()).unwrap()).unwrap(),
    )
}
fn prepared(authority: &IssuerAuthority, key: Arc<IssuerSigningKey>) -> Prepared {
    Prepared {
        authority: authority.clone(),
        key,
        introspection: false,
    }
}
#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn startup_requires_current_exact_realm_public_key_without_provisioning_or_enable_writes(
    pool: PgPool,
) {
    let repository = Arc::new(Postgres::new(pool.clone()));
    let realm = Uuid::new_v4();
    repository.ensure_realm(realm).await.unwrap();
    let authority = IssuerAuthority::new(realm, "https://issuer.example").unwrap();
    let key = normal_key(Uuid::new_v4());
    assert!(
        services(repository.clone(), prepared(&authority, key.clone()))
            .await
            .is_err()
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_issuer_key_sets WHERE realm_id=$1")
            .bind(realm)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0, "startup does not provision a missing registry");
    let now: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&pool)
            .await
            .unwrap();
    repository
        .publish_issuer_key(
            &IssuerKeyPublication::new(
                authority.clone(),
                key.public_key().unwrap(),
                now - 1_000_000,
                now + 3_600_000_000,
                now + 3_900_000_000,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let revision = repository
        .activate_issuer_key(&authority, key.id())
        .await
        .unwrap();
    assert!(
        services(repository.clone(), prepared(&authority, key.clone()))
            .await
            .is_err(),
        "startup cannot enable a disabled registry"
    );
    repository
        .enable_issuer_signing(&authority, revision)
        .await
        .unwrap();
    assert!(
        services(repository.clone(), prepared(&authority, key.clone()))
            .await
            .is_ok()
    );
    let after = repository.load_issuer_signing(&authority).await.unwrap();
    assert_eq!(
        after.revision(),
        revision,
        "composition makes no registration change"
    );
    // Another ordinary operator key with the same public ID is not a match.
    assert!(
        services(
            repository.clone(),
            prepared(&authority, normal_key(key.id()))
        )
        .await
        .is_err()
    );
    let foreign = Uuid::new_v4();
    repository.ensure_realm(foreign).await.unwrap();
    let other = IssuerAuthority::new(foreign, authority.issuer()).unwrap();
    assert!(
        services(repository.clone(), prepared(&other, key.clone()))
            .await
            .is_err()
    );
    let another = IssuerAuthority::new(realm, "https://other.example").unwrap();
    assert!(
        services(repository.clone(), prepared(&another, key.clone()))
            .await
            .is_err()
    );
    repository
        .disable_issuer_key(&authority, key.id())
        .await
        .unwrap();
    assert!(
        services(repository.clone(), prepared(&authority, key))
            .await
            .is_err()
    );
}
