use super::{allow_rotation, token_setup::Tokens};
use auth_core::{Error, IssuerKeyPublication, IssuerSigningKey, IssuerTokenIssuer};
use josekit::{
    jwk::{Jwk, KeyPair},
    jws::{self, RS256},
};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

#[sqlx::test]
async fn actual_sequential_tokens_follow_explicit_rotation_and_both_public_keys_remain_verifiable(
    pool: PgPool,
) {
    let f = Tokens::new(pool).await;
    let pair = RS256.generate_key_pair(2048).unwrap();
    let replacement = Arc::new(
        IssuerSigningKey::from_pkcs8_pem(
            Uuid::new_v4(),
            String::from_utf8(pair.to_pem_private_key()).unwrap(),
        )
        .unwrap(),
    );
    let old = f.store.load_issuer_signing(&f.authority).await.unwrap();
    let old = old.publication();
    let publication = IssuerKeyPublication::new(
        f.authority.clone(),
        replacement.public_key().unwrap(),
        old.sign_from_us(),
        old.sign_until_us(),
        old.verify_until_us(),
    )
    .unwrap();
    f.store.publish_issuer_key(&publication).await.unwrap();
    assert!(matches!(
        f.store
            .activate_issuer_key(&f.authority, replacement.id())
            .await,
        Err(Error::Unauthorized)
    ));
    let service = IssuerTokenIssuer::new(
        f.authority.clone(),
        f.store.clone(),
        vec![f.key.clone(), replacement.clone()],
    )
    .unwrap();
    let first = service
        .exchange(
            &f.authentication(),
            &f.code().await,
            "https://app.example/cb",
            &f.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
    // Accelerate only the persisted propagation deadline in the isolated test
    // database. The production API has no caller-supplied propagation bypass.
    allow_rotation(&f.pool, &publication).await;
    f.store
        .activate_issuer_key(&f.authority, replacement.id())
        .await
        .unwrap();
    let second = service
        .exchange(
            &f.authentication(),
            &f.code().await,
            "https://app.example/cb",
            &f.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
    let published = f.store.issuer_public_keys(&f.authority).await.unwrap();
    assert_eq!(published.len(), 2);
    for (token, expected) in [
        (first.id_token(), f.key.id()),
        (second.id_token(), replacement.id()),
    ] {
        let key = published.iter().find(|key| key.id() == expected).unwrap();
        let jwk = Jwk::from_bytes(serde_json::to_vec(key.document()).unwrap()).unwrap();
        let verifier = RS256.verifier_from_jwk(&jwk).unwrap();
        let verified = jws::deserialize_compact(token, &verifier);
        assert!(
            verified.is_ok(),
            "unaltered production token must verify using its overlapping published key"
        );
        let (_, header) = verified.unwrap();
        assert_eq!(header.key_id(), Some(expected.to_string().as_str()));
    }
    let old_jwk =
        Jwk::from_bytes(serde_json::to_vec(f.key.public_key().unwrap().document()).unwrap())
            .unwrap();
    assert!(
        jws::deserialize_compact(
            second.id_token(),
            &RS256.verifier_from_jwk(&old_jwk).unwrap()
        )
        .is_err()
    );
    assert_eq!(f.facts().await, (1, 1, 2, 2));
    f.store
        .disable_issuer_key(&f.authority, f.key.id())
        .await
        .unwrap();
    let remaining = f.store.issuer_public_keys(&f.authority).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id(), replacement.id());
    assert_eq!(
        f.store
            .load_issuer_signing(&f.authority)
            .await
            .unwrap()
            .publication()
            .key()
            .id(),
        replacement.id()
    );
}
