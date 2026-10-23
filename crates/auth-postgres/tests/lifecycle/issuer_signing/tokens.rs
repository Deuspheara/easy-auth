use super::token_setup::Tokens;
use auth_core::{Error, IssuerTokenError, Repository};
use josekit::{
    jwk::Jwk,
    jws::{self, RS256},
};
use sqlx::PgPool;

#[sqlx::test]
async fn concrete_rs256_tokens_commit_once_with_exact_claims_and_hash_only_access(pool: PgPool) {
    let f = Tokens::new(pool).await;
    let code = f.code().await;
    let service = f.service();
    let response = service
        .exchange(
            &f.authentication(),
            &code,
            "https://app.example/cb",
            &f.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert_eq!(format!("{response:?}"), "IssuerTokens([REDACTED])");
    assert!(response.expires_in() > 0 && response.expires_in() <= 60);
    let public = f.key.public_key().unwrap();
    let jwk = Jwk::from_bytes(serde_json::to_vec(public.document()).unwrap()).unwrap();
    let verifier = RS256.verifier_from_jwk(&jwk).unwrap();
    let verified = jws::deserialize_compact(response.id_token(), &verifier);
    assert!(
        verified.is_ok(),
        "ordinary production-issued token must verify with the published public key"
    );
    let (payload, header) = verified.unwrap();
    assert_eq!(header.algorithm(), Some("RS256"));
    assert_eq!(header.key_id(), Some(f.key.id().to_string().as_str()));
    let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(claims["iss"], f.authority.issuer());
    assert_eq!(claims["aud"], f.client.client().to_string());
    assert_eq!(claims["nonce"], "client-nonce");
    assert_ne!(claims["sub"], f.owner.to_string());
    let auth_time:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM authenticated_at))::bigint FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
        .bind(f.authority.realm()).bind(f.current.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(claims["auth_time"], auth_time);
    let correct:bool=sqlx::query_scalar("SELECT access_hash=$2 AND subject::text=$3 AND key_id=$4 AND expires_at_us=$5 FROM auth_issuer_access_tokens WHERE realm_id=$1")
        .bind(f.authority.realm()).bind(response.access_token().verifier().as_slice()).bind(claims["sub"].as_str().unwrap())
        .bind(f.key.id()).bind(claims["exp"].as_i64().unwrap()*1_000_000).fetch_one(&f.pool).await.unwrap();
    assert!(correct);
    assert!(matches!(
        f.store
            .authenticate(f.authority.realm(), response.access_token().verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (1, 1, 1, 1));
    assert!(matches!(
        service
            .exchange(
                &f.authentication(),
                &code,
                "https://app.example/cb",
                &f.pkce,
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    assert_eq!(f.facts().await, (1, 1, 1, 1));
}

#[sqlx::test]
async fn missing_current_private_key_never_selects_a_different_signer_or_consumes_code(
    pool: PgPool,
) {
    let f = Tokens::new(pool).await;
    let code = f.code().await;
    let other = josekit::jws::RS256.generate_key_pair(2048).unwrap();
    use josekit::jwk::KeyPair;
    let key = std::sync::Arc::new(
        auth_core::IssuerSigningKey::from_pkcs8_pem(
            uuid::Uuid::new_v4(),
            String::from_utf8(other.to_pem_private_key()).unwrap(),
        )
        .unwrap(),
    );
    let wrong =
        auth_core::IssuerTokenIssuer::new(f.authority.clone(), f.store.clone(), vec![key]).unwrap();
    assert!(matches!(
        wrong
            .exchange(
                &f.authentication(),
                &code,
                "https://app.example/cb",
                &f.pkce,
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::Unavailable)
    ));
    assert_eq!(f.facts().await, (1, 1, 0, 0));
    f.service()
        .exchange(
            &f.authentication(),
            &code,
            "https://app.example/cb",
            &f.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert_eq!(f.facts().await, (1, 1, 1, 1));
}

#[sqlx::test]
async fn final_audit_failure_rolls_back_access_code_and_scrubbing_before_retry(pool: PgPool) {
    let f = Tokens::new(pool).await;
    let code = f.code().await;
    sqlx::query("ALTER TABLE auth_audit ADD CONSTRAINT test_signed_audit_failure CHECK(kind<>'issuer_code_redeemed')").execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.service()
            .exchange(
                &f.authentication(),
                &code,
                "https://app.example/cb",
                &f.pkce,
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::Unavailable)
    ));
    assert_eq!(f.facts().await, (1, 1, 0, 0));
    let original:bool=sqlx::query_scalar("SELECT status='approved' AND nonce IS NOT NULL AND state IS NOT NULL AND pkce_challenge IS NOT NULL FROM auth_issuer_authorizations WHERE realm_id=$1")
        .bind(f.authority.realm()).fetch_one(&f.pool).await.unwrap();
    assert!(original);
    sqlx::query("ALTER TABLE auth_audit DROP CONSTRAINT test_signed_audit_failure")
        .execute(&f.pool)
        .await
        .unwrap();
    f.service()
        .exchange(
            &f.authentication(),
            &code,
            "https://app.example/cb",
            &f.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert_eq!(f.facts().await, (1, 1, 1, 1));
}
