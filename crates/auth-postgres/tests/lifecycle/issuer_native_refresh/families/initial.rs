use super::*;
use auth_core::{IssuerTokenError, Repository};
use josekit::{jws::RS256, jwt};

#[sqlx::test]
async fn genuine_native_code_issues_exact_signed_identity_and_hash_only_bounded_family_once(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let code = f.code().await;
    let issued = f.exchange(&code).await.unwrap();
    assert_eq!(f.facts().await, (1, 1, 1, 1, 1));
    assert!(issued.expires_in() > 0 && issued.expires_in() <= 60);
    assert!(
        issued.refresh_expires_in() > issued.expires_in() && issued.refresh_expires_in() <= 3600
    );
    assert_ne!(
        issued.access_token().verifier(),
        issued.refresh_token().verifier()
    );
    assert!(!format!("{issued:?}").contains(issued.refresh_token().expose()));
    let jwk = josekit::jwk::Jwk::from_bytes(
        serde_json::to_vec(f.base.key.public_key().unwrap().document()).unwrap(),
    )
    .unwrap();
    let verifier = RS256.verifier_from_jwk(&jwk).unwrap();
    let (claims, header) = jwt::decode_with_verifier(issued.id_token(), &verifier).unwrap();
    assert_eq!(header.algorithm(), Some("RS256"));
    assert_eq!(claims.issuer(), Some(f.base.authority.issuer()));
    assert_eq!(
        claims.audience(),
        Some(vec![f.policy.client().client().to_string().as_str()])
    );
    assert_eq!(
        claims.claim("nonce").unwrap().as_str(),
        Some("native-owned-nonce")
    );
    assert!(claims.claim("email").is_none());
    assert_ne!(
        claims.claim("sub").unwrap().as_str(),
        Some(f.base.owner.to_string().as_str())
    );
    let auth_time:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM authenticated_at))::bigint FROM auth_sessions WHERE realm_id=$1 AND id=(SELECT session_id FROM auth_issuer_native_families WHERE realm_id=$1)")
        .bind(f.base.authority.realm()).fetch_one(&f.base.pool).await.unwrap();
    assert_eq!(claims.claim("auth_time").unwrap().as_i64(), Some(auth_time));
    assert!(
        f.base
            .store
            .authenticate(f.base.authority.realm(), issued.access_token().verifier())
            .await
            .is_err()
    );
    assert!(
        f.base
            .store
            .authenticate(f.base.authority.realm(), issued.refresh_token().verifier())
            .await
            .is_err()
    );
    let exact:bool=sqlx::query_scalar("SELECT t.token_hash=$2 AND a.access_hash=$3 AND a.native_refresh AND a.native_family_id=f.id AND a.native_generation=0 AND f.generation=0 AND t.spent_at_us IS NULL AND f.expires_at_us=c.grant_expires_at_us AND f.source_absolute_cap_us=c.source_absolute_cap_us AND f.expires_at_us>a.expires_at_us AND f.idle_until_us<=f.expires_at_us AND f.policy_revision=c.policy_revision AND f.client_revision=c.client_revision AND f.approved_at_us=c.approved_at_us FROM auth_issuer_native_families f JOIN auth_issuer_native_refresh_tokens t ON (t.realm_id,t.family_id)=(f.realm_id,f.id) JOIN auth_issuer_access_tokens a ON (a.realm_id,a.native_family_id)=(f.realm_id,f.id) JOIN auth_issuer_native_consents c ON (c.realm_id,c.authorization_id)=(f.realm_id,f.authorization_id) WHERE f.realm_id=$1")
        .bind(f.base.authority.realm()).bind(issued.refresh_token().verifier().as_slice()).bind(issued.access_token().verifier().as_slice()).fetch_one(&f.base.pool).await.unwrap();
    assert!(exact);
    let actor:bool=sqlx::query_scalar("SELECT user_id=$2 AND actor_session_id IS NULL AND session_id IS NULL AND issuer_credential_kind='authorization_code' AND issuer_generation=0 AND issuer_family_id IS NOT NULL FROM auth_audit WHERE realm_id=$1 AND kind='issuer_native_created'")
        .bind(f.base.authority.realm()).bind(f.base.owner).fetch_one(&f.base.pool).await.unwrap();
    assert!(actor);
    assert!(matches!(
        f.exchange(&code).await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    assert_eq!(f.facts().await, (1, 1, 1, 1, 1));
}

#[sqlx::test]
async fn final_native_creation_audit_failure_rolls_back_family_hash_access_and_code_consumption(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let code = f.code().await;
    sqlx::raw_sql("ALTER TABLE auth_audit ADD CONSTRAINT owned_family_fault CHECK (kind<>'issuer_native_created') NOT VALID").execute(&f.base.pool).await.unwrap();
    assert!(matches!(
        f.exchange(&code).await,
        Err(IssuerTokenError::Unavailable)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    let unspent:bool=sqlx::query_scalar("SELECT status='approved' AND consumed_at_us IS NULL AND nonce IS NOT NULL AND pkce_challenge IS NOT NULL FROM auth_issuer_authorizations WHERE realm_id=$1")
        .bind(f.base.authority.realm()).fetch_one(&f.base.pool).await.unwrap();
    assert!(unspent);
    sqlx::raw_sql("ALTER TABLE auth_audit DROP CONSTRAINT owned_family_fault")
        .execute(&f.base.pool)
        .await
        .unwrap();
    let _issued = f.exchange(&code).await.unwrap();
    assert_eq!(f.facts().await, (1, 1, 1, 1, 1));
}

#[sqlx::test]
async fn native_family_requires_exact_client_pkce_uri_and_current_policy_before_any_grant(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let code = f.code().await;
    let wrong =
        auth_core::IssuerPkceVerifier::parse(Secret::generate().unwrap().expose().to_owned())
            .unwrap();
    assert!(matches!(
        f.issuer
            .exchange(
                &f.authentication(),
                &code,
                "http://127.0.0.1:41003/cb",
                &f.base.pkce,
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    assert!(matches!(
        f.issuer
            .exchange(
                &f.authentication(),
                &code,
                "http://127.0.0.1:41002/cb",
                &wrong,
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    assert!(matches!(
        f.issuer
            .exchange(
                &f.base.authentication(),
                &code,
                "http://127.0.0.1:41002/cb",
                &f.base.pkce,
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidClient)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.base
        .store
        .disable_issuer_native_refresh_policy(f.policy.authority(), f.policy.client().client())
        .await
        .unwrap();
    assert!(matches!(
        f.exchange(&code).await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
}

#[sqlx::test]
async fn account_erasure_cascades_family_credentials_and_deidentifies_credential_actor_audit(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let code = f.code().await;
    let _issued = f.exchange(&code).await.unwrap();
    let token = Secret::generate().unwrap();
    let browser = Secret::generate().unwrap();
    f.base
        .store
        .begin_account_deletion(
            f.base.authority.realm(),
            f.base.current.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    f.base
        .store
        .finish_account_deletion(
            f.base.authority.realm(),
            f.base.current.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    assert_eq!(f.facts().await, (0, 0, 0, 1, 1));
    let erased:bool=sqlx::query_scalar("SELECT subject_erased AND user_id IS NULL AND actor_session_id IS NULL AND issuer_client_id IS NULL AND issuer_authorization_id IS NULL AND issuer_family_id IS NULL AND issuer_generation IS NULL AND issuer_credential_kind IS NULL FROM auth_audit WHERE realm_id=$1 AND kind='issuer_native_created'")
        .bind(f.base.authority.realm()).fetch_one(&f.base.pool).await.unwrap();
    assert!(erased);
}
