use super::{setup::*, *};
use josekit::{jwk::KeyPair, jws::ES256};

#[tokio::test]
async fn fixed_claim_secret_has_actual_es256_signature_and_only_apple_claims() {
    let (key, signer) = signer("KEY0000001", 100, 1000);
    let secret = signer.issue(200_999_999).await.unwrap();
    let (claims, header) = verify(&secret, &key);
    assert_eq!(
        claims,
        serde_json::json!({"iss":TEAM,"sub":CLIENT,"aud":"https://appleid.apple.com","iat":200,"exp":500})
    );
    assert_eq!(header.algorithm(), Some("ES256"));
    assert_eq!(header.key_id(), Some("KEY0000001"));
    assert_eq!(header.token_type(), Some("JWT"));
    assert_eq!(secret.expires_at(), 500);
    assert_eq!(signer.client_id(), CLIENT);
    assert_eq!(format!("{signer:?}"), "AppleClientSecretSigner([REDACTED])");
    assert_eq!(format!("{secret:?}"), "AppleClientSecret([REDACTED])");
    let auth = secret.into_client_authentication().unwrap();
    assert!(matches!(
        auth,
        OidcClientAuthentication::ClientSecretPost(_)
    ));
    assert_eq!(format!("{auth:?}"), "OidcClientAuthentication([REDACTED])");
}

#[tokio::test]
async fn secret_lifetime_is_capped_by_the_exact_selected_key_window() {
    let (key, signer) = signer("KEY0000001", 100, 350);
    for now in [100_000_000, 349_999_999] {
        let secret = signer.issue(now).await.unwrap();
        let (claims, _) = verify(&secret, &key);
        assert_eq!(claims["exp"], 350);
        assert_eq!(secret.expires_at(), 350);
    }
    for now in [0, 99_999_999, 350_000_000, i64::MAX] {
        assert!(matches!(signer.issue(now).await, Err(Error::Unauthorized)));
    }
    assert!(matches!(signer.issue(-1).await, Err(Error::Unavailable)));
}

#[tokio::test]
async fn explicit_rotation_uses_new_key_and_never_falls_back_to_retired_material() {
    let (old_key, old) = signer("OLD0000001", 100, 300);
    let (new_key, new) = signer("NEW0000001", 250, 1000);
    let old_secret = old.issue(275_000_000).await.unwrap();
    let new_secret = new.issue(275_000_000).await.unwrap();
    assert_eq!(verify(&old_secret, &old_key).1.key_id(), Some("OLD0000001"));
    assert_eq!(verify(&new_secret, &new_key).1.key_id(), Some("NEW0000001"));
    let verifier = ES256
        .verifier_from_pem(old_key.to_pem_public_key())
        .unwrap();
    assert!(josekit::jws::deserialize_compact(new_secret.token.as_bytes(), &verifier).is_err());
    assert!(matches!(
        old.issue(300_000_000).await,
        Err(Error::Unauthorized)
    ));
    assert!(new.issue(300_000_000).await.is_ok());
}

#[tokio::test]
async fn bounded_signing_admission_rejects_before_native_work_and_recovers() {
    let (_, signer) = signer("KEY0000001", 0, 1000);
    let permit = signer
        .workers
        .clone()
        .acquire_many_owned(MAX_SIGNING_OPERATIONS as u32)
        .await
        .unwrap();
    assert!(matches!(
        signer.issue(1_000_000).await,
        Err(Error::RateLimited)
    ));
    drop(permit);
    assert!(signer.issue(1_000_000).await.is_ok());
}
