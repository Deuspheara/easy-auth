use super::setup::Fixture;
use crate::*;
use uuid::Uuid;

#[tokio::test]
async fn restored_definition_rejects_nil_and_cannot_rebind_verified_proof() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let original = OidcIdentityPolicy::new(
        f.store.connection.clone(),
        &[f.store.connection.issuer()],
        OidcDisplayNameClaim::Subject,
    )
    .unwrap();
    assert!(matches!(
        original.clone().with_persisted_revision(Uuid::nil()),
        Err(Error::InvalidInput)
    ));
    let (exchange, claims) = f.exchange().await;
    let verified = f
        .verifier
        .verify(exchange, f.key.token(&claims))
        .await
        .unwrap();
    let restored = original
        .clone()
        .with_persisted_revision(Uuid::new_v4())
        .unwrap();
    assert_eq!(restored.allowed_issuers(), original.allowed_issuers());
    assert_eq!(restored.display_name_claim(), original.display_name_claim());
    assert_eq!(restored.jit(), original.jit());
    assert!(
        matches!(restored.map(verified), Err(Error::Unauthorized)),
        "configuration metadata cannot rewrite a verified identity's original revision"
    );
}
