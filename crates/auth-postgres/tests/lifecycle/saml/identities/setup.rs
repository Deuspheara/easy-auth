use super::super::{setup::Fixture, signed_idp};
use auth_core::{
    SamlIdentityPolicy, SamlResponseVerifier, SamlTransactions, VerifiedSamlAssertion,
};
use sqlx::PgPool;
use std::time::Duration;

pub(super) async fn fixture(pool: PgPool) -> (Fixture, SamlIdentityPolicy) {
    let mut f = signed_idp::fixture(pool).await;
    let policy = f
        .store
        .configure_saml_identity_policy(
            &SamlIdentityPolicy::new(f.registration.clone()),
            &signed_idp::trust(),
        )
        .await
        .unwrap();
    f.registration = policy.registration().clone();
    f.flow = SamlTransactions::new(f.registration.clone(), f.store.clone());
    (f, policy)
}

/// Genuine library verification only; no test proof constructor or crypto stub.
pub(super) async fn verify(f: &Fixture, subject: &str) -> VerifiedSamlAssertion {
    let start = f.flow.start().await.unwrap();
    let input = signed_idp::response(f, &start, subject, Duration::from_secs(180));
    let prepared = f
        .flow
        .prepare_response(
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    SamlResponseVerifier::new(f.registration.clone(), f.store.clone())
        .unwrap()
        .verify(prepared, input)
        .await
        .unwrap()
}
