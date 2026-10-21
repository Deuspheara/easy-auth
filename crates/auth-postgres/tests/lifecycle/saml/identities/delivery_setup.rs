use super::super::{setup::Fixture, signed_idp};
use auth_core::{
    SamlBrowserProof, SamlIdentityPolicy, SamlJitPolicy, SamlMappedIdentity, SamlPostResponse,
    SamlRegistration, SamlRequestAdmission, SamlRequestRepository, SamlResponseVerifier,
    SamlTransactions, Secret,
};
use saml_rs::{NameId, NameIdFormat};
use std::time::Duration;
use uuid::Uuid;

pub(super) struct Delivery {
    pub first: SamlMappedIdentity,
    pub request_id: String,
    pub encoded: String,
}

pub(super) async fn first(f: &Fixture, policy: &SamlIdentityPolicy) -> Delivery {
    let start = f.flow.start().await.unwrap();
    let encoded = signed_idp::response_field_from(
        f,
        &start,
        NameId::new("normal", Some(NameIdFormat::Persistent)),
        f.registration.idp_entity(),
        Duration::from_secs(180),
    );
    let prepared = f
        .flow
        .prepare_response(
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    let proof = SamlResponseVerifier::new(f.registration.clone(), f.store.clone())
        .unwrap()
        .verify(prepared, SamlPostResponse::parse(encoded.clone()).unwrap())
        .await
        .unwrap();
    Delivery {
        first: policy.map(proof).unwrap(),
        request_id: start.request_id().to_owned(),
        encoded,
    }
}

pub(super) async fn other_client(f: &Fixture) -> SamlIdentityPolicy {
    let r = &f.registration;
    let reg = SamlRegistration::unsigned_redirect(
        r.realm(),
        r.connection(),
        Uuid::new_v4(),
        r.sp_entity(),
        r.idp_entity(),
        r.sso(),
        r.acs(),
    )
    .unwrap();
    f.store
        .configure_saml_identity_policy(
            &SamlIdentityPolicy::new(reg).with_jit(SamlJitPolicy::Allow),
            &signed_idp::trust(),
        )
        .await
        .unwrap()
}

/// The same unchanged signed provider POST is delivered to a second independently
/// browser-bound stored context of the same SP/IdP namespace. Trusted test setup
/// reuses its public request ID through the real repository port. No XML mutation,
/// forged proof or signature-concurrency experiment is involved.
pub(super) async fn repeated(
    f: &Fixture,
    policy: &SamlIdentityPolicy,
    request_id: &str,
    encoded: &str,
) -> SamlMappedIdentity {
    let relay = Secret::generate().unwrap();
    let browser = Secret::generate().unwrap();
    let browser_proof = SamlBrowserProof::parse(browser.expose().to_owned()).unwrap();
    f.store
        .save_saml_request(
            policy.registration(),
            SamlRequestAdmission {
                request_id,
                relay: relay.verifier(),
                browser: browser.verifier(),
            },
        )
        .await
        .unwrap();
    let flow = SamlTransactions::new(policy.registration().clone(), f.store.clone());
    let prepared = flow
        .prepare_response(request_id, &relay, &browser_proof)
        .await
        .unwrap();
    let proof = SamlResponseVerifier::new(policy.registration().clone(), f.store.clone())
        .unwrap()
        .verify(
            prepared,
            SamlPostResponse::parse(encoded.to_owned()).unwrap(),
        )
        .await
        .unwrap();
    policy.map(proof).unwrap()
}
