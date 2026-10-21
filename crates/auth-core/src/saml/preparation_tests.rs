use super::{SamlRegistration, SamlRequestAdmission, SamlRequestRepository, SamlTransactions};
use crate::{Error, Result, Secret};
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

// A pre-existing requests-only adapter intentionally implements no take method.
struct RequestsOnly;

#[async_trait]
impl SamlRequestRepository for RequestsOnly {
    async fn save_saml_request(
        &self,
        _: &SamlRegistration,
        _: SamlRequestAdmission<'_>,
    ) -> Result<i64> {
        Err(Error::InvalidInput)
    }
    async fn cancel_saml_request(
        &self,
        _: &SamlRegistration,
        _: SamlRequestAdmission<'_>,
    ) -> Result<()> {
        Err(Error::InvalidInput)
    }
}

#[tokio::test]
async fn existing_requests_only_adapters_fail_closed_for_response_preparation() {
    let registration = SamlRegistration::unsigned_redirect(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        "urn:example:sp",
        "urn:example:idp",
        "https://idp.example/sso",
        "https://sp.example/acs",
    )
    .unwrap();
    let flow = SamlTransactions::new(registration, Arc::new(RequestsOnly));
    let relay = Secret::generate().unwrap();
    let browser =
        super::SamlBrowserProof::parse(Secret::generate().unwrap().expose().to_owned()).unwrap();
    assert!(matches!(
        flow.prepare_response("_request", &relay, &browser).await,
        Err(Error::Unavailable)
    ));
}
