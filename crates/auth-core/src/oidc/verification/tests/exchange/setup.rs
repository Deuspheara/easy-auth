use super::super::setup::Fixture;
pub(super) use super::super::setup::TokenHttp as Http;
use crate::{
    OidcClientAuthentication, OidcCodeExchange, OidcSigningAlgorithm, OidcVerificationPolicy,
};
use std::sync::Arc;

pub(super) fn client(
    f: &Fixture,
    http: Arc<Http>,
    authentication: OidcClientAuthentication,
) -> OidcCodeExchange {
    OidcCodeExchange::new(
        f.documents.clone(),
        f.store.clone(),
        OidcVerificationPolicy::new(&[OidcSigningAlgorithm::ES256], &[]).unwrap(),
        authentication,
        http,
    )
}
