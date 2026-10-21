use super::SamlRegistration;
use crate::{Error, Result};
use saml_rs::{
    constants::{Binding, name_id_format},
    entity::{BindingContext, EntitySetting},
    idp::IdentityProvider,
    metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig, generate_sp_metadata},
    sp::{LoginRequestOptions, ServiceProvider},
};

fn sp_config(registration: &SamlRegistration) -> SpMetadataConfig {
    SpMetadataConfig {
        entity_id: registration.sp_entity().to_owned(),
        authn_requests_signed: false,
        want_assertions_signed: true,
        name_id_format: vec![name_id_format::PERSISTENT.to_owned()],
        assertion_consumer_service: vec![Endpoint {
            binding: Binding::Post,
            location: registration.acs().to_owned(),
            index: Some(0),
            is_default: true,
        }],
        ..Default::default()
    }
}

impl SamlRegistration {
    /// Registration data only. Publishing this XML does not create or enable an
    /// ACS. It advertises no signing/encryption key or unsupported logout path.
    pub fn metadata_xml(&self) -> String {
        generate_sp_metadata(&sp_config(self))
    }

    pub(super) fn login_request(
        &self,
        relay_state: &str,
        force_authn: Option<bool>,
    ) -> Result<BindingContext> {
        // Only our own generated metadata is parsed. No inbound SAML/metadata or
        // cryptographic verification API is exposed by the requests-only feature.
        let sp = ServiceProvider::from_config(&sp_config(self), EntitySetting::default())
            .map_err(|_| Error::Unavailable)?;
        let idp_config = IdpMetadataConfig {
            entity_id: self.idp_entity().to_owned(),
            want_authn_requests_signed: false,
            name_id_format: vec![name_id_format::PERSISTENT.to_owned()],
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, self.sso())],
            ..Default::default()
        };
        let idp = IdentityProvider::from_config(&idp_config, EntitySetting::default())
            .map_err(|_| Error::Unavailable)?;
        sp.create_login_request_with_options(
            &idp,
            Binding::Redirect,
            &LoginRequestOptions {
                relay_state: Some(relay_state),
                force_authn,
                response_binding: Some(Binding::Post),
                ..Default::default()
            },
        )
        .map_err(|_| Error::Unavailable)
    }
}
