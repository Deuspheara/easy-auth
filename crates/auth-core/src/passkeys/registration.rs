use super::{
    MAX_CREDENTIAL_ID_BYTES, MAX_PASSKEYS_PER_ACCOUNT, PasskeyCreationOptions,
    PasskeyRegistrationResponse, PasskeyService, PrivatePasskeyRegistration, VerifiedPasskey,
    configuration, logging,
};
use crate::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use uuid::Uuid;

const MAX_REGISTRATION_RESPONSE_BYTES: usize = 16 * 1024;

impl PasskeyService {
    /// Explicit request for browser residence, not independently verified metadata.
    /// The caller must still retain account-bound sign-in for nonresident credentials.
    pub fn begin_discoverable_registration(
        &self,
        owner: Uuid,
        account_name: &str,
        excluded_credentials: &[Vec<u8>],
    ) -> Result<(PasskeyCreationOptions, PrivatePasskeyRegistration)> {
        let (mut options, state) =
            self.begin_registration(owner, account_name, excluded_credentials)?;
        let selection = options
            .public_key
            .authenticator_selection
            .as_mut()
            .ok_or(Error::Unavailable)?;
        // This field's public enum is not reexported by the high-level prelude.
        selection.resident_key =
            Some(serde_json::from_value("required".into()).map_err(|_| Error::Unavailable)?);
        selection.require_resident_key = true;
        Ok((options, state))
    }

    pub fn begin_registration(
        &self,
        owner: Uuid,
        account_name: &str,
        excluded_credentials: &[Vec<u8>],
    ) -> Result<(PasskeyCreationOptions, PrivatePasskeyRegistration)> {
        configuration::display_name(account_name)?;
        if owner.is_nil()
            || excluded_credentials.len() >= MAX_PASSKEYS_PER_ACCOUNT
            || excluded_credentials
                .iter()
                .any(|id| id.is_empty() || id.len() > MAX_CREDENTIAL_ID_BYTES)
        {
            return Err(Error::InvalidInput);
        }
        let excluded = excluded_credentials
            .iter()
            .cloned()
            .map(Into::into)
            .collect();
        let (options, state) = logging::without_payload_events(|| {
            self.verifier.start_passkey_registration(
                owner,
                account_name,
                account_name,
                Some(excluded),
            )
        })
        .map_err(|_| Error::Unavailable)?;
        Ok((
            options,
            PrivatePasskeyRegistration {
                origin: self.origin.as_str().to_owned(),
                state,
            },
        ))
    }

    /// This consumes only the in-memory value. Database consumption is a separate transaction.
    pub fn verify_registration(
        &self,
        response: &PasskeyRegistrationResponse,
        state: PrivatePasskeyRegistration,
    ) -> Result<VerifiedPasskey> {
        if state.origin != self.origin.as_str() || !bounded_response(response) {
            return Err(Error::Unauthorized);
        }
        super::client_context::require_same_origin(response.response.client_data_json.as_slice())?;
        let credential = logging::without_payload_events(|| {
            self.verifier
                .finish_passkey_registration(response, &state.state)
        })
        .map_err(|_| Error::Unauthorized)?;
        if credential.cred_id().is_empty() || credential.cred_id().len() > MAX_CREDENTIAL_ID_BYTES {
            return Err(Error::Unauthorized);
        }
        // The verifier takes the credential ID from attested data. Reject contradictory
        // public envelope identifiers rather than letting later adapters interpret them.
        if response.raw_id.as_slice() != credential.cred_id().as_slice()
            || response.id != URL_SAFE_NO_PAD.encode(credential.cred_id().as_slice())
        {
            return Err(Error::Unauthorized);
        }
        Ok(VerifiedPasskey {
            rp_id: self.rp_id.clone(),
            credential,
        })
    }
}

fn bounded_response(response: &PasskeyRegistrationResponse) -> bool {
    let bytes = response
        .id
        .len()
        .saturating_add(response.raw_id.len())
        .saturating_add(response.response.attestation_object.len())
        .saturating_add(response.response.client_data_json.len());
    response.type_ == "public-key" && bytes <= MAX_REGISTRATION_RESPONSE_BYTES
}
