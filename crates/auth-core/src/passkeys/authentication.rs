use super::authentication_state::{AuthenticationCeremony, CredentialSnapshot};
use super::{
    MAX_CREDENTIAL_ID_BYTES, MAX_PASSKEYS_PER_ACCOUNT, PasskeyAuthenticationOptions,
    PasskeyAuthenticationResponse, PasskeyService, PrivatePasskeyAuthentication, StoredPasskey,
    VerifiedPasskeyAuthentication, logging,
};
use crate::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use uuid::Uuid;

const MAX_AUTHENTICATION_RESPONSE_BYTES: usize = 16 * 1024;

impl PasskeyService {
    /// Credentials and owner come from trusted realm-scoped storage. Exposing the
    /// resulting allow-list for an arbitrary email would disclose account metadata;
    /// the owning use case must review its account-selection boundary.
    pub fn begin_account_authentication(
        &self,
        realm: Uuid,
        owner: Uuid,
        credentials: &[StoredPasskey],
    ) -> Result<(PasskeyAuthenticationOptions, PrivatePasskeyAuthentication)> {
        if realm.is_nil()
            || owner.is_nil()
            || credentials.is_empty()
            || credentials.len() > MAX_PASSKEYS_PER_ACCOUNT
            || credentials
                .iter()
                .any(|key| key.realm != realm || key.owner != owner || key.rp_id != self.rp_id)
        {
            return Err(Error::InvalidInput);
        }
        let keys = credentials
            .iter()
            .map(|key| key.credential.clone())
            .collect::<Vec<_>>();
        let (options, state) =
            logging::without_payload_events(|| self.verifier.start_passkey_authentication(&keys))
                .map_err(|_| Error::Unavailable)?;
        let credentials = credentials
            .iter()
            .map(|key| CredentialSnapshot {
                id: key.credential.cred_id().to_vec(),
                digest: key.digest(),
            })
            .collect();
        Ok((
            options,
            PrivatePasskeyAuthentication {
                realm,
                origin: self.origin.as_str().to_owned(),
                ceremony: AuthenticationCeremony::AccountBound {
                    owner,
                    credentials,
                    state,
                },
            },
        ))
    }

    /// The pinned high-level library supports conditional UI for opportunistically
    /// resident passkeys. Preserve that mediation; this is not a generic modal flow.
    pub fn begin_discoverable_authentication(
        &self,
        realm: Uuid,
    ) -> Result<(PasskeyAuthenticationOptions, PrivatePasskeyAuthentication)> {
        if realm.is_nil() {
            return Err(Error::InvalidInput);
        }
        let (options, state) =
            logging::without_payload_events(|| self.verifier.start_discoverable_authentication())
                .map_err(|_| Error::Unavailable)?;
        Ok((
            options,
            PrivatePasskeyAuthentication {
                realm,
                origin: self.origin.as_str().to_owned(),
                ceremony: AuthenticationCeremony::Discoverable { state },
            },
        ))
    }

    /// Lookup hint only. Query by trusted realm/RP and this ID; proof and userHandle
    /// ownership are checked separately below. No assertion is trusted at this point.
    pub fn authentication_credential_id<'a>(
        &self,
        response: &'a PasskeyAuthenticationResponse,
    ) -> Result<&'a [u8]> {
        let raw = response.raw_id.as_slice();
        let bytes = response
            .id
            .len()
            .saturating_add(raw.len())
            .saturating_add(response.response.authenticator_data.len())
            .saturating_add(response.response.client_data_json.len())
            .saturating_add(response.response.signature.len())
            .saturating_add(
                response
                    .response
                    .user_handle
                    .as_ref()
                    .map_or(0, |id| id.len()),
            );
        if response.type_ != "public-key"
            || raw.is_empty()
            || raw.len() > MAX_CREDENTIAL_ID_BYTES
            || bytes > MAX_AUTHENTICATION_RESPONSE_BYTES
            || response.id != URL_SAFE_NO_PAD.encode(raw)
        {
            return Err(Error::Unauthorized);
        }
        Ok(raw)
    }

    /// Counter checks, signature, UP/UV, challenge, RP and origin validation stay in
    /// the reviewed high-level library. No database mutation or session is issued here.
    pub fn verify_authentication(
        &self,
        response: &PasskeyAuthenticationResponse,
        state: PrivatePasskeyAuthentication,
        stored: StoredPasskey,
    ) -> Result<VerifiedPasskeyAuthentication> {
        let id = self.authentication_credential_id(response)?;
        if state.realm != stored.realm
            || state.origin != self.origin.as_str()
            || stored.rp_id != self.rp_id
            || stored.credential.cred_id().as_slice() != id
            || response
                .get_user_unique_id()
                .is_some_and(|handle| handle != stored.owner.as_bytes())
        {
            return Err(Error::Unauthorized);
        }
        let result = logging::without_payload_events(|| match state.ceremony {
            AuthenticationCeremony::AccountBound {
                owner,
                credentials,
                state,
            } => {
                if owner != stored.owner
                    || !credentials
                        .iter()
                        .any(|key| key.id == id && key.digest == stored.digest())
                {
                    return Err(Error::Unauthorized);
                }
                self.verifier
                    .finish_passkey_authentication(response, &state)
                    .map_err(|_| Error::Unauthorized)
            }
            AuthenticationCeremony::Discoverable { state } => {
                let (owner, _) = self
                    .verifier
                    .identify_discoverable_authentication(response)
                    .map_err(|_| Error::Unauthorized)?;
                if owner != stored.owner {
                    return Err(Error::Unauthorized);
                }
                self.verifier
                    .finish_discoverable_authentication(
                        response,
                        state,
                        &[(&stored.credential).into()],
                    )
                    .map_err(|_| Error::Unauthorized)
            }
        })?;
        // BE is immutable for this application in both modes. BS may change when
        // BE was true at registration. Do not silently apply the bound API's BE upgrade.
        if !result.user_verified() || result.backup_eligible() != stored.backup_eligible {
            return Err(Error::Unauthorized);
        }
        let mut credential = stored.credential.clone();
        credential
            .update_credential(&result)
            .ok_or(Error::Unauthorized)?;
        let updated = serde_json::to_vec(&credential).map_err(|_| Error::Unavailable)?;
        Ok(VerifiedPasskeyAuthentication {
            original: stored,
            updated,
        })
    }
}
