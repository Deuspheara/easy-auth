use super::{
    SamlPostResponse, SamlVerificationRepository, VerifiedSamlAssertion, configuration, projection,
    replay::Reservations, timing,
};
use crate::{Error, Result, SamlPreparedResponse, SamlRegistration};
use saml_rs::{
    BrowserInput, ClockSkew, CryptoFipsStatus, CryptoProvider, EntityId, FormField, MessageId,
    PendingAuthnRequest, RelayStateParam, ReplayPolicy, SamlValidationContext, SsoResponse,
    SsoResponseBinding, initialize_crypto_provider,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

const MAX_VERIFICATIONS: usize = 2;
const VERIFY_TIMEOUT: Duration = Duration::from_secs(15);

/// Concrete pinned saml-rs/Bergshamra AWS-LC adapter. No runtime engine selection,
/// unsigned fallback or public proof constructor. Normal provider routes stay closed.
pub struct SamlResponseVerifier {
    registration: SamlRegistration,
    repository: Arc<dyn SamlVerificationRepository>,
    workers: Arc<Semaphore>,
}
impl SamlResponseVerifier {
    pub fn new(
        registration: SamlRegistration,
        repository: Arc<dyn SamlVerificationRepository>,
    ) -> Result<Self> {
        let provider = initialize_crypto_provider().map_err(|_| Error::Unavailable)?;
        if provider.provider() != CryptoProvider::AwsLc
            || provider.fips_status() != CryptoFipsStatus::Disabled
        {
            return Err(Error::Unavailable);
        }
        configuration::sp(&registration).map_err(|_| Error::Unavailable)?;
        Ok(Self {
            registration,
            repository,
            workers: Arc::new(Semaphore::new(MAX_VERIFICATIONS)),
        })
    }

    #[cfg(feature = "saml-identities")]
    pub(crate) fn share_capacity_with(&mut self, other: &Self) -> Result<()> {
        if self.registration != other.registration {
            return Err(Error::InvalidInput);
        }
        // A timed-out/cancelled caller can leave native work in flight. Do not
        // detach that work from its budget when joining another composition.
        if self.workers.available_permits() != MAX_VERIFICATIONS {
            return Err(Error::RateLimited);
        }
        self.workers = other.workers.clone();
        Ok(())
    }

    pub async fn verify(
        &self,
        prepared: SamlPreparedResponse,
        input: SamlPostResponse,
    ) -> Result<VerifiedSamlAssertion> {
        if prepared.registration() != &self.registration {
            return Err(Error::Unauthorized);
        }
        let permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::RateLimited)?;
        let material = tokio::time::timeout(
            VERIFY_TIMEOUT,
            self.repository
                .load_saml_verification_material(&self.registration),
        )
        .await
        .map_err(|_| Error::Unavailable)??;
        if material.observed_at_us < prepared.observed_at_us() || material.observed_at_us <= 0 {
            return Err(Error::Unavailable);
        }
        if material.observed_at_us >= prepared.expires_at_us() {
            return Err(Error::Unauthorized);
        }
        // Timeout cannot abort native crypto. The blocking worker retains the
        // permit until it actually exits, including after caller cancellation.
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            verify(prepared, input, material)
        });
        tokio::time::timeout(VERIFY_TIMEOUT, worker)
            .await
            .map_err(|_| Error::Unavailable)?
            .map_err(|_| Error::Unavailable)?
    }
}

fn verify(
    prepared: SamlPreparedResponse,
    input: SamlPostResponse,
    material: super::SamlVerificationMaterial,
) -> Result<VerifiedSamlAssertion> {
    let now = material.observed_at_us;
    let time = timing::system(now)?;
    let reg = prepared.registration();
    let sp = configuration::sp(reg).map_err(|_| Error::Unavailable)?;
    let pending = PendingAuthnRequest::try_new(
        MessageId::try_new(prepared.request_id()).map_err(|_| Error::Unavailable)?,
        // Actual RelayState and private browser proof were consumed together in
        // storage. Only trusted request correlation reaches this message adapter.
        RelayStateParam::absent(),
        configuration::acs(reg).map_err(|_| Error::Unavailable)?,
        SsoResponseBinding::Post,
        EntityId::try_new(reg.idp_entity()).map_err(|_| Error::Unavailable)?,
    )
    .map_err(|_| Error::Unavailable)?;
    for pin in material.trust.active_at(now / timing::SECOND_US)? {
        let idp = configuration::idp(reg, pin.der())?;
        let mut reservations = Reservations::default();
        let validation =
            SamlValidationContext::new(time, ReplayPolicy::RequireCache(&mut reservations))
                .with_clock_skew(ClockSkew::strict());
        let browser = BrowserInput::<SsoResponse>::post(vec![FormField::new(
            "SAMLResponse",
            input.0.as_str(),
        )]);
        if let Ok(session) = sp.finish_sso(&idp, &pending, browser, validation) {
            return projection::project(prepared, session, reservations, pin, now);
        }
    }
    Err(Error::Unauthorized)
}
