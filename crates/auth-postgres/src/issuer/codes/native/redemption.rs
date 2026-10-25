use super::super::{
    redemption_state::{CodeCandidate, LockedCode},
    state,
};
use super::{preparation, state::ConsentState};
use crate::{Postgres, unavailable};
use auth_core::{
    Error, IssuerCodeRedemption, IssuerGrantData, IssuerNativeConsentData, IssuerRedirectProfile,
    IssuerTokenError, IssuerTokenResult, Result,
};
use sqlx::{Postgres as Pg, Transaction};

pub(in crate::issuer) struct NativeCodeCandidate {
    code: CodeCandidate,
    consent: ConsentState,
    data: IssuerNativeConsentData,
}
impl NativeCodeCandidate {
    pub(in crate::issuer) async fn read(
        store: &Postgres,
        request: &IssuerCodeRedemption<'_>,
    ) -> Result<Option<Self>> {
        if request.client.realm() != request.authority.realm()
            || request.client.redirect_profile() != IssuerRedirectProfile::NativeRefreshLoopback
        {
            return Err(Error::Unauthorized);
        }
        let Some(original) = state::code(store, request).await? else {
            return Ok(None);
        };
        if !original.native_refresh {
            return Err(Error::Unauthorized);
        }
        let consent = ConsentState::load(store, &original).await?;
        let data = consent.data(request.authority, request.client)?;
        let Some(code) =
            CodeCandidate::from_state(store, request.authority.realm(), original).await?
        else {
            return Ok(None);
        };
        Ok(Some(Self {
            code,
            consent,
            data,
        }))
    }
    pub(in crate::issuer) fn consent(&self) -> &IssuerNativeConsentData {
        &self.data
    }
    /// Caller holds current client, exact native policy and current signing key.
    pub(in crate::issuer) async fn lock(
        self,
        tx: &mut Transaction<'_, Pg>,
        request: &IssuerCodeRedemption<'_>,
    ) -> IssuerTokenResult<LockedNativeCode> {
        let code = self.code.lock(tx, request).await?;
        self.consent.lock_approved(tx, &code.state).await?;
        if self.data.grant_expires_at_us
            > preparation::absolute_cap(tx, request.authority, &code.caller).await?
            || code.expires_at_us() > self.data.grant_expires_at_us
        {
            return Err(IssuerTokenError::InvalidGrant);
        }
        Ok(LockedNativeCode {
            code,
            consent: self.consent,
            data: self.data,
        })
    }
}
pub(in crate::issuer) struct LockedNativeCode {
    code: LockedCode,
    consent: ConsentState,
    data: IssuerNativeConsentData,
}
impl LockedNativeCode {
    pub(in crate::issuer) fn facts(&self, at: i64) -> IssuerTokenResult<IssuerGrantData> {
        self.code.facts(at)
    }
    pub(in crate::issuer) fn consent_data(
        &self,
        request: &IssuerCodeRedemption<'_>,
    ) -> Result<IssuerNativeConsentData> {
        self.consent.data(request.authority, request.client)
    }
    pub(in crate::issuer) fn expires_at_us(&self) -> i64 {
        self.code.expires_at_us()
    }
    pub(in crate::issuer) async fn snapshots(
        &self,
        tx: &mut Transaction<'_, Pg>,
        request: &IssuerCodeRedemption<'_>,
    ) -> Result<(String, String)> {
        Ok((
            self.code.snapshot(tx, request).await?,
            self.consent.snapshot(tx).await?,
        ))
    }
    pub(in crate::issuer) async fn matches(
        &self,
        tx: &mut Transaction<'_, Pg>,
        signed: &auth_core::IssuerNativeSignedCode<'_>,
    ) -> IssuerTokenResult<bool> {
        let (code, consent) = self.snapshots(tx, signed.redemption()).await?;
        Ok(self.code.matches_grant(signed.grant())?
            && code == signed.code_snapshot()
            && consent == signed.consent_snapshot()
            && signed.consent().policy == self.data.policy
            && signed.consent().grant_expires_at_us == self.data.grant_expires_at_us
            && signed.consent().approved_at_us == self.data.approved_at_us)
    }
    pub(in crate::issuer) async fn consume(
        &self,
        tx: &mut Transaction<'_, Pg>,
        request: &IssuerCodeRedemption<'_>,
        at: i64,
    ) -> Result<()> {
        self.code.consume(tx, request, at).await
    }
    pub(in crate::issuer) async fn quota(
        &self,
        tx: &mut Transaction<'_, Pg>,
        request: &IssuerCodeRedemption<'_>,
        at: i64,
    ) -> IssuerTokenResult<()> {
        let active:i64=sqlx::query_scalar("SELECT count(*) FROM auth_issuer_native_families WHERE realm_id=$1 AND issuer=$2 AND client_id=$3 AND user_id=$4 AND revoked_at_us IS NULL AND expires_at_us>$5 AND idle_until_us>$5")
            .bind(request.authority.realm()).bind(request.authority.issuer()).bind(request.client.client()).bind(self.code.caller.user).bind(at)
            .fetch_one(&mut **tx).await.map_err(unavailable)?;
        if active >= auth_core::MAX_ISSUER_NATIVE_FAMILIES_PER_OWNER_CLIENT {
            return Err(IssuerTokenError::RateLimited);
        }
        Ok(())
    }
}
