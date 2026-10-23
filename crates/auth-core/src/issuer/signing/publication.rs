use super::{ISSUER_ID_TOKEN_LIFETIME_SECONDS, IssuerPublicKey};
use crate::{Error, IssuerAuthority, Result};
use uuid::Uuid;

/// Trusted publication policy, not proof that the key is active/approved now.
/// The repository owns actual time, operator disable and propagation checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerKeyPublication {
    authority: IssuerAuthority,
    key: IssuerPublicKey,
    sign_from_us: i64,
    sign_until_us: i64,
    verify_until_us: i64,
}
impl IssuerKeyPublication {
    pub fn new(
        authority: IssuerAuthority,
        key: IssuerPublicKey,
        sign_from_us: i64,
        sign_until_us: i64,
        verify_until_us: i64,
    ) -> Result<Self> {
        let retained_until = sign_until_us
            .checked_add(ISSUER_ID_TOKEN_LIFETIME_SECONDS * 1_000_000)
            .ok_or(Error::InvalidInput)?;
        if sign_from_us < 0 || sign_until_us <= sign_from_us || verify_until_us < retained_until {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            authority,
            key,
            sign_from_us,
            sign_until_us,
            verify_until_us,
        })
    }
    pub fn authority(&self) -> &IssuerAuthority {
        &self.authority
    }
    pub fn key(&self) -> &IssuerPublicKey {
        &self.key
    }
    pub fn sign_from_us(&self) -> i64 {
        self.sign_from_us
    }
    pub fn sign_until_us(&self) -> i64 {
        self.sign_until_us
    }
    pub fn verify_until_us(&self) -> i64 {
        self.verify_until_us
    }
}
/// Validated persisted metadata only. It must be rechecked in the final issuance
/// transaction; callers cannot turn a read snapshot into a signed token proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerSigningSnapshot {
    revision: Uuid,
    publication: IssuerKeyPublication,
}
impl IssuerSigningSnapshot {
    pub fn from_persisted(revision: Uuid, publication: IssuerKeyPublication) -> Result<Self> {
        if revision.is_nil() {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            revision,
            publication,
        })
    }
    pub fn revision(&self) -> Uuid {
        self.revision
    }
    pub fn publication(&self) -> &IssuerKeyPublication {
        &self.publication
    }
    pub fn authority(&self) -> &IssuerAuthority {
        self.publication.authority()
    }
}
