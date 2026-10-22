//! Read-only startup: administrative provisioning owns revision, pins and enable.
use crate::{Postgres, unavailable};
use auth_core::{Error, Result, SamlIdentityPolicy, SamlVerificationRepository};
use uuid::Uuid;

impl Postgres {
    /// Load only an already provisioned, enabled, exact registration and policy.
    /// Never create/reconfigure a source, rotate pins or clear operator disable.
    /// Active configured leaf pins are required at the fresh database clock.
    pub async fn load_saml_identity_policy(
        &self,
        input: &SamlIdentityPolicy,
    ) -> Result<SamlIdentityPolicy> {
        let reg = input.registration();
        let revision: Uuid = sqlx::query_scalar(
            "SELECT revision FROM auth_saml_registrations WHERE realm_id=$1 AND id=$2 AND client_id=$3"
        ).bind(reg.realm()).bind(reg.connection()).bind(reg.client())
            .fetch_optional(&self.pool).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
        let registration = reg.clone().with_persisted_revision(revision)?;
        let expected = SamlIdentityPolicy::new(registration).with_jit(input.jit());
        let actual = self.saml_identity_policy(expected.registration()).await?;
        if actual != expected {
            return Err(Error::Unauthorized);
        }
        let material = self
            .load_saml_verification_material(actual.registration())
            .await?;
        material
            .trust
            .active_at(material.observed_at_us / 1_000_000)?;
        // No lock spans certificate parsing. Recheck current full policy after it;
        // later authority operations independently perform their final checks.
        if self.saml_identity_policy(actual.registration()).await? != actual {
            return Err(Error::Unauthorized);
        }
        Ok(actual)
    }
}
