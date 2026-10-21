use super::{certificates, configuration};
use crate::{Postgres, unavailable};
use auth_core::{
    Error, Result, SamlCertificateTrust, SamlIdentityPolicy, SamlJitPolicy, SamlRegistration,
};
use sqlx::{Postgres as Pg, Transaction};

impl Postgres {
    /// Trusted administration: replace full registration, explicit pins and JIT
    /// policy atomically under a fresh revision while retaining operator disable.
    /// Cancels pending requests; does not create an identity/session or activate ACS.
    pub async fn configure_saml_identity_policy(
        &self,
        input: &SamlIdentityPolicy,
        trust: &SamlCertificateTrust,
    ) -> Result<SamlIdentityPolicy> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let reg = certificates::replace_registration(&mut tx, input.registration(), trust).await?;
        let policy = SamlIdentityPolicy::new(reg).with_jit(input.jit());
        let reg = policy.registration();
        let jit = match policy.jit() {
            SamlJitPolicy::Deny => "deny",
            SamlJitPolicy::Allow => "allow",
        };
        sqlx::query("INSERT INTO auth_saml_identity_policies(realm_id,connection_id,client_id,revision,jit) VALUES($1,$2,$3,$4,$5)")
            .bind(reg.realm()).bind(reg.connection()).bind(reg.client()).bind(reg.revision()).bind(jit)
            .execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(policy)
    }

    /// Current enabled snapshot only. Mapping or reading does not confer ongoing
    /// authority; final replay/identity/session commit must recheck full policy.
    pub async fn saml_identity_policy(&self, reg: &SamlRegistration) -> Result<SamlIdentityPolicy> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let policy = load(&mut tx, reg).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(policy)
    }
}

/// Exact current definition under the caller's source/configuration transaction.
pub(super) async fn load(
    tx: &mut Transaction<'_, Pg>,
    reg: &SamlRegistration,
) -> Result<SamlIdentityPolicy> {
    configuration::lock(tx, reg).await?;
    let jit: String = sqlx::query_scalar("SELECT jit FROM auth_saml_identity_policies WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3 AND revision=$4")
        .bind(reg.realm()).bind(reg.connection()).bind(reg.client()).bind(reg.revision())
        .fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
    let jit = match jit.as_str() {
        "deny" => SamlJitPolicy::Deny,
        "allow" => SamlJitPolicy::Allow,
        _ => return Err(Error::Unavailable),
    };
    Ok(SamlIdentityPolicy::new(reg.clone()).with_jit(jit))
}
