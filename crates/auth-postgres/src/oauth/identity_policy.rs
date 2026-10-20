use super::configuration;
use crate::{Postgres, unavailable};
use auth_core::{Error, OidcDisplayNameClaim, OidcIdentityPolicy, OidcJitPolicy, Result};
use sqlx::Row;

impl Postgres {
    /// Trusted administration only. Policy changes allocate a new configuration
    /// revision and cancel prior pending state in the same transaction. Applying
    /// policy never clears an existing connection disable. Use the returned policy.
    pub async fn configure_oidc_identity_policy(
        &self,
        input: &OidcIdentityPolicy,
    ) -> Result<OidcIdentityPolicy> {
        let current = input.configuration();
        let connection = current.reconfigured();
        let issuers: Vec<&str> = input.allowed_issuers().iter().map(String::as_str).collect();
        let policy = OidcIdentityPolicy::new(connection, &issuers, input.display_name_claim())?
            .with_jit(input.jit());
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        configuration::replace(&mut tx, policy.configuration()).await?;
        replace(&mut tx, &policy).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(policy)
    }
}

/// Persist policy under the caller's already locked/configured revision.
/// Configuration mutation and transaction commit stay explicit in the caller.
pub(super) async fn replace(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    policy: &OidcIdentityPolicy,
) -> Result<()> {
    let display_claim = match policy.display_name_claim() {
        OidcDisplayNameClaim::Subject => "sub",
        OidcDisplayNameClaim::Name => "name",
        OidcDisplayNameClaim::PreferredUsername => "preferred_username",
    };
    let jit = match policy.jit() {
        OidcJitPolicy::Deny => "deny",
        OidcJitPolicy::Allow => "allow",
    };
    let connection = policy.configuration();
    sqlx::query(
        r#"
        INSERT INTO auth_oidc_identity_policies
          (realm_id,connection_id,client_id,revision,allowed_issuers,display_claim,jit)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (realm_id,connection_id,client_id) DO UPDATE SET
          revision=EXCLUDED.revision,allowed_issuers=EXCLUDED.allowed_issuers,
          display_claim=EXCLUDED.display_claim,jit=EXCLUDED.jit
        "#,
    )
    .bind(connection.realm())
    .bind(connection.connection())
    .bind(connection.client())
    .bind(connection.revision())
    .bind(policy.allowed_issuers())
    .bind(display_claim)
    .bind(jit)
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?;
    Ok(())
}

pub(crate) async fn lock(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    expected: &OidcIdentityPolicy,
) -> Result<()> {
    let c = expected.configuration();
    configuration::lock(tx, c).await?;
    let row = sqlx::query("SELECT allowed_issuers,display_claim,jit FROM auth_oidc_identity_policies WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3 AND revision=$4 FOR SHARE")
        .bind(c.realm()).bind(c.connection()).bind(c.client()).bind(c.revision())
        .fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
    let issuers: Vec<String> = row.try_get("allowed_issuers").map_err(unavailable)?;
    let display = match row
        .try_get::<&str, _>("display_claim")
        .map_err(unavailable)?
    {
        "sub" => OidcDisplayNameClaim::Subject,
        "name" => OidcDisplayNameClaim::Name,
        "preferred_username" => OidcDisplayNameClaim::PreferredUsername,
        _ => return Err(Error::Unavailable),
    };
    let jit = match row.try_get::<&str, _>("jit").map_err(unavailable)? {
        "deny" => OidcJitPolicy::Deny,
        "allow" => OidcJitPolicy::Allow,
        _ => return Err(Error::Unavailable),
    };
    let issuer_refs: Vec<&str> = issuers.iter().map(String::as_str).collect();
    let actual = OidcIdentityPolicy::new(c.clone(), &issuer_refs, display)
        .map_err(|_| Error::Unavailable)?
        .with_jit(jit);
    if &actual != expected {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
