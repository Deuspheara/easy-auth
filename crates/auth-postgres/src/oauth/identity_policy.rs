use super::configuration;
use crate::{Postgres, unavailable};
use auth_core::{OAuthConnection, OidcDisplayNameClaim, OidcIdentityPolicy, OidcJitPolicy, Result};

impl Postgres {
    /// Trusted administration only. Policy changes allocate a new configuration
    /// revision and cancel prior pending state in the same transaction. Applying
    /// policy never clears an existing connection disable. Use the returned policy.
    pub async fn configure_oidc_identity_policy(
        &self,
        input: &OidcIdentityPolicy,
    ) -> Result<OidcIdentityPolicy> {
        let current = input.configuration();
        let connection = OAuthConnection::new(
            current.realm(),
            current.connection(),
            current.client(),
            current.issuer(),
            current.provider_client(),
            current.redirect(),
            current.defense(),
        )?;
        let issuers: Vec<&str> = input.allowed_issuers().iter().map(String::as_str).collect();
        let policy = OidcIdentityPolicy::new(connection, &issuers, input.display_name_claim())?
            .with_jit(input.jit());
        let display_claim = match policy.display_name_claim() {
            OidcDisplayNameClaim::Subject => "sub",
            OidcDisplayNameClaim::Name => "name",
            OidcDisplayNameClaim::PreferredUsername => "preferred_username",
        };
        let jit = match policy.jit() {
            OidcJitPolicy::Deny => "deny",
            OidcJitPolicy::Allow => "allow",
        };
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let connection = policy.configuration();
        configuration::replace(&mut tx, connection).await?;
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
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(policy)
    }
}
