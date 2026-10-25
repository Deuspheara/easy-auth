//! Sequential test-only changes after signing; forwards the original opaque proof.
use async_trait::async_trait;
use auth_core::*;
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

pub(super) enum Action {
    DisableIssuer,
    DisableClient,
    RevokeSession,
    ShortenCode,
    WaitUntilExpiring,
}
pub(super) struct Probe {
    pub store: Arc<Postgres>,
    pub pool: PgPool,
    pub action: Action,
}
#[async_trait]
impl IssuerTokenRepository for Probe {
    async fn prepare_issuer_token(
        &self,
        request: &IssuerCodeRedemption<'_>,
    ) -> IssuerTokenResult<IssuerTokenPreparationData> {
        self.store.prepare_issuer_token(request).await
    }
    async fn commit_issuer_token(&self, signed: &IssuerSignedCode<'_>) -> IssuerTokenResult<i64> {
        let request = signed.redemption();
        match self.action {
            Action::DisableIssuer => self.store.disable_issuer_signing(request.authority).await?,
            Action::DisableClient => {
                self.store
                    .disable_issuer_client(request.authority.realm(), request.client.client())
                    .await?
            }
            Action::RevokeSession => {
                sqlx::query("UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1 AND id=$2")
                    .bind(request.authority.realm()).bind(signed.grant().session).execute(&self.pool).await.map_err(|_|Error::Unavailable)?;
            }
            Action::ShortenCode => {
                sqlx::query("UPDATE auth_issuer_authorizations SET code_expires_at_us=code_expires_at_us-1 WHERE realm_id=$1 AND id=$2")
                    .bind(request.authority.realm()).bind(signed.grant().authorization).execute(&self.pool).await.map_err(|_|Error::Unavailable)?;
            }
            Action::WaitUntilExpiring => {
                // One completed ordinary signature, no transaction/crypto race.
                // Delay final admission until less than its required second remains.
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    loop {
                        let now: i64 = sqlx::query_scalar(
                            "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint",
                        )
                        .fetch_one(&self.pool)
                        .await
                        .map_err(|_| Error::Unavailable)?;
                        if now >= signed.expires_at_us() - 500_000 {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                    Ok::<(), Error>(())
                })
                .await
                .map_err(|_| IssuerTokenError::Unavailable)??;
            }
        }
        self.store.commit_issuer_token(signed).await
    }
}
#[async_trait]
impl IssuerAuthorizationRepository for Probe {
    async fn load_issuer_client(
        &self,
        realm: Uuid,
        client: Uuid,
    ) -> Result<IssuerClientRegistration> {
        self.store.load_issuer_client(realm, client).await
    }
    async fn admit_issuer_redemption(
        &self,
        authority: &IssuerAuthority,
        source: Verifier,
    ) -> Result<()> {
        self.store.admit_issuer_redemption(authority, source).await
    }
    async fn save_issuer_authorization(
        &self,
        request: &IssuerAuthorizationRequest,
        current: Verifier,
        browser: Verifier,
        handle: Verifier,
    ) -> Result<i64> {
        self.store
            .save_issuer_authorization(request, current, browser, handle)
            .await
    }
    async fn preview_issuer_authorization(
        &self,
        proof: &IssuerConsentProof<'_>,
    ) -> Result<IssuerAuthorizationDestination> {
        self.store.preview_issuer_authorization(proof).await
    }
    async fn approve_issuer_authorization(
        &self,
        proof: &IssuerConsentProof<'_>,
        code: Verifier,
    ) -> Result<IssuerAuthorizationDestination> {
        self.store.approve_issuer_authorization(proof, code).await
    }
    async fn cancel_issuer_authorization(
        &self,
        proof: &IssuerConsentProof<'_>,
    ) -> Result<IssuerAuthorizationDestination> {
        self.store.cancel_issuer_authorization(proof).await
    }
    async fn redeem_issuer_code(
        &self,
        request: &IssuerCodeRedemption<'_>,
    ) -> IssuerTokenResult<IssuerGrantData> {
        self.store.redeem_issuer_code(request).await
    }
}
