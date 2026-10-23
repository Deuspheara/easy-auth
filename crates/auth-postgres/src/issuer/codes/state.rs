use crate::{Postgres, sessions::FreshSessionAuthorization, unavailable};
use auth_core::{
    Error, IssuerClientRegistration, IssuerCodeRedemption, IssuerConsentProof, Result,
};
use sqlx::{Postgres as Pg, Transaction};
use uuid::Uuid;

// No Debug/Serialize: these are private pending correlation data and digests.
#[derive(sqlx::FromRow, PartialEq, Eq)]
pub(super) struct AuthorizationState {
    pub(super) realm_id: Uuid,
    pub(super) id: Uuid,
    pub(super) issuer: String,
    pub(super) client_id: Uuid,
    pub(super) client_revision: Uuid,
    pub(super) sector: String,
    pub(super) user_id: Uuid,
    pub(super) session_id: Uuid,
    pub(super) authentication_method: String,
    pub(super) authenticated_at_us: i64,
    pub(super) session_cap_us: i64,
    pub(super) handle_hash: Vec<u8>,
    pub(super) browser_hash: Vec<u8>,
    pub(super) redirect_uri: String,
    pub(super) state: Option<String>,
    pub(super) nonce: Option<String>,
    pub(super) pkce_challenge: Option<Vec<u8>>,
    pub(super) status: String,
    pub(super) subject: Option<Uuid>,
    pub(super) code_hash: Option<Vec<u8>>,
    pub(super) created_at_us: i64,
    pub(super) expires_at_us: i64,
    pub(super) approved_at_us: Option<i64>,
    pub(super) code_expires_at_us: Option<i64>,
    pub(super) consumed_at_us: Option<i64>,
}
pub(super) async fn pending(
    store: &Postgres,
    proof: &IssuerConsentProof<'_>,
) -> Result<AuthorizationState> {
    sqlx::query_as(
        r#"
            SELECT *
            FROM auth_issuer_authorizations
            WHERE realm_id=$1
            AND issuer=$2
            AND id=$3
            AND handle_hash=$4
            AND browser_hash=$5
            AND status='pending'
        "#,
    )
    .bind(proof.authority.realm())
    .bind(proof.authority.issuer())
    .bind(proof.authorization)
    .bind(proof.handle.as_slice())
    .bind(proof.browser.as_slice())
    .fetch_optional(&store.pool)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)
}
pub(super) async fn lock_pending(
    tx: &mut Transaction<'_, Pg>,
    proof: &IssuerConsentProof<'_>,
    client: &IssuerClientRegistration,
    caller: &FreshSessionAuthorization,
) -> Result<AuthorizationState> {
    sqlx::query_as(
        r#"
            SELECT *
            FROM auth_issuer_authorizations
            WHERE realm_id=$1
            AND issuer=$2
            AND id=$3
            AND handle_hash=$4
            AND browser_hash=$5
            AND status='pending'
            AND client_id=$6
            AND client_revision=$7
            AND sector=$8
            AND user_id=$9
            AND session_id=$10
            AND authentication_method=$11
            AND authenticated_at_us=$12
            AND expires_at_us>(extract(epoch FROM clock_timestamp())*1000000)::bigint FOR UPDATE
        "#,
    )
    .bind(proof.authority.realm())
    .bind(proof.authority.issuer())
    .bind(proof.authorization)
    .bind(proof.handle.as_slice())
    .bind(proof.browser.as_slice())
    .bind(client.client())
    .bind(client.revision())
    .bind(client.sector())
    .bind(caller.user)
    .bind(caller.session)
    .bind(&caller.method)
    .bind(caller.authenticated_at_us)
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)
}
pub(super) async fn code(
    store: &Postgres,
    request: &IssuerCodeRedemption<'_>,
) -> Result<Option<AuthorizationState>> {
    sqlx::query_as("SELECT * FROM auth_issuer_authorizations WHERE realm_id=$1 AND issuer=$2 AND client_id=$3 AND code_hash=$4 AND status='approved'")
        .bind(request.authority.realm()).bind(request.authority.issuer()).bind(request.client.client())
        .bind(request.code.as_slice()).fetch_optional(&store.pool).await.map_err(unavailable)
}
pub(super) async fn lock_code(
    tx: &mut Transaction<'_, Pg>,
    request: &IssuerCodeRedemption<'_>,
    caller: &FreshSessionAuthorization,
) -> Result<AuthorizationState> {
    sqlx::query_as(
        r#"
            SELECT *
            FROM auth_issuer_authorizations
            WHERE realm_id=$1
            AND issuer=$2
            AND client_id=$3
            AND client_revision=$4
            AND sector=$5
            AND code_hash=$6
            AND status='approved'
            AND user_id=$7
            AND session_id=$8
            AND authentication_method=$9
            AND authenticated_at_us=$10
            AND redirect_uri=$11
            AND pkce_challenge=$12
            AND code_expires_at_us>(extract(epoch FROM clock_timestamp())*1000000)::bigint FOR UPDATE
        "#,
    )
    .bind(request.authority.realm())
    .bind(request.authority.issuer())
    .bind(request.client.client())
    .bind(request.client.revision())
    .bind(request.client.sector())
    .bind(request.code.as_slice())
    .bind(caller.user)
    .bind(caller.session)
    .bind(&caller.method)
    .bind(caller.authenticated_at_us)
    .bind(request.redirect_uri)
    .bind(request.pkce.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)
}
