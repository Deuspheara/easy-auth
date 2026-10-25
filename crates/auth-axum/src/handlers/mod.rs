pub(crate) mod account;
pub(crate) mod email;
pub(crate) mod health;
pub(crate) mod passwords;
pub(crate) mod providers;
pub(crate) mod recovery;
pub(crate) mod sessions;

use axum::{Extension, extract::ConnectInfo};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmailInput {
    pub(crate) email: String,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinishInput {
    pub(crate) token: String,
}
#[derive(Serialize, ToSchema)]
pub(crate) struct Accepted {
    pub(crate) status: &'static str,
}
#[derive(Serialize, ToSchema)]
pub(crate) struct UserResponse {
    pub(crate) id: Uuid,
    pub(crate) realm_id: Uuid,
    #[schema(required = true)]
    pub(crate) email: Option<String>,
    #[schema(required = true)]
    pub(crate) display_name: Option<String>,
    /// mailbox, passkey_required or provider_required; current method/freshness still governs APIs.
    #[schema(value_type=String)]
    pub(crate) authentication_policy: auth_core::AuthenticationPolicy,
}

pub(super) fn source_key(source: Option<Extension<ConnectInfo<SocketAddr>>>) -> String {
    source
        .map(|Extension(ConnectInfo(addr))| addr.ip().to_string())
        .unwrap_or_else(|| "embedded".to_owned())
}
