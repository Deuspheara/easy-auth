mod boundary;
mod lifecycle;
#[cfg(feature = "issuer-token-management-web")]
mod management;
mod metadata;
#[cfg(feature = "oidc-web")]
mod rp;
#[cfg(feature = "oidc-web")]
mod rp_transport;

use auth_core::*;
use axum::http::header;
use base64::{Engine, engine::general_purpose::STANDARD};
use josekit::jws::RS256;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use crate::support::issuer_web::{Fixture, ORIGIN, Profile, get, read, token_request};
