mod boundary;
mod contract;
mod isolation;
mod lifecycle;
mod rollback;

use crate::support::issuer_web::{ORIGIN, read};
use crate::support::{cookie, post};
use auth_core::*;
use axum::http::header;
use easy_auth_axum::{BrowserConfig, experimental_issuer_native_consent_router};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

use crate::support::issuer_native::Fixture;
