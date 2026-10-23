mod deadlines;
mod initial;
mod isolation;
mod lifecycle;
mod limits;
mod policy;
mod revocation;
mod rotation;
mod upgrade;

use auth_core::{
    IssuerClientAuthentication, IssuerClientRegistration, IssuerNativeAuthorization,
    IssuerNativeTokenIssuer, Secret,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::support::issuer_native_families::Fixture;
