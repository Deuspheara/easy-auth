mod configuration;
mod isolation;
mod key_policy;
mod lifecycle;
mod ordering;
mod upgrade;
use crate::support::{issuer_native_consumers::Consumer, issuer_native_families::Fixture};
use auth_core::*;
use sqlx::PgPool;
use uuid::Uuid;

async fn issued(f: &Fixture) -> IssuerNativeTokens {
    f.exchange(&f.code().await).await.unwrap()
}
