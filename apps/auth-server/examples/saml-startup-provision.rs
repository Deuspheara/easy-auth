//! Owned startup-test provisioning only. Never configures a deployed database.
use auth_core::{
    SamlCertificateTrust, SamlIdentityPolicy, SamlPinnedCertificate, SamlRegistration,
};
use auth_postgres::Postgres;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::env;

type Outcome<T> = Result<T, Box<dyn std::error::Error>>;

fn public_fixture_trust() -> Outcome<SamlCertificateTrust> {
    // Unchanged upstream public certificate. No private key or signing is used.
    let pem = include_str!(
        "../../../third-party/saml-rs/tests/fixtures/interop/shibboleth-idp-5.2.3/idp-signing-cert.pem"
    );
    let encoded: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    Ok(SamlCertificateTrust::pinned_leaf(vec![
        SamlPinnedCertificate::from_der(&STANDARD.decode(encoded)?, 1_785_000_000, 2_000_000_000)?,
    ])?)
}

async fn provision() -> Outcome<()> {
    let database = env::var("DATABASE_URL")?;
    let url = url::Url::parse(&database)?;
    if !matches!(url.host_str(), Some("127.0.0.1" | "localhost"))
        || !url.path().starts_with("/easy_auth_saml_startup_")
    {
        return Err("owned loopback startup database required".into());
    }
    let pool = sqlx::PgPool::connect(&database).await?;
    let store = Postgres::new(pool.clone());
    store.migrate().await?;
    let realm = env::var("AUTH_REALM_ID")?.parse()?;
    store.ensure_realm(realm).await?;
    let registration = SamlRegistration::unsigned_redirect(
        realm,
        env::var("AUTH_SAML_CONNECTION_ID")?.parse()?,
        env::var("AUTH_SAML_LOCAL_CLIENT_ID")?.parse()?,
        &env::var("AUTH_SAML_SP_ENTITY")?,
        &env::var("AUTH_SAML_IDP_ENTITY")?,
        &env::var("AUTH_SAML_SSO_URL")?,
        &format!("{}/saml/acs", env::var("AUTH_PUBLIC_URL")?),
    )?;
    store
        .configure_saml_identity_policy(
            &SamlIdentityPolicy::new(registration),
            &public_fixture_trust()?,
        )
        .await?;
    pool.close().await;
    Ok(())
}

#[tokio::main]
async fn main() {
    if provision().await.is_err() {
        // Never expose database credentials or raw backend diagnostics.
        eprintln!("owned SAML startup provisioning failed");
        std::process::exit(1);
    }
}
