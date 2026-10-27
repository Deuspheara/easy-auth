use super::{ProbeResult, input, preservation};
use auth_core::{Error, Repository, Secret};
use auth_postgres::Postgres;

const CAPTURE_SELECTED: bool = cfg!(feature = "apple-grants-web");
const LINKING_SELECTED: bool = cfg!(feature = "social-linking-web");

pub(super) async fn run() -> ProbeResult<()> {
    if CAPTURE_SELECTED || LINKING_SELECTED {
        return Err("probe must be built without capture/linking".into());
    }
    let input = input::read()?;
    let pool = input::pool().await?;
    let store = Postgres::new(pool.clone());
    let owner = store
        .authenticate(input.realm, input.session.verifier())
        .await?;
    let original = preservation::before(&pool, input.realm, owner.id).await?;
    if original.is_empty() {
        return Err("owned captured grant control required".into());
    }
    // Exercise the ordinary repository preparation/completion with actual bound
    // session and fresh generated private verifiers. This is a persistence probe,
    // not a browser/mail-delivery or public erasure-authority shortcut.
    let token = Secret::generate()?;
    let browser = Secret::generate()?;
    store
        .begin_account_deletion(
            input.realm,
            input.session.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await?;
    store
        .finish_account_deletion(
            input.realm,
            input.session.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await?;
    preservation::after(&pool, input.realm, owner.id, &original).await?;
    if !matches!(
        store
            .authenticate(input.realm, input.session.verifier())
            .await,
        Err(Error::Unauthorized)
    ) {
        return Err("owned erased session still accepted".into());
    }
    pool.close().await;
    println!(
        "{}",
        serde_json::json!({"deletion_confirmed":true,"captured_rows_preserved":original.len(),
        "ciphertext_unchanged":true,"capture_selected":CAPTURE_SELECTED,"linking_selected":LINKING_SELECTED})
    );
    Ok(())
}
