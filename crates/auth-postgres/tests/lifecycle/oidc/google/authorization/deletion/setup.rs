use super::super::super::{
    provider::{CLIENT, ISSUER},
    session_age::setup::selected,
    setup::{Attempt, Fixture},
};
use auth_core::*;
use serde_json::{Value, json};
use std::sync::Arc;

const TOKEN_LIFETIME_SECONDS: i64 = 120;

pub(super) fn service(f: &Fixture) -> GoogleAccountDeletionAuthorization {
    GoogleAccountDeletionAuthorization::new(Arc::new(f.flow()), Arc::new(selected(f))).unwrap()
}
pub(super) async fn account(f: &Fixture) -> (User, Secret) {
    f.sign_in(f.mapped("managed-deletion", json!({})).await)
        .await
        .unwrap()
}
pub(super) fn intent<'a>(browser: &'a Secret, user: &User, session: &Secret) -> OAuthIntent<'a> {
    OAuthIntent {
        browser,
        source: "owned-google-managed-deletion",
        purpose: OAuthPurpose::DeleteProviderAccount {
            user: user.id,
            session: session.verifier(),
        },
    }
}
pub(super) async fn now(f: &Fixture) -> i64 {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        .fetch_one(&f.pool)
        .await
        .expect("test infrastructure: real managed deletion clock")
}
pub(super) async fn initiated(
    f: &Fixture,
    service: &GoogleAccountDeletionAuthorization,
    user: &User,
    session: &Secret,
    attributes: Value,
) -> Attempt {
    let browser = Secret::generate().unwrap();
    let code = Secret::generate().unwrap();
    let start = service
        .begin(&intent(&browser, user, session))
        .await
        .unwrap();
    let url = url::Url::parse(start.authorization_url.expose()).unwrap();
    let pairs: Vec<_> = url.query_pairs().collect();
    assert_eq!(pairs.iter().filter(|(name, _)| name == "claims").count(), 1);
    assert!(pairs.iter().any(|(name, value)| name == "claims"
        && serde_json::from_str::<Value>(value).unwrap()
            == json!({"id_token":{"auth_time":{"essential":true}}})));
    assert!(
        !pairs
            .iter()
            .any(|(name, _)| matches!(name.as_ref(), "prompt" | "max_age"))
    );
    let now = now(f).await;
    let mut claims = json!({"iss":ISSUER,"sub":"managed-deletion","aud":CLIENT,"iat":now,
        "exp":now+TOKEN_LIFETIME_SECONDS,"nonce":start.transaction.proof.nonce().expose()});
    for (name, value) in attributes.as_object().unwrap() {
        claims[name] = value.clone();
    }
    f.provider.issue(
        &code,
        start.transaction.proof.pkce_verifier().verifier(),
        f.policy.configuration(),
        claims,
    );
    let cap = start.transaction.expires_us;
    Attempt {
        start: start.transaction,
        browser,
        code,
        cap,
    }
}
pub(super) async fn finish(
    f: &Fixture,
    service: &GoogleAccountDeletionAuthorization,
    a: &Attempt,
    user: &User,
    session: &Secret,
    error: Option<&str>,
) -> Result<GoogleAuthorizationCompletion> {
    service
        .finish(
            &intent(&a.browser, user, session),
            &a.start.state,
            a.proof(),
            f.policy.configuration().redirect(),
            super::super::setup::response(a, error),
        )
        .await
}
pub(super) async fn remove(f: &Fixture, completion: GoogleAuthorizationCompletion) -> Result<()> {
    let GoogleAuthorizationCompletion::Verified(identity) = completion else {
        panic!("owned signed deletion control must verify");
    };
    OidcAccountDeletion::new(f.store.clone())
        .finish(f.policy.map(*identity)?)
        .await
}
