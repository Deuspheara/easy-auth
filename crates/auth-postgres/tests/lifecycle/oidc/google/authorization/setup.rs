use super::super::{
    provider::{CLIENT, ISSUER},
    setup::{Attempt, Fixture},
};
use auth_core::*;
use serde_json::{Value, json};
use std::sync::Arc;

const TOKEN_LIFETIME_SECONDS: i64 = 120;

pub(super) fn service(f: &Fixture) -> GoogleAuthorization {
    GoogleAuthorization::new(Arc::new(f.flow()), f.google.clone()).unwrap()
}

pub(super) async fn initiated(
    f: &Fixture,
    service: &GoogleAuthorization,
    attributes: Value,
) -> Attempt {
    let browser = Secret::generate().unwrap();
    let code = Secret::generate().unwrap();
    let start = service
        .begin(&OAuthIntent {
            browser: &browser,
            source: "owned-google-postgres",
            purpose: OAuthPurpose::SignIn,
        })
        .await
        .unwrap();
    let url = url::Url::parse(start.authorization_url.expose()).unwrap();
    let fields: Vec<_> = url.query_pairs().collect();
    assert_eq!(
        fields
            .iter()
            .filter(|(key, _)| key == "code_challenge_method")
            .map(|(_, value)| value.as_ref())
            .collect::<Vec<_>>(),
        ["S256"]
    );
    assert!(
        !start
            .authorization_url
            .expose()
            .contains(start.transaction.proof.pkce_verifier().expose())
    );
    let cap = start.transaction.expires_us;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.pool)
            .await
            .expect("test infrastructure: actual PostgreSQL clock");
    let mut claims = json!({"iss":ISSUER,"sub":"managed-google-subject","aud":CLIENT,"iat":now,"exp":now+TOKEN_LIFETIME_SECONDS,"nonce":start.transaction.proof.nonce().expose()});
    for (name, value) in attributes.as_object().unwrap() {
        claims[name] = value.clone();
    }
    f.provider
        .issue(&code, &start.transaction, f.policy.configuration(), claims);
    Attempt {
        start: start.transaction,
        browser,
        code,
        cap,
    }
}

pub(super) fn response(a: &Attempt, error: Option<&str>) -> GoogleAuthorizationResponse {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("state", a.start.state.expose())
        .append_pair("iss", ISSUER);
    if let Some(error) = error {
        form.append_pair("error", error)
            .append_pair("error_description", "private-provider-detail");
    } else {
        form.append_pair("code", a.code.expose())
            .append_pair("scope", "openid email profile");
    }
    GoogleAuthorizationResponse::parse(&form.finish()).unwrap()
}

pub(super) async fn finish(
    f: &Fixture,
    service: &GoogleAuthorization,
    a: &Attempt,
    error: Option<&str>,
) -> Result<GoogleAuthorizationCompletion> {
    service
        .finish(
            &a.intent(),
            &a.start.state,
            a.proof(),
            f.policy.configuration().redirect(),
            response(a, error),
        )
        .await
}

pub(super) async fn commit(f: &Fixture, completion: GoogleAuthorizationCompletion) -> User {
    let GoogleAuthorizationCompletion::Verified(identity) = completion else {
        panic!("owned signed positive control must verify");
    };
    let (owner, session) = f.sign_in(f.policy.map(*identity).unwrap()).await.unwrap();
    assert!(owner.email.is_none());
    assert_eq!(
        f.store
            .authenticate(f.realm(), session.verifier())
            .await
            .unwrap(),
        owner
    );
    owner
}
