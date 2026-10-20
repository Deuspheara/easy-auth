use super::{
    provider::{CLIENT, ISSUER, Provider},
    socket,
};
use crate::{
    settings::{ClaimsProfile, Settings},
    setup::Setup,
};
use auth_core::*;
use auth_postgres::Postgres;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::{future::pending, net::IpAddr, sync::Arc};

pub(super) struct Fixture {
    pub setup: Setup,
    pub provider: Arc<Provider>,
    pool: PgPool,
}
pub(super) struct Delivered {
    pub store: Arc<Postgres>,
    pub policy: OidcIdentityPolicy,
    pub provider: Arc<Provider>,
    pub result: Result<GoogleAuthorizationCompletion>,
}
impl Fixture {
    pub async fn new(
        pool: PgPool,
        profile: ClaimsProfile,
        ip: IpAddr,
        provider: Arc<Provider>,
    ) -> Self {
        let settings = Settings {
            client: CLIENT.to_owned(),
            authentication: provider.authentication(),
            ip,
            profile,
        };
        let setup = Setup::new(&pool, settings, provider.clone(), provider.clone())
            .await
            .unwrap();
        Self {
            setup,
            provider,
            pool,
        }
    }
    pub async fn delivered(self, attributes: Value) -> Delivered {
        let browser = Secret::generate().unwrap();
        let intent = OAuthIntent {
            browser: &browser,
            source: "manual-offline-control",
            purpose: OAuthPurpose::SignIn,
        };
        let start = self.setup.service.begin(&intent).await.unwrap();
        let url = url::Url::parse(start.authorization_url.expose()).unwrap();
        let uri = url::Url::parse(self.setup.listener.redirect().as_str()).unwrap();
        assert_eq!(field(&url, "redirect_uri"), uri.as_str());
        assert_eq!(field(&url, "code_challenge_method"), "S256");
        let challenge: Verifier = URL_SAFE_NO_PAD
            .decode(field(&url, "code_challenge"))
            .unwrap()
            .try_into()
            .unwrap();
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&self.pool)
                .await
                .expect("test infrastructure: actual PostgreSQL clock");
        let mut claims = json!({"iss":ISSUER,"aud":CLIENT,"sub":"manual-offline-subject","nonce":field(&url,"nonce"),"iat":now,"exp":now+120});
        for (name, value) in attributes.as_object().unwrap() {
            claims[name] = value.clone();
        }
        let code = Secret::generate().unwrap();
        self.provider
            .issue(&code, challenge, self.setup.policy.configuration(), claims);
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("state", start.transaction.state.expose())
            .append_pair("iss", ISSUER)
            .append_pair("code", code.expose())
            .finish();
        let request = socket::request(&uri, &query);
        let (received, response) = tokio::join!(
            self.setup.listener.receive(
                &start.transaction.state,
                start.transaction.expires_us,
                pending()
            ),
            socket::send(&uri, &request)
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "test infrastructure: actual callback response"
        );
        socket::stopped(&uri).await;
        let result = received
            .unwrap()
            .finish(
                &self.setup.service,
                &intent,
                &start.transaction.state,
                start.transaction.proof,
            )
            .await;
        Delivered {
            store: self.setup.store,
            policy: self.setup.policy,
            provider: self.provider,
            result,
        }
    }
}
fn field(url: &url::Url, name: &str) -> String {
    let values: Vec<_> = url
        .query_pairs()
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .collect();
    assert_eq!(values.len(), 1, "one original public authorization field");
    values[0].clone()
}
