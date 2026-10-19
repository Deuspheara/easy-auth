use super::{FixtureResult, database::Database, read_command, send, transport::Http};
use auth_core::*;
use auth_postgres::Postgres;
use serde_json::{Value, json};
use std::{
    io::BufRead,
    sync::{Arc, atomic::Ordering},
};
use uuid::Uuid;
use zeroize::Zeroizing;

struct Pending {
    browser: Secret,
    start: OAuthStart,
}
struct Replay {
    browser: Secret,
    state: Secret,
    nonce: Zeroizing<String>,
    pkce: Zeroizing<String>,
}
struct Fixture {
    store: Arc<Postgres>,
    connection: OAuthConnection,
    transactions: OAuthTransactions,
    exchange: OidcCodeExchange,
    http: Arc<Http>,
    expected_subject: String,
    pending: Option<Pending>,
    replay: Option<Replay>,
}
impl Fixture {
    async fn new(mut config: Value, database: &Database) -> FixtureResult<Self> {
        let issuer = config["issuer"]
            .as_str()
            .ok_or("fixture issuer")?
            .to_owned();
        let address = config["address"]
            .as_str()
            .ok_or("fixture address")?
            .parse()?;
        let certificate: Vec<u8> = serde_json::from_value(config["certificate_der"].take())?;
        let store = Arc::new(Postgres::new(database.pool.clone()));
        send(json!({"phase":"database_migration"}))?;
        store.migrate().await?;
        let realm = Uuid::new_v4();
        store.ensure_realm(realm).await?;
        let input = OAuthConnection::new(
            realm,
            Uuid::new_v4(),
            Uuid::new_v4(),
            &issuer,
            config["client"].as_str().ok_or("fixture client")?,
            config["redirect"].as_str().ok_or("fixture redirect")?,
            OAuthMixupDefense::RequireIssuer,
        )?;
        send(json!({"phase":"connection_configuration"}))?;
        let connection = store.configure_oauth_connection(&input).await?;
        send(json!({"phase":"tls_configuration"}))?;
        let http = Http::new(&issuer, address, certificate)?;
        let origin = url::Url::parse(&issuer)?.origin().ascii_serialization();
        send(json!({"phase":"document_configuration"}))?;
        let documents = Arc::new(OidcDocuments::new(
            connection.clone(),
            &[&origin],
            store.clone(),
            http.clone(),
        )?);
        send(json!({"phase":"exchange_configuration"}))?;
        let secret = config["secret"]
            .take()
            .as_str()
            .ok_or("fixture credential")?
            .to_owned();
        let exchange = OidcCodeExchange::new(
            documents,
            store.clone(),
            OidcVerificationPolicy::new(&[OidcSigningAlgorithm::RS256], &[])?,
            OidcClientAuthentication::ClientSecretBasic(OidcClientSecret::parse(secret)?),
            http.clone(),
        );
        Ok(Self {
            transactions: OAuthTransactions::new(connection.clone(), store.clone()),
            store,
            connection,
            exchange,
            http,
            expected_subject: config["subject"]
                .as_str()
                .ok_or("fixture subject")?
                .to_owned(),
            pending: None,
            replay: None,
        })
    }
    async fn begin(&mut self) -> auth_core::Result<Value> {
        if self.pending.is_some() {
            return Err(Error::InvalidInput);
        }
        let browser = Secret::generate()?;
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-keycloak",
            purpose: OAuthPurpose::SignIn,
        };
        let start = self.transactions.begin(&intent).await?;
        let authorization = self
            .exchange
            .authorization_url(&start, &["profile"])
            .await?;
        let response = json!({"result":"started","authorization":authorization.expose()});
        self.pending = Some(Pending { browser, start });
        Ok(response)
    }
    async fn finish(&mut self, callback: &str) -> auth_core::Result<Value> {
        let Pending { browser, start } = self.pending.take().ok_or(Error::InvalidInput)?;
        let url = url::Url::parse(callback).map_err(|_| Error::Unauthorized)?;
        let mut base = url.clone();
        base.set_query(None);
        if base.as_str() != self.connection.redirect() {
            return Err(Error::Unauthorized);
        }
        let pairs: Vec<_> = url.query_pairs().collect();
        let value = |name: &str| -> auth_core::Result<&str> {
            let values: Vec<_> = pairs.iter().filter(|(key, _)| key == name).collect();
            if values.len() != 1 {
                return Err(Error::Unauthorized);
            }
            Ok(values[0].1.as_ref())
        };
        let state = Secret::parse(value("state")?.to_owned())?;
        let proof = OAuthBrowserProof::parse(
            start.proof.nonce().expose().to_owned(),
            start.proof.pkce_verifier().expose().to_owned(),
        )?;
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-keycloak",
            purpose: OAuthPurpose::SignIn,
        };
        let context = self
            .transactions
            .consume(
                &intent,
                &state,
                proof,
                OAuthCallback {
                    redirect: self.connection.redirect(),
                    issuer: Some(value("iss")?),
                },
            )
            .await?;
        // Retain original protected transport material only to test an exact
        // replay of consumed PostgreSQL state. This adds no production hook.
        self.replay = Some(Replay {
            browser,
            state: start.state,
            nonce: Zeroizing::new(start.proof.nonce().expose().to_owned()),
            pkce: Zeroizing::new(start.proof.pkce_verifier().expose().to_owned()),
        });
        let cap = context.expires_us();
        let identity = self
            .exchange
            .exchange(
                context,
                OidcAuthorizationCode::parse(value("code")?.to_owned())?,
            )
            .await?;
        Ok(
            json!({"result":"verified","subject_matches":identity.subject()==self.expected_subject,
            "email_absent":identity.email().is_none(),"email_verified":identity.email_verified(),
            "same_configuration":identity.configuration()==&self.connection,
            "original_cap_retained":identity.expires_us()<=cap,
            "authenticated_time_present":identity.authenticated_at().is_some()}),
        )
    }
    async fn replay_state(&self) -> auth_core::Result<Value> {
        let replay = self.replay.as_ref().ok_or(Error::InvalidInput)?;
        let intent = OAuthIntent {
            browser: &replay.browser,
            source: "owned-keycloak",
            purpose: OAuthPurpose::SignIn,
        };
        self.transactions
            .consume(
                &intent,
                &replay.state,
                OAuthBrowserProof::parse(replay.nonce.to_string(), replay.pkce.to_string())?,
                OAuthCallback {
                    redirect: self.connection.redirect(),
                    issuer: Some(self.connection.issuer()),
                },
            )
            .await?;
        Ok(json!({"result":"unexpected-state-reuse"}))
    }
    async fn command(&mut self, command: &Value) -> auth_core::Result<Value> {
        match command["command"].as_str() {
            Some("begin") => self.begin().await,
            Some("finish") => {
                self.finish(command["callback"].as_str().ok_or(Error::InvalidInput)?)
                    .await
            }
            Some("replay_state") => self.replay_state().await,
            Some("disable") => {
                self.store
                    .disable_oauth_connection(
                        self.connection.realm(),
                        self.connection.connection(),
                        self.connection.client(),
                    )
                    .await?;
                Ok(json!({"result":"disabled"}))
            }
            _ => Err(Error::InvalidInput),
        }
    }
}
fn classified(result: auth_core::Result<Value>) -> Value {
    match result {
        Ok(value) => value,
        Err(error) => json!({"result":match error {
            Error::Unauthorized=>"unauthorized",Error::Unavailable=>"unavailable",
            Error::RateLimited=>"rate_limited",Error::InvalidInput=>"invalid_input"
        }}),
    }
}
pub(super) async fn run(
    config: Value,
    database: &Database,
    input: &mut impl BufRead,
) -> FixtureResult<()> {
    let mut fixture = Fixture::new(config, database).await?;
    send(json!({"ready":true}))?;
    while let Some(command) = read_command(input)? {
        if command["command"].as_str() == Some("close") {
            break;
        }
        let before_posts = fixture.http.posts.load(Ordering::SeqCst);
        let mut response = classified(fixture.command(&command).await);
        response["post_delta"] = (fixture.http.posts.load(Ordering::SeqCst) - before_posts).into();
        response["gets"] = fixture.http.gets.load(Ordering::SeqCst).into();
        response["id"] = command["id"].clone();
        send(response)?;
    }
    let facts:(i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit),(SELECT count(*) FROM auth_oauth_transactions)").fetch_one(&database.pool).await?;
    send(json!({"facts":{"users":facts.0,"sessions":facts.1,"audit":facts.2,"pending":facts.3}}))?;
    Ok(())
}
