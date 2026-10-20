use super::*;
use auth_axum::OidcAccountDeletionServices;
use url::Url;

impl Fixture {
    pub(super) async fn new(mut config: Value, database: &Database) -> FixtureResult<Self> {
        let issuer = config["issuer"]
            .as_str()
            .ok_or("fixture issuer")?
            .to_owned();
        let address = config["address"]
            .as_str()
            .ok_or("fixture address")?
            .parse()?;
        let certificate = serde_json::from_value(config["certificate_der"].take())?;
        let store = Arc::new(Postgres::new(database.pool.clone()));
        send(json!({"phase":"database_migration"}))?;
        store.migrate().await?;
        let realm = uuid::Uuid::new_v4();
        store.ensure_realm(realm).await?;
        let connection = OAuthConnection::new(
            realm,
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            &issuer,
            config["client"].as_str().ok_or("fixture client")?,
            config["redirect"].as_str().ok_or("fixture redirect")?,
            OAuthMixupDefense::RequireIssuer,
        )?;
        let policy =
            OidcIdentityPolicy::new(connection, &[&issuer], OidcDisplayNameClaim::Subject)?
                .with_jit(OidcJitPolicy::Allow);
        let policy = store.configure_oidc_identity_policy(&policy).await?;
        let http = Http::new(&issuer, address, certificate)?;
        let secret = config["secret"]
            .take()
            .as_str()
            .ok_or("fixture credential")?
            .to_owned();
        let exchange = Arc::new(crate::protocol::exchange(
            policy.configuration(),
            store.clone(),
            http.clone(),
            secret,
        )?);
        let transactions = Arc::new(OAuthTransactions::new(
            policy.configuration().clone(),
            store.clone(),
        ));
        let observation = Arc::new(Observation::new(
            store.clone(),
            database.pool.clone(),
            policy.clone(),
            config["subject"]
                .as_str()
                .ok_or("fixture subject")?
                .to_owned(),
        ));
        let services = OidcAccountDeletionServices::new(
            policy.clone(),
            transactions.clone(),
            exchange.clone(),
            Arc::new(OidcAccountDeletion::new(observation.clone())),
        )?;
        let mail = Arc::new(NoDelivery::default());
        let auth = Auth::new(realm, store.clone(), mail.clone());
        let origin = Url::parse(policy.configuration().redirect())?
            .origin()
            .ascii_serialization();
        let server = Server::new(auth.clone(), &origin, services).await?;
        Ok(Self {
            pool: database.pool.clone(),
            store,
            policy,
            transactions,
            exchange,
            auth,
            server,
            observation,
            mail,
            http,
            pending: None,
            replay: None,
            current: None,
        })
    }
}
