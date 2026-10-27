use super::{
    google_provider::{CLIENT, ISSUER, Provider},
    setup::*,
};
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use uuid::Uuid;

pub(super) struct GoogleFixture {
    pub pool: PgPool,
    pub store: Arc<Postgres>,
    pub policy: OidcIdentityPolicy,
    pub provider: Arc<Provider>,
    sign_in: GoogleAuthorization,
    link: GoogleIdentityLinkAuthorization,
    pub linking: OidcIdentityLinking,
}
impl GoogleFixture {
    pub async fn new(pool: PgPool) -> Self {
        let (store, realm) = crate::support::realm(pool.clone()).await;
        let store = Arc::new(store);
        let config = OAuthConnection::new(
            realm,
            Uuid::new_v4(),
            Uuid::new_v4(),
            ISSUER,
            CLIENT,
            &format!("https://app.example/google/link/{realm}"),
            OAuthMixupDefense::RequireIssuer,
        )
        .unwrap();
        let policy = store
            .configure_oidc_identity_policy(
                &OidcIdentityPolicy::new(config, &[ISSUER], OidcDisplayNameClaim::Subject)
                    .unwrap()
                    .with_jit(OidcJitPolicy::Allow),
            )
            .await
            .unwrap();
        let provider = Provider::new();
        let exchange = Arc::new(
            GoogleCodeExchange::new(
                policy.configuration().clone(),
                store.clone(),
                store.clone(),
                provider.authentication(),
                provider.clone(),
                provider.clone(),
            )
            .unwrap()
            .with_session_age_claims(),
        );
        let transactions = Arc::new(OAuthTransactions::new(
            policy.configuration().clone(),
            store.clone(),
        ));
        let sign_in =
            GoogleAuthorization::new_session_age(transactions.clone(), exchange.clone()).unwrap();
        let link =
            GoogleIdentityLinkAuthorization::new_session_age(transactions, exchange).unwrap();
        let linking = OidcIdentityLinking::new(store.clone());
        Self {
            pool,
            store,
            policy,
            provider,
            sign_in,
            link,
            linking,
        }
    }
    pub fn realm(&self) -> Uuid {
        self.policy.configuration().realm()
    }
    pub async fn local(&self, email: &str) -> (User, Secret) {
        let current = crate::support::signed_in(self.store.as_ref(), self.realm(), email).await;
        let owner = self
            .store
            .authenticate(self.realm(), current.verifier())
            .await
            .unwrap();
        (owner, current)
    }
    pub async fn mapped(&self, purpose: OAuthPurpose, subject: &str) -> OidcMappedIdentity {
        let browser = Secret::generate().unwrap();
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-google-linking",
            purpose: purpose.clone(),
        };
        let start = match purpose {
            OAuthPurpose::SignIn => self.sign_in.begin(&intent).await,
            OAuthPurpose::Link { .. } => self.link.begin(&intent).await,
            _ => panic!("fixture purpose unsupported"),
        }
        .unwrap();
        let public = url::Url::parse(start.authorization_url.expose()).unwrap();
        let field = |name: &str| {
            let values: Vec<_> = public
                .query_pairs()
                .filter(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
                .collect();
            assert_eq!(values.len(), 1);
            values[0].clone()
        };
        assert_eq!(field("client_id"), CLIENT);
        assert_eq!(
            field("redirect_uri"),
            self.policy.configuration().redirect()
        );
        assert_eq!(field("code_challenge_method"), "S256");
        // Public digest bytes only, after checking the actual wire projection.
        // The producer never receives the private PKCE verifier.
        assert_eq!(
            field("code_challenge"),
            start.transaction.proof.code_challenge()
        );
        assert_eq!(
            serde_json::from_str::<Value>(&field("claims")).unwrap(),
            json!({"id_token":{"auth_time":{"essential":true}}})
        );
        if matches!(purpose, OAuthPurpose::Link { .. }) {
            assert_eq!(field("prompt"), "select_account");
        }
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&self.pool)
                .await
                .unwrap();
        let code = Secret::generate().unwrap();
        self.provider.issue(&code,start.transaction.proof.pkce_verifier().verifier(),self.policy.configuration(),json!({"iss":ISSUER,"aud":CLIENT,"sub":subject,"iat":now,"exp":now+120,"nonce":field("nonce"),"auth_time":now}));
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("state", &field("state"))
            .append_pair("code", code.expose())
            .append_pair("iss", ISSUER);
        let response = GoogleAuthorizationResponse::parse(&form.finish()).unwrap();
        let proof = OAuthBrowserProof::parse(
            start.transaction.proof.nonce().expose().to_owned(),
            start.transaction.proof.pkce_verifier().expose().to_owned(),
        )
        .unwrap();
        let completed = match purpose {
            OAuthPurpose::SignIn => {
                self.sign_in
                    .finish(
                        &intent,
                        &start.transaction.state,
                        proof,
                        self.policy.configuration().redirect(),
                        response,
                    )
                    .await
            }
            OAuthPurpose::Link { .. } => {
                self.link
                    .finish(
                        &intent,
                        &start.transaction.state,
                        proof,
                        self.policy.configuration().redirect(),
                        response,
                    )
                    .await
            }
            _ => unreachable!(),
        }
        .unwrap();
        match completed {
            GoogleAuthorizationCompletion::Verified(identity) => {
                self.policy.map(*identity).unwrap()
            }
            _ => panic!("owned normal signed response must verify"),
        }
    }
    pub async fn login(&self, subject: &str) -> (User, Secret) {
        OidcSignIn::new(self.store.clone())
            .finish(self.mapped(OAuthPurpose::SignIn, subject).await)
            .await
            .unwrap()
    }
    pub async fn linked(&self, owner: &User, current: &Secret, subject: &str) -> LinkedProvider {
        self.linking
            .finish(
                self.mapped(
                    OAuthPurpose::Link {
                        user: owner.id,
                        session: current.verifier(),
                    },
                    subject,
                )
                .await,
                current,
            )
            .await
            .unwrap()
    }
    pub async fn identity(&self, subject: &str) -> Uuid {
        sqlx::query_scalar("SELECT id FROM auth_oidc_identities WHERE realm_id=$1 AND subject=$2")
            .bind(self.realm())
            .bind(subject)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}
