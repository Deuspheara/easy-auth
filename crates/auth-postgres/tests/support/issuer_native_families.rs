use crate::support::issuer_tokens::Tokens;
use auth_core::{
    IssuerAuthorizationInput, IssuerClientAuthentication, IssuerClientRegistration,
    IssuerNativeAuthorization, IssuerNativeAuthorizationInput, IssuerNativeRefreshPolicy,
    IssuerNativeTokenIssuer, IssuerNativeTokens, IssuerTokenResult, Secret,
};
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) struct Fixture {
    pub(crate) base: Tokens,
    pub(crate) policy: IssuerNativeRefreshPolicy,
    pub(crate) consent: IssuerNativeAuthorization,
    pub(crate) issuer: IssuerNativeTokenIssuer,
}
impl Fixture {
    pub(crate) async fn new(pool: PgPool) -> Self {
        Self::with_client(pool, Uuid::new_v4()).await
    }
    pub(crate) async fn with_client(pool: PgPool, native_client: Uuid) -> Self {
        // Reuse the unchanged existing ordinary key/account producer. No new
        // cryptographic fixture or alternative signing implementation is added.
        let base = Tokens::new(pool).await;
        Self::for_base(base, native_client).await
    }
    pub(crate) async fn for_base(base: Tokens, native_client: Uuid) -> Self {
        let client = base
            .store
            .configure_issuer_client(
                &IssuerClientRegistration::public_native_refresh_loopback(
                    base.authority.realm(),
                    native_client,
                    &["http://127.0.0.1/cb"],
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let policy = base
            .store
            .configure_issuer_native_refresh_policy(
                &IssuerNativeRefreshPolicy::new(base.authority.clone(), client, 86400, 3600)
                    .unwrap(),
            )
            .await
            .unwrap();
        base.store
            .enable_issuer_native_refresh_policy(&policy)
            .await
            .unwrap();
        let consent = IssuerNativeAuthorization::new(base.authority.clone(), base.store.clone());
        let issuer = IssuerNativeTokenIssuer::new(&base.service(), base.store.clone());
        Self {
            base,
            policy,
            consent,
            issuer,
        }
    }
    pub(crate) async fn code(&self) -> Secret {
        let pending = self
            .consent
            .prepare(
                &self.base.current,
                &self.base.browser,
                &IssuerNativeAuthorizationInput {
                    authorization: IssuerAuthorizationInput {
                        client: self.policy.client().client(),
                        response_type: "code",
                        redirect_uri: "http://127.0.0.1:41002/cb",
                        scope: "openid offline_access",
                        state: "native-owned-state",
                        nonce: "native-owned-nonce",
                        code_challenge: &self.base.pkce.challenge(),
                        code_challenge_method: "S256",
                    },
                    prompt: "consent",
                },
            )
            .await
            .unwrap();
        let returned = self
            .consent
            .approve(
                &self.base.current,
                &self.base.browser,
                pending.handle(),
                pending.authorization(),
            )
            .await
            .unwrap();
        let url = url::Url::parse(returned.url()).unwrap();
        Secret::parse(
            url.query_pairs()
                .find(|(k, _)| k == "code")
                .unwrap()
                .1
                .into_owned(),
        )
        .unwrap()
    }
    pub(crate) fn authentication(&self) -> IssuerClientAuthentication {
        IssuerClientAuthentication::public(self.policy.client().client()).unwrap()
    }
    pub(crate) async fn exchange(&self, code: &Secret) -> IssuerTokenResult<IssuerNativeTokens> {
        self.issuer
            .exchange(
                &self.authentication(),
                code,
                "http://127.0.0.1:41002/cb",
                &self.base.pkce,
                "127.0.0.1",
            )
            .await
    }
    pub(crate) async fn facts(&self) -> (i64, i64, i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_issuer_native_families WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_native_refresh_tokens WHERE realm_id=$1),(SELECT count(*) FROM auth_issuer_access_tokens WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='issuer_native_created'),(SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='issuer_code_redeemed')")
            .bind(self.base.authority.realm()).fetch_one(&self.base.pool).await.unwrap()
    }
    pub(crate) fn refresher(&self) -> auth_core::IssuerNativeRefresh {
        auth_core::IssuerNativeRefresh::new(self.base.authority.clone(), self.base.store.clone())
    }
}
