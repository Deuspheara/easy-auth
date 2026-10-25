mod credentials;
mod lifecycle;
mod migration;
mod ordering;
mod policy;

use super::token_setup::Tokens;
use auth_core::{
    IssuerClientAuthentication, IssuerClientRegistration, IssuerPresentedToken,
    IssuerTokenManagement, IssuerTokens, Secret,
};
use sqlx::PgPool;

struct Fixture {
    f: Tokens,
    secret: Option<Secret>,
    issued: IssuerTokens,
}
impl Fixture {
    async fn new(pool: PgPool, confidential: bool) -> Self {
        let mut f = Tokens::new(pool).await;
        let secret = confidential.then(|| Secret::generate().unwrap());
        if let Some(secret) = &secret {
            f.client = f
                .store
                .configure_issuer_client(
                    &IssuerClientRegistration::confidential(
                        f.authority.realm(),
                        f.client.client(),
                        &["https://app.example/cb"],
                        secret,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
        }
        let authentication = match &secret {
            Some(secret) => IssuerClientAuthentication::basic(f.client.client(), secret).unwrap(),
            None => f.authentication(),
        };
        let issued = f
            .service()
            .exchange(
                &authentication,
                &f.code().await,
                "https://app.example/cb",
                &f.pkce,
                "127.0.0.1",
            )
            .await
            .unwrap();
        Self { f, secret, issued }
    }
    fn service(&self) -> IssuerTokenManagement {
        IssuerTokenManagement::new(self.f.authority.clone(), self.f.store.clone())
    }
    fn authentication(&self) -> IssuerClientAuthentication {
        match &self.secret {
            Some(secret) => {
                IssuerClientAuthentication::basic(self.f.client.client(), secret).unwrap()
            }
            None => self.f.authentication(),
        }
    }
    async fn revoked(&self) -> Option<i64> {
        sqlx::query_scalar("SELECT revoked_at_us FROM auth_issuer_access_tokens WHERE realm_id=$1 AND access_hash=$2")
            .bind(self.f.authority.realm()).bind(self.issued.access_token().verifier().as_slice()).fetch_one(&self.f.pool).await.unwrap()
    }
}
