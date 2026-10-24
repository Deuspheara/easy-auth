use super::issuer_native_families::Fixture;
use auth_core::*;
use uuid::Uuid;

pub(crate) struct Consumer {
    pub policy: IssuerNativeConsumerPolicy,
    pub secret: Secret,
}
impl Consumer {
    pub async fn new(f: &Fixture) -> Self {
        Self::with_client(f, Uuid::new_v4()).await
    }
    pub async fn with_client(f: &Fixture, id: Uuid) -> Self {
        let secret = Secret::generate().unwrap();
        let reader = f
            .base
            .store
            .configure_issuer_client(
                &IssuerClientRegistration::confidential(
                    f.base.authority.realm(),
                    id,
                    &["https://resource.example/cb"],
                    &secret,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let policy = f
            .base
            .store
            .configure_issuer_native_consumer(
                &IssuerNativeConsumerPolicy::new(
                    f.base.authority.clone(),
                    reader,
                    f.policy.client().clone(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        Self { policy, secret }
    }
    pub fn authentication(&self) -> IssuerClientAuthentication {
        IssuerClientAuthentication::basic(self.policy.consumer().client(), &self.secret).unwrap()
    }
    pub fn service(&self, f: &Fixture) -> IssuerNativeIntrospection {
        IssuerNativeIntrospection::new(f.base.authority.clone(), f.base.store.clone())
    }
    pub async fn enable(&self, f: &Fixture) {
        f.base
            .store
            .enable_issuer_native_consumer(&self.policy)
            .await
            .unwrap();
    }
    pub async fn inspect(
        &self,
        f: &Fixture,
        token: &Secret,
    ) -> IssuerTokenResult<Option<IssuerNativeActiveAccess>> {
        self.service(f)
            .introspect_access(&self.authentication(), &token.into(), "127.0.0.1")
            .await
    }
}
