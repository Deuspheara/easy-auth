use super::super::super::setup::Fixture as Source;
use super::super::setup::{allow_jit, fixture, verify};
use auth_core::{SamlDeletionRequests, SamlIdentityPolicy, SamlSignIn, Secret, User};
use sqlx::PgPool;

pub(super) struct Fixture {
    pub source: Source,
    pub policy: SamlIdentityPolicy,
    pub user: User,
    pub current: Secret,
    pub requests: SamlDeletionRequests,
}
impl Fixture {
    pub async fn new(pool: PgPool) -> Self {
        let (mut source, policy) = fixture(pool).await;
        let policy = allow_jit(&mut source, &policy).await;
        let (user, current) = SamlSignIn::new(source.store.clone())
            .finish(policy.map(verify(&source, "normal").await).unwrap())
            .await
            .unwrap();
        let requests = SamlDeletionRequests::new(source.registration.clone(), source.store.clone());
        Self {
            source,
            policy,
            user,
            current,
            requests,
        }
    }
    pub async fn another_session(&self, subject: &str) -> Secret {
        SamlSignIn::new(self.source.store.clone())
            .finish(
                self.policy
                    .map(verify(&self.source, subject).await)
                    .unwrap(),
            )
            .await
            .unwrap()
            .1
    }
    pub async fn pending(&self) -> i64 {
        self.source.pending().await
    }
}
