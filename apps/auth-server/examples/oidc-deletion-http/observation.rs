use async_trait::async_trait;
use auth_core::*;
use auth_postgres::Postgres;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use uuid::Uuid;

/// Finite evidence at the verified core port. Forward the original opaque value
/// unchanged to real PostgreSQL and preserve its result; never manufacture proof.
pub(super) struct Observation {
    pub store: Arc<Postgres>,
    pub pool: PgPool,
    pub policy: OidcIdentityPolicy,
    pub subject: String,
    pub calls: AtomicUsize,
    pub last: Mutex<Option<Value>>,
    owner: Mutex<Option<(Uuid, Verifier)>>,
}
impl Observation {
    pub fn new(
        store: Arc<Postgres>,
        pool: PgPool,
        policy: OidcIdentityPolicy,
        subject: String,
    ) -> Self {
        Self {
            store,
            pool,
            policy,
            subject,
            calls: AtomicUsize::new(0),
            last: Mutex::new(None),
            owner: Mutex::new(None),
        }
    }
    pub fn bind(&self, user: Uuid, session: &Secret) {
        *self.owner.lock().unwrap() = Some((user, session.verifier()));
    }
}
#[async_trait]
impl OidcAccountDeletionRepository for Observation {
    async fn finish_oidc_account_deletion(&self, mapped: OidcMappedIdentity) -> Result<()> {
        let now_us: i64 =
            sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
                .fetch_one(&self.pool)
                .await
                .map_err(|_| Error::Unavailable)?;
        let now = now_us / 1_000_000;
        let identity = mapped.identity();
        let bound = match identity.purpose() {
            OAuthPurpose::DeleteProviderAccount { user, session } => {
                Some((*user, *session)) == *self.owner.lock().unwrap()
            }
            _ => false,
        };
        let mut facts = json!({"subject_matches":identity.subject()==self.subject,
            "configuration_matches":identity.configuration()==self.policy.configuration(),
            "purpose_bound":bound,"signed_time_present":identity.authenticated_at().is_some(),
            "signed_time_recent":identity.authenticated_at().is_some_and(|time| i128::from(time)<=i128::from(now) && i128::from(now)-i128::from(time)<=i128::from(MAX_OIDC_DELETION_AUTH_AGE_SECONDS)),
            "original_cap_live":identity.expires_us()>now_us});
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = self.store.finish_oidc_account_deletion(mapped).await;
        facts["result"] = json!(match &result {
            Ok(()) => "committed",
            Err(Error::Unauthorized) => "unauthorized",
            Err(Error::Unavailable) => "unavailable",
            Err(Error::RateLimited) => "rate_limited",
            Err(Error::InvalidInput) => "invalid_input",
        });
        *self.last.lock().unwrap() = Some(facts);
        result
    }
}

pub(super) async fn facts(pool: &PgPool) -> Result<Value> {
    // The owned database contains this fixture alone. Exact whole-database counts
    // additionally detect accidental authority outside the configured realm.
    let f:(i64,i64,i64,i64,i64,i64,i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_oidc_identities),(SELECT count(*) FROM auth_audit),(SELECT count(*) FROM auth_oauth_transactions),(SELECT count(*) FROM auth_oidc_deleted_subjects),(SELECT count(*) FROM auth_security_notifications),(SELECT count(*) FROM auth_users WHERE email IS NOT NULL),(SELECT count(*) FROM auth_oidc_deleted_subjects WHERE blocked_until>clock_timestamp()),(SELECT count(*) FROM auth_audit WHERE user_id IS NOT NULL OR actor_session_id IS NOT NULL OR session_id IS NOT NULL OR NOT subject_erased)")
        .fetch_one(pool).await.map_err(|_|Error::Unavailable)?;
    Ok(
        json!({"users":f.0,"sessions":f.1,"identities":f.2,"audit":f.3,"pending":f.4,"cooldown":f.5,"notices":f.6,"contacts":f.7,"live_cooldown":f.8,"retained_subjects":f.9}),
    )
}
