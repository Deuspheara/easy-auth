//! Observe real opaque proof timing around the unchanged PostgreSQL grant.
//! No proof constructor, XML access, policy fallback or authority setup exists.
use super::FixtureResult;
use async_trait::async_trait;
use auth_core::{Result, SamlIdentityRepository, SamlMappedIdentity, User, Verifier};
use auth_postgres::Postgres;
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

// Measurement of the documented default, not an authorization rule.
const FIXED_AUTHN_AGE_US: i64 = 24 * 60 * 60 * 1_000_000;
#[derive(Clone)]
struct Record {
    realm: Uuid,
    bearer: Verifier,
    authn: i64,
    admission: i64,
    session: i64,
}
pub(super) struct Observations {
    store: Arc<Postgres>,
    accepted: Mutex<Vec<Record>>,
}
impl Observations {
    pub fn new(store: Arc<Postgres>) -> Self {
        Self {
            store,
            accepted: Mutex::new(Vec::new()),
        }
    }
    pub async fn facts(&self, pool: &PgPool) -> FixtureResult<serde_json::Value> {
        let records = self
            .accepted
            .lock()
            .expect("owned observations mutex")
            .clone();
        let mut exact_authn = true;
        let mut bounded_session = true;
        let mut distinct_caps = true;
        let mut statement_caps = 0;
        let mut removed_sessions = 0;
        for record in &records {
            let stored:Option<(i64,i64)>=sqlx::query_as("SELECT (extract(epoch FROM authenticated_at)*1000000)::bigint,(extract(epoch FROM expires_at)*1000000)::bigint FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
                .bind(record.realm).bind(record.bearer.as_slice()).fetch_optional(pool).await?;
            let Some((authn, expiry)) = stored else {
                removed_sessions += 1;
                continue;
            };
            exact_authn &= authn == record.authn;
            bounded_session &= expiry <= record.session;
            distinct_caps &= expiry > record.admission;
            if record.session < record.authn + FIXED_AUTHN_AGE_US {
                statement_caps += 1;
            }
        }
        Ok(
            // Missing sessions after erasure cannot establish historical timing.
            // Keep those measurements explicitly unavailable, never vacuously true.
            serde_json::json!({"grants":records.len(),"removed_sessions":removed_sessions,
                "exact_signed_authn":(removed_sessions == 0).then_some(exact_authn),
                "verified_session_caps":(removed_sessions == 0).then_some(bounded_session),
                "session_exceeds_admission_cap":(removed_sessions == 0).then_some(distinct_caps),
                "signed_statement_caps_below_default":statement_caps}),
        )
    }
}
#[async_trait]
impl SamlIdentityRepository for Observations {
    async fn finish_saml_identity(
        &self,
        mapped: SamlMappedIdentity,
        bearer: Verifier,
    ) -> Result<User> {
        let proof = mapped.assertion();
        let record = Record {
            realm: proof.registration().realm(),
            bearer,
            authn: proof.authenticated_at_us(),
            admission: proof.expires_at_us(),
            session: proof.session_expires_at_us(),
        };
        // All authority and rollback remain in the original repository. Record
        // only scalar timing/hash facts after its successful real commit.
        let user = self.store.finish_saml_identity(mapped, bearer).await?;
        self.accepted
            .lock()
            .expect("owned observations mutex")
            .push(record);
        Ok(user)
    }
}
