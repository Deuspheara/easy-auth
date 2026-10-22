//! Observe real opaque proof timing around the unchanged PostgreSQL grant.
//! No proof constructor, XML access, policy fallback or authority setup exists.
use super::FixtureResult;
use async_trait::async_trait;
use auth_core::{
    Result, SamlAccountDeletionRepository, SamlIdentityRepository, SamlMappedIdentity,
    SamlVerifiedDeletion, User, Verifier,
};
use auth_postgres::Postgres;
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

// Measurement of the documented default, not an authorization rule.
const FIXED_AUTHN_AGE_US: i64 = 24 * 60 * 60 * 1_000_000;
#[derive(Clone)]
struct Record {
    realm: Uuid,
    user: Uuid,
    bearer: Verifier,
    authn: i64,
    admission: i64,
    session: i64,
}
pub(super) struct Observations {
    store: Arc<Postgres>,
    accepted: Mutex<Vec<Record>>,
    deletion_authn_advanced: Mutex<Vec<Option<bool>>>,
}
impl Observations {
    pub fn new(store: Arc<Postgres>) -> Self {
        Self {
            store,
            accepted: Mutex::new(Vec::new()),
            deletion_authn_advanced: Mutex::new(Vec::new()),
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
        let deletion = self
            .deletion_authn_advanced
            .lock()
            .expect("owned deletion timing mutex")
            .clone();
        Ok(
            // Missing sessions after erasure cannot establish historical timing.
            // Keep those measurements explicitly unavailable, never vacuously true.
            serde_json::json!({"grants":records.len(),"removed_sessions":removed_sessions,
                "exact_signed_authn":(removed_sessions == 0).then_some(exact_authn),
                "verified_session_caps":(removed_sessions == 0).then_some(bounded_session),
                "session_exceeds_admission_cap":(removed_sessions == 0).then_some(distinct_caps),
                "signed_statement_caps_below_default":statement_caps,
                "deletions":deletion.len(),"deletion_authn_advanced":deletion.last().copied().flatten()}),
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
        let realm = proof.registration().realm();
        let authn = proof.authenticated_at_us();
        let admission = proof.expires_at_us();
        let session = proof.session_expires_at_us();
        // All authority and rollback remain in the original repository. Record
        // only scalar timing/hash facts after its successful real commit.
        let user = self.store.finish_saml_identity(mapped, bearer).await?;
        let record = Record {
            realm,
            user: user.id,
            bearer,
            authn,
            admission,
            session,
        };
        self.accepted
            .lock()
            .expect("owned observations mutex")
            .push(record);
        Ok(user)
    }
}

#[async_trait]
impl SamlAccountDeletionRepository for Observations {
    async fn finish_saml_account_deletion(&self, proof: SamlVerifiedDeletion) -> Result<()> {
        let advanced = {
            let records = self.accepted.lock().expect("owned observations mutex");
            let mut initiating = records.iter().filter(|record| {
                record.realm == proof.policy().registration().realm()
                    && record.user == proof.binding().user
            });
            // This owned acceptance has exactly one initiating grant. Multiple
            // records cannot identify its original session and remain unknown.
            let first = initiating.next();
            if initiating.next().is_some() {
                None
            } else {
                first.map(|record| proof.assertion().authenticated_at_us() > record.authn)
            }
        };
        self.store.finish_saml_account_deletion(proof).await?;
        self.deletion_authn_advanced
            .lock()
            .expect("owned deletion timing mutex")
            .push(advanced);
        Ok(())
    }
}
