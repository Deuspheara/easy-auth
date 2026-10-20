mod admission;
mod cancellation;
mod concurrency;
mod lifecycle;
mod migration;
mod provider_policy;
mod receipts;
mod replacement;
mod waiting;

use super::{Fixture, SOURCE};
use auth_core::{
    Error, PasskeyEnrollment, PasskeyRecoveryClaimRepository, PasskeyRecoveryClaimRequest,
    PasskeyRecoveryClaims, PasskeyRecoverySetup, Repository, Secret, SecurityNotice,
    SecurityNoticeKind,
};
use sqlx::PgPool;
use uuid::Uuid;

struct Claims {
    f: Fixture,
    pool: PgPool,
    flow: PasskeyRecoveryClaims,
    setup: PasskeyRecoverySetup,
    owner: Uuid,
    code: Secret,
    browser: Secret,
    weak: Secret,
    token: webauthn_authenticator_rs::softtoken::SoftToken,
}

impl Claims {
    async fn new(pool: PgPool, email_free: bool) -> Self {
        Self::in_realm(pool, email_free, None).await
    }

    async fn in_realm(pool: PgPool, email_free: bool, realm: Option<Uuid>) -> Self {
        let mut f = Fixture::new(pool.clone()).await;
        if let Some(realm) = realm {
            f.realm = realm;
            f.session = crate::support::signed_in(&f.store, realm, "peer@example.test").await;
            f.enrollment = PasskeyEnrollment::new(realm, f.service.clone(), f.store.clone());
        }
        let owner = f
            .store
            .authenticate(f.realm, f.session.verifier())
            .await
            .unwrap()
            .id;
        let (id, response, mut token) = f.begin_with_token().await;
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, id, &response)
            .await
            .unwrap();
        let proven = f.sign_in_with_key(&mut token).await;
        let weak = std::mem::replace(&mut f.session, proven);
        if email_free {
            // Account-model fixture only. Session provenance is an actual assertion.
            sqlx::query("UPDATE auth_users SET email=NULL,email_verified_at=NULL,display_name='Recovery owner',authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2")
                .bind(f.realm).bind(owner).execute(&pool).await.unwrap();
        }
        let setup = PasskeyRecoverySetup::new(f.realm, f.service.clone(), f.store.clone());
        let prepared = setup.prepare(&f.session, SOURCE).await.unwrap();
        setup
            .confirm(&f.session, SOURCE, prepared.id, &prepared.code)
            .await
            .unwrap();
        // Clear only the fixture's earlier configuration notice via the real lease
        // API. Receipt tests below independently control claim-start acknowledgements.
        if let Some(notice) = f.store.claim_security_notice(f.realm).await.unwrap() {
            assert!(matches!(
                notice.kind,
                SecurityNoticeKind::PasskeyRecoveryChanged
            ));
            f.store
                .complete_security_notice(f.realm, notice.id, notice.lease, true)
                .await
                .unwrap();
        }
        let flow = PasskeyRecoveryClaims::new(f.realm, f.service.clone(), f.store.clone());
        Self {
            f,
            pool,
            flow,
            setup,
            owner,
            code: prepared.code,
            browser: Secret::generate().unwrap(),
            weak,
            token,
        }
    }

    fn request(&self) -> PasskeyRecoveryClaimRequest {
        PasskeyRecoveryClaimRequest {
            realm: self.f.realm,
            user_id: self.owner,
            rp_id: self.f.service.rp_id().into(),
            browser: self.browser.verifier(),
            source: [29; 32],
        }
    }

    async fn snapshot(&self) -> Vec<String> {
        let mut rows = Vec::new();
        for table in [
            "auth_users",
            "auth_sessions",
            "auth_passkeys",
            "auth_passkey_recovery_codes",
            "auth_passkey_recovery_setups",
            "auth_passkey_recovery_claims",
            "auth_passkey_recovery_replacements",
            "auth_security_notifications",
            "auth_audit",
        ] {
            rows.push(sqlx::query_scalar(&format!("SELECT coalesce(string_agg(row_to_json(t)::text,E'\\n' ORDER BY row_to_json(t)::text),'') FROM {table} t WHERE realm_id=$1"))
                .bind(self.f.realm).fetch_one(&self.pool).await.unwrap());
        }
        rows
    }

    async fn unchanged(&self, before: Vec<String>) {
        assert!(
            self.snapshot().await == before,
            "durable state must be unchanged; admission is separately durable"
        );
    }

    async fn unnotified(&self) {
        let pending: bool = sqlx::query_scalar("SELECT notified_at IS NULL AND not_before IS NULL FROM auth_passkey_recovery_claims WHERE realm_id=$1 AND user_id=$2")
            .bind(self.f.realm).bind(self.owner).fetch_one(&self.pool).await.unwrap();
        assert!(
            pending,
            "a queued, failed or stale acknowledgement cannot start the delay"
        );
    }

    async fn start_notice(&self) -> SecurityNotice {
        let notice = self
            .f
            .store
            .claim_security_notice(self.f.realm)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            notice.kind,
            SecurityNoticeKind::PasskeyRecoveryStarted
        ));
        notice
    }

    async fn due_notices(&self) {
        sqlx::query("UPDATE auth_security_notifications SET next_attempt_at=clock_timestamp()-interval '1 second',lease_until=clock_timestamp()-interval '1 second' WHERE realm_id=$1")
            .bind(self.f.realm).execute(&self.pool).await.unwrap();
    }
}
