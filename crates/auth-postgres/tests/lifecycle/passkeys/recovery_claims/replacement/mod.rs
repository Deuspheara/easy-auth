mod atomicity;
mod boundaries;
mod invalidation;
mod lifecycle;
mod migration;
mod rotation;
mod waiting;
mod waiting_rows;

use super::*;
use crate::passkeys::ORIGIN;
use auth_core::{
    PasskeyAuthenticationResponse, PasskeyRecoveryReplacement,
    PasskeyRecoveryReplacementRepository, PasskeyRecoveryReplacementRequest, PasskeyRecoveryTarget,
    PasskeyRegistrationResponse, VerifiedPasskeyAuthentication,
};
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

struct Replacement {
    c: Claims,
    flow: PasskeyRecoveryReplacement,
    target: PasskeyRecoveryTarget,
    token: SoftToken,
}
impl Replacement {
    async fn new(pool: PgPool, email_free: bool) -> Self {
        let c = Claims::new(pool, email_free).await;
        let info = c
            .flow
            .begin(c.owner, &c.code, &c.browser, SOURCE)
            .await
            .unwrap();
        let flow =
            PasskeyRecoveryReplacement::new(c.f.realm, c.f.service.clone(), c.f.store.clone());
        let (token, _) = SoftToken::new(true).unwrap();
        Self {
            target: PasskeyRecoveryTarget {
                user_id: c.owner,
                claim_id: info.id,
            },
            c,
            flow,
            token,
        }
    }
    async fn mature(&self) {
        let notified:bool=sqlx::query_scalar("SELECT notification_required FROM auth_passkey_recovery_claims WHERE realm_id=$1 AND id=$2")
            .bind(self.c.f.realm).bind(self.target.claim_id).fetch_one(&self.c.pool).await.unwrap();
        if notified {
            let notice = self.c.start_notice().await;
            self.c
                .f
                .store
                .complete_security_notice(self.c.f.realm, notice.id, notice.lease, true)
                .await
                .unwrap();
            let scheduled:bool=sqlx::query_scalar("SELECT notified_at IS NOT NULL AND not_before=notified_at+interval '24 hours' FROM auth_passkey_recovery_claims WHERE realm_id=$1 AND id=$2")
                .bind(self.c.f.realm).bind(self.target.claim_id).fetch_one(&self.c.pool).await.unwrap();
            assert!(
                scheduled,
                "actual current-lease receipt must schedule the full delay first"
            );
        }
        // Trusted clock fixture fast-forwards an actually scheduled delay only;
        // no receipt or session provenance is fabricated for completion.
        sqlx::query("WITH instant AS (SELECT clock_timestamp()-interval '2 days' AS started) UPDATE auth_passkey_recovery_claims SET created_at=started,notified_at=CASE WHEN notification_required THEN started ELSE NULL END,not_before=started+interval '1 day' FROM instant WHERE realm_id=$1 AND id=$2")
            .bind(self.c.f.realm).bind(self.target.claim_id).execute(&self.c.pool).await.unwrap();
    }
    async fn registration(&mut self) -> (Uuid, PasskeyRegistrationResponse) {
        let pending = self
            .flow
            .begin(self.target, &self.c.browser, SOURCE)
            .await
            .unwrap();
        let mut options = pending.options;
        let selection = options.public_key.authenticator_selection.as_mut().unwrap();
        assert!(selection.require_resident_key);
        // Pinned SoftToken rejects residence. This test-only client hint change
        // retains private state/UV/signatures; native residence remains a gate.
        selection.require_resident_key = false;
        selection.resident_key = None;
        let response = self
            .token
            .perform_register(ORIGIN.parse().unwrap(), options.public_key, 120_000)
            .unwrap();
        (pending.transaction, response)
    }
    async fn assertion(&mut self) -> (Uuid, PasskeyAuthenticationResponse) {
        let (id, response) = self.registration().await;
        let pending = self
            .flow
            .finish_registration(self.target, id, &self.c.browser, SOURCE, &response)
            .await
            .unwrap();
        let response = self
            .token
            .perform_auth(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
            .unwrap();
        (id, response)
    }
    fn request(&self, id: Uuid) -> PasskeyRecoveryReplacementRequest {
        PasskeyRecoveryReplacementRequest {
            claim: self.c.request(),
            claim_id: self.target.claim_id,
            transaction: id,
        }
    }
    async fn proof(
        &self,
        id: Uuid,
        response: &PasskeyAuthenticationResponse,
    ) -> VerifiedPasskeyAuthentication {
        let (state, key) = self
            .c
            .f
            .store
            .load_recovery_assertion(&self.request(id))
            .await
            .unwrap();
        self.c
            .f
            .service
            .verify_authentication(response, state, key)
            .unwrap()
    }
}
