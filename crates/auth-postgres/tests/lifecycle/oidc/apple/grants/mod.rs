mod atomicity;
mod lifecycle;
mod schema;
use super::setup::{Attempt, Fixture};
use auth_core::*;
use std::sync::Arc;
use uuid::Uuid;

async fn captured(f: &Fixture, a: &Attempt) -> Result<AppleMappedGrant> {
    let result = f
        .grant_flow
        .finish(
            &a.intent(),
            &a.start.transaction.state,
            a.proof(),
            f.policy.configuration().redirect(),
            a.response(None),
        )
        .await?;
    match result {
        AppleGrantAuthorizationCompletion::Verified(grant) => grant.map(&f.policy),
        _ => panic!("owned actual signature required"),
    }
}
async fn sign_in(f: &Fixture, subject: &str) -> (User, Secret) {
    let a = f.prepare(subject, serde_json::json!({})).await;
    AppleGrantSignIn::new(f.store.clone())
        .finish(captured(f, &a).await.unwrap())
        .await
        .unwrap()
}
async fn envelopes(f: &Fixture) -> Vec<AppleGrantEnvelope> {
    use sqlx::Row;
    let rows=sqlx::query("SELECT id,connection_id,client_id,binding_identity_id,key_id,ciphertext FROM auth_apple_grants WHERE realm_id=$1 ORDER BY id").bind(f.realm()).fetch_all(&f.pool).await.unwrap();
    rows.into_iter()
        .map(|row| {
            AppleGrantEnvelope::restore(
                AppleGrantBinding::new(
                    f.realm(),
                    row.get("connection_id"),
                    row.get("client_id"),
                    row.get("binding_identity_id"),
                    row.get("id"),
                )
                .unwrap(),
                row.get("key_id"),
                row.get("ciphertext"),
            )
            .unwrap()
        })
        .collect()
}
async fn local(f: &Fixture) -> (User, Secret) {
    let current = crate::support::signed_in(&f.store, f.realm(), "owner@owned.example").await;
    let user = f
        .store
        .authenticate(f.realm(), current.verifier())
        .await
        .unwrap();
    (user, current)
}

fn new_vault() -> Arc<AppleGrantVault> {
    Arc::new(
        AppleGrantVault::new(
            AppleGrantKey::new(Uuid::new_v4(), vec![31; 32]).unwrap(),
            vec![],
        )
        .unwrap(),
    )
}

async fn link(f: &Fixture, owner: &User, current: &Secret, subject: &str) -> LinkedProvider {
    let flow = AppleGrantAuthorization::linking(
        Arc::new(OAuthTransactions::new(
            f.policy.configuration().clone(),
            f.store.clone(),
        )),
        f.component.clone(),
    )
    .unwrap();
    let browser = Secret::generate().unwrap();
    let code = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "owned-grant-link",
        purpose: OAuthPurpose::Link {
            user: owner.id,
            session: current.verifier(),
        },
    };
    let start = flow.begin(&intent).await.unwrap();
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    f.provider.issue(&code,serde_json::json!({"iss":"https://appleid.apple.com","sub":subject,"aud":f.policy.configuration().provider_client(),
        "nonce":start.request.nonce(),"iat":now,"exp":now+120}),Some(f.policy.configuration().redirect()));
    let response = AppleAuthorizationResponse::parse(&format!(
        "state={}&code={}",
        start.transaction.state.expose(),
        code.expose()
    ))
    .unwrap();
    let result = flow
        .finish(
            &intent,
            &start.transaction.state,
            start.transaction.proof,
            f.policy.configuration().redirect(),
            response,
        )
        .await
        .unwrap();
    let AppleGrantAuthorizationCompletion::Verified(grant) = result else {
        panic!("actual link signature required")
    };
    AppleGrantLinking::new(f.store.clone())
        .finish(grant.map(&f.policy).unwrap(), current)
        .await
        .unwrap()
}
mod deadlines;
mod revocation;
mod rotation;
