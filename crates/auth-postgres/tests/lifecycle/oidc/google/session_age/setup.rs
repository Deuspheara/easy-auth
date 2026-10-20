use super::super::{
    provider::{CLIENT, ISSUER},
    setup::Fixture,
};
use auth_core::*;
use serde_json::{Value, json};

const TOKEN_LIFETIME_SECONDS: i64 = 120;

pub(in crate::oidc::google) fn selected(f: &Fixture) -> GoogleSessionAgeCodeExchange {
    GoogleCodeExchange::new(
        f.policy.configuration().clone(),
        f.store.clone(),
        f.store.clone(),
        f.provider.authentication(),
        f.provider.clone(),
        f.provider.clone(),
    )
    .unwrap()
    .with_session_age_claims()
}
pub(super) async fn now(f: &Fixture) -> i64 {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        .fetch_one(&f.pool)
        .await
        .expect("test infrastructure: actual Google session-age clock")
}
pub(super) async fn account(f: &Fixture, subject: &str) -> (User, Secret) {
    f.sign_in(f.mapped(subject, json!({})).await).await.unwrap()
}
pub(super) async fn proof(
    f: &Fixture,
    user: &User,
    current: &Secret,
    subject: &str,
    attributes: Value,
) -> Result<VerifiedOidcIdentity> {
    let browser = Secret::generate()?;
    let code = Secret::generate()?;
    let intent = OAuthIntent {
        browser: &browser,
        source: "owned-google-session-age",
        purpose: OAuthPurpose::DeleteProviderAccount {
            user: user.id,
            session: current.verifier(),
        },
    };
    let flow = f.flow();
    let start = flow.begin(&intent).await?;
    let profile = selected(f);
    let url = profile.authorization_url(&start).await?;
    let url = url::Url::parse(url.expose()).unwrap();
    let pairs: Vec<_> = url.query_pairs().collect();
    assert!(
        !pairs
            .iter()
            .any(|(name, _)| matches!(name.as_ref(), "prompt" | "max_age")),
        "Google request cannot claim to force reauthentication"
    );
    let claims: Vec<_> = pairs.iter().filter(|(name, _)| name == "claims").collect();
    assert_eq!(claims.len(), 1);
    assert_eq!(
        serde_json::from_str::<Value>(&claims[0].1).unwrap(),
        json!({"id_token":{"auth_time":{"essential":true}}})
    );
    let now = now(f).await;
    let mut claims = json!({"iss":ISSUER,"aud":CLIENT,"sub":subject,"nonce":start.proof.nonce().expose(),"iat":now,"exp":now+TOKEN_LIFETIME_SECONDS});
    for (name, value) in attributes.as_object().unwrap() {
        claims[name] = value.clone();
    }
    f.provider
        .issue(&code, &start, f.policy.configuration(), claims);
    let cap = start.expires_us;
    let context = flow
        .consume(
            &intent,
            &start.state,
            start.proof,
            OAuthCallback {
                redirect: f.policy.configuration().redirect(),
                issuer: Some(ISSUER),
            },
        )
        .await?;
    let identity = profile
        .exchange_account_deletion(
            context,
            OidcAuthorizationCode::parse(code.expose().to_owned())?,
        )
        .await?;
    assert!(
        identity.expires_us() <= cap,
        "session-age selection preserves original proof cap"
    );
    Ok(identity)
}
pub(super) async fn remove(f: &Fixture, identity: VerifiedOidcIdentity) -> Result<()> {
    OidcAccountDeletion::new(f.store.clone())
        .finish(f.policy.map(identity)?)
        .await
}
/// Compare privately without formatting rows or verifiers. Admission is not account state.
pub(in crate::oidc::google) async fn snapshot(f: &Fixture) -> Value {
    sqlx::query_scalar(r#"SELECT jsonb_build_object(
      'users',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,id) FROM auth_users t),
      'identities',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,id) FROM auth_oidc_identities t),
      'sessions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,id) FROM auth_sessions t),
      'audit',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM auth_audit t),
      'notices',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,id) FROM auth_security_notifications t),
      'pending',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,state_hash) FROM auth_oauth_transactions t),
      'cooldown',(SELECT jsonb_agg(to_jsonb(t) ORDER BY realm_id,subject_hash) FROM auth_oidc_deleted_subjects t))"#)
      .fetch_one(&f.pool).await.expect("test infrastructure: private Google deletion state snapshot")
}
