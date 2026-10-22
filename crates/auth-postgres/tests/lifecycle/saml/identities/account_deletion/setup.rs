use super::super::super::signed_idp;
pub(super) use super::super::deletion_setup::Fixture;
use auth_core::{SamlDeletionVerifier, SamlVerifiedDeletion};
use std::time::Duration;

/// Ordinary library-produced signatures; no fabricated proof, XML editing or
/// cryptographic work under a database lock/concurrent commit test.
pub(super) async fn proof(f: &Fixture, subject: &str) -> SamlVerifiedDeletion {
    with_pending_cap(f, subject, None).await
}

pub(super) async fn expiring_proof(f: &Fixture) -> SamlVerifiedDeletion {
    with_pending_cap(f, "normal", Some(4)).await
}

async fn with_pending_cap(
    f: &Fixture,
    subject: &str,
    seconds: Option<i64>,
) -> SamlVerifiedDeletion {
    let start = f.requests.start(&f.current).await.unwrap();
    let input = signed_idp::response(&f.source, &start, subject, Duration::from_secs(180));
    if let Some(seconds) = seconds {
        // Shorten only owned DB admission; preserve the library-produced XML.
        sqlx::query("UPDATE auth_saml_requests SET expires_at=clock_timestamp()+$2*interval '1 second' WHERE request_id=$1")
            .bind(start.request_id()).bind(seconds).execute(&f.source.pool).await.unwrap();
    }
    let prepared = f
        .requests
        .prepare_response(
            &f.current,
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    SamlDeletionVerifier::new(f.policy.clone(), f.source.store.clone())
        .unwrap()
        .verify(prepared, input)
        .await
        .unwrap()
}

pub(super) async fn counts(f: &Fixture) -> (i64, i64, i64, i64, i64, i64) {
    sqlx::query_as("SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),(SELECT count(*) FROM auth_saml_identities WHERE realm_id=$1),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1),(SELECT count(*) FROM auth_saml_replays WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1),(SELECT count(*) FROM auth_saml_requests WHERE realm_id=$1)")
        .bind(f.user.realm_id).fetch_one(&f.source.pool).await.unwrap()
}
