use super::setup::{Fixture, counts};
use crate::support::observation;
use auth_core::{Error, Repository};
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn targeted_and_all_revocation_cannot_commit_after_a_pending_cleanup_wait_exceeds_original_session_cap(
    pool: PgPool,
) {
    for all in [false, true] {
        let f = Fixture::new(pool.clone()).await;
        sqlx::query("UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '4 seconds' WHERE realm_id=$1 AND token_hash=$2")
            .bind(f.user.realm_id).bind(f.current.verifier().as_slice()).execute(&f.source.pool).await.unwrap();
        let pending = f.requests.start(&f.current).await.unwrap();
        let (session,cap): (uuid::Uuid,i64) = sqlx::query_as("SELECT session_id,(extract(epoch FROM expires_at)*1000000)::bigint FROM auth_saml_requests WHERE request_id=$1").bind(pending.request_id()).fetch_one(&f.source.pool).await.unwrap();
        sqlx::raw_sql("CREATE FUNCTION hold_saml_invalidation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(5704); RETURN OLD; END $$; CREATE TRIGGER hold_saml_invalidation BEFORE DELETE ON auth_saml_requests FOR EACH ROW WHEN (OLD.purpose='delete_account') EXECUTE FUNCTION hold_saml_invalidation();")
            .execute(&f.source.pool).await.unwrap();
        let observer = observation::observer(&f.source.pool).await;
        let mut gate = f.source.pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(5704)")
            .execute(&mut *gate)
            .await
            .unwrap();
        let store = f.source.store.clone();
        let realm = f.user.realm_id;
        let current = f.current.verifier();
        let action = tokio::spawn(async move {
            if all {
                store.revoke_all_sessions(realm, current).await
            } else {
                store
                    .revoke_session(realm, current, session)
                    .await
                    .map(|_| ())
            }
        });
        observation::locked(
            &observer,
            "%DELETE FROM auth_saml_requests%purpose='delete_account'%",
        )
        .await;
        let live: bool = sqlx::query_scalar(
            "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint < $1",
        )
        .bind(cap)
        .fetch_one(&observer)
        .await
        .unwrap();
        assert!(
            live,
            "test infrastructure: cleanup wait must precede the retained cap"
        );
        observation::expired(&observer, cap).await;
        gate.commit().await.unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(5), action)
                .await
                .unwrap()
                .unwrap(),
            Err(Error::Unauthorized)
        ));
        assert_eq!(counts(&f).await, (1, 1, 1, 2, 1, 1));
        let revoked: bool = sqlx::query_scalar(
            "SELECT revoked_at IS NOT NULL FROM auth_sessions WHERE realm_id=$1 AND id=$2",
        )
        .bind(realm)
        .bind(session)
        .fetch_one(&f.source.pool)
        .await
        .unwrap();
        assert!(
            !revoked,
            "deadline failure rolls back revocation, audit and pending cleanup"
        );
        sqlx::raw_sql("DROP TRIGGER hold_saml_invalidation ON auth_saml_requests; DROP FUNCTION hold_saml_invalidation();").execute(&f.source.pool).await.unwrap();
    }
}
