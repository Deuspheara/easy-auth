use super::super::signed_idp;
use super::setup::{allow_jit, facts, fixture};
use crate::support::observation;
use auth_core::{Error, Repository, SamlResponseVerifier, SamlSignIn};
use sqlx::PgPool;
use std::time::Duration;

async fn audit_gate(pool: &PgPool) -> sqlx::Transaction<'_, sqlx::Postgres> {
    sqlx::raw_sql("CREATE FUNCTION hold_saml_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(3401); RETURN NEW; END $$; CREATE TRIGGER hold_saml_audit BEFORE INSERT ON auth_audit FOR EACH ROW WHEN (NEW.kind='saml_authenticated') EXECUTE FUNCTION hold_saml_audit();")
        .execute(pool).await.unwrap();
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(3401)")
        .execute(&mut *gate)
        .await
        .unwrap();
    gate
}

#[sqlx::test(migrations = "./migrations")]
async fn original_cap_expiring_during_final_audit_wait_rolls_back_every_authority_write(
    pool: PgPool,
) {
    let (mut f, policy) = fixture(pool).await;
    let policy = allow_jit(&mut f, &policy).await;
    let observer = observation::observer(&f.pool).await;
    let start = f.flow.start().await.unwrap();
    let input = signed_idp::response(&f, &start, "normal", Duration::from_secs(180));
    // Shorten only the owned pending-row deadline after normal IdP issuance.
    // Signature verification still completes before any concurrent DB operation.
    sqlx::query("UPDATE auth_saml_requests SET expires_at=clock_timestamp()+interval '4 seconds' WHERE realm_id=$1")
        .bind(f.registration.realm()).execute(&f.pool).await.unwrap();
    let prepared = f
        .flow
        .prepare_response(
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    let proof = SamlResponseVerifier::new(f.registration.clone(), f.store.clone())
        .unwrap()
        .verify(prepared, input)
        .await
        .unwrap();
    let cap = proof.expires_at_us();
    let mapped = policy.map(proof).unwrap();
    let gate = audit_gate(&f.pool).await;
    let service = SamlSignIn::new(f.store.clone());
    let completion = tokio::spawn(async move { service.finish(mapped).await });
    observation::audit(&observer).await;
    let before: bool =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint < $1")
            .bind(cap)
            .fetch_one(&observer)
            .await
            .unwrap();
    assert!(
        before,
        "the observed audit wait must precede the original cap"
    );
    observation::expired(&observer, cap).await;
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), completion)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    assert_eq!(facts(&f).await, (0, 0, 0, 0, 0));
    sqlx::raw_sql("DROP TRIGGER hold_saml_audit ON auth_audit; DROP FUNCTION hold_saml_audit();")
        .execute(&f.pool)
        .await
        .unwrap();
    let service = SamlSignIn::new(f.store.clone());
    service
        .finish(
            policy
                .map(super::setup::verify(&f, "normal").await)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(facts(&f).await, (1, 1, 1, 2, 1));
}

#[sqlx::test(migrations = "./migrations")]
async fn disable_committed_before_source_lock_rejects_a_preverified_callback(pool: PgPool) {
    let (mut f, policy) = fixture(pool).await;
    let policy = allow_jit(&mut f, &policy).await;
    let mapped = policy
        .map(super::setup::verify(&f, "normal").await)
        .unwrap();
    let observer = observation::observer(&f.pool).await;
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("UPDATE auth_saml_registrations SET enabled=false, revision=$2 WHERE realm_id=$1")
        .bind(f.registration.realm())
        .bind(uuid::Uuid::new_v4())
        .execute(&mut *gate)
        .await
        .unwrap();
    let service = SamlSignIn::new(f.store.clone());
    let completion = tokio::spawn(async move { service.finish(mapped).await });
    observation::locked(&observer, "%SELECT enabled FROM auth_saml_registrations%").await;
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), completion)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    assert_eq!(facts(&f).await, (0, 0, 0, 0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn callback_holding_source_lock_commits_before_disable_then_its_session_is_invalid(
    pool: PgPool,
) {
    let (mut f, policy) = fixture(pool).await;
    let policy = allow_jit(&mut f, &policy).await;
    let mapped = policy
        .map(super::setup::verify(&f, "normal").await)
        .unwrap();
    let observer = observation::observer(&f.pool).await;
    let gate = audit_gate(&f.pool).await;
    let service = SamlSignIn::new(f.store.clone());
    let completion = tokio::spawn(async move { service.finish(mapped).await });
    observation::audit(&observer).await;
    let store = f.store.clone();
    let reg = f.registration.clone();
    let disable = tokio::spawn(async move {
        store
            .disable_saml_registration(reg.realm(), reg.connection(), reg.client())
            .await
    });
    observation::locked(&observer, "%UPDATE auth_saml_registrations%").await;
    gate.commit().await.unwrap();
    let (user, bearer) = tokio::time::timeout(Duration::from_secs(5), completion)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), disable)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        f.store.authenticate(user.realm_id, bearer.verifier()).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(facts(&f).await, (1, 1, 1, 2, 1));
}

#[sqlx::test(migrations = "./migrations")]
async fn changed_owner_policy_is_rechecked_after_wait_for_callback_and_session_use(pool: PgPool) {
    let (mut f, policy) = fixture(pool).await;
    let policy = allow_jit(&mut f, &policy).await;
    let service = SamlSignIn::new(f.store.clone());
    let (user, bearer) = service
        .finish(
            policy
                .map(super::setup::verify(&f, "normal").await)
                .unwrap(),
        )
        .await
        .unwrap();
    let observer = observation::observer(&f.pool).await;
    for callback in [true, false] {
        sqlx::query("UPDATE auth_users SET authentication_policy='provider_required' WHERE realm_id=$1 AND id=$2")
            .bind(user.realm_id).bind(user.id).execute(&f.pool).await.unwrap();
        let mapped = policy
            .map(super::setup::verify(&f, "normal").await)
            .unwrap();
        let mut gate = f.pool.begin().await.unwrap();
        sqlx::query("UPDATE auth_users SET authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2")
            .bind(user.realm_id).bind(user.id).execute(&mut *gate).await.unwrap();
        if callback {
            let service = SamlSignIn::new(f.store.clone());
            let completion = tokio::spawn(async move { service.finish(mapped).await });
            observation::locked(
                &observer,
                "%SELECT id,email,display_name,authentication_policy FROM auth_users%FOR UPDATE%",
            )
            .await;
            gate.commit().await.unwrap();
            assert!(matches!(
                tokio::time::timeout(Duration::from_secs(5), completion)
                    .await
                    .unwrap()
                    .unwrap(),
                Err(Error::Unauthorized)
            ));
        } else {
            let store = f.store.clone();
            let realm = user.realm_id;
            let verifier = bearer.verifier();
            let authentication =
                tokio::spawn(async move { store.authenticate(realm, verifier).await });
            observation::locked(&observer, "%SELECT u.id FROM auth_users%FOR SHARE OF u%").await;
            gate.commit().await.unwrap();
            assert!(matches!(
                tokio::time::timeout(Duration::from_secs(5), authentication)
                    .await
                    .unwrap()
                    .unwrap(),
                Err(Error::Unauthorized)
            ));
        }
        assert_eq!(facts(&f).await, (1, 1, 1, 2, 1));
    }
}
