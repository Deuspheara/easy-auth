use super::*;
use auth_core::{Error, PasskeyEnrollmentStart, Repository};
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn preparation_insert_wait_cannot_outlive_the_original_authentication_deadline(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let context = f
        .store
        .enrollment_context(f.realm, f.session.verifier(), f.service.rp_id())
        .await
        .unwrap();
    let (_, state) = f
        .service
        .begin_registration(context.user_id, &context.account_name, &[])
        .unwrap();
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '4 minutes 55 seconds' WHERE realm_id=$1")
        .bind(f.realm).execute(&pool).await.unwrap();
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(200021)")
        .execute(&mut *gate)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION enrollment_start_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(200021); RETURN NEW; END $$; CREATE TRIGGER enrollment_start_gate BEFORE INSERT ON auth_passkey_enrollments FOR EACH ROW EXECUTE FUNCTION enrollment_start_gate();")
        .execute(&pool).await.unwrap();
    let pending = PasskeyEnrollmentStart {
        request: f.request(Uuid::new_v4()),
        user_id: context.user_id,
        rp_id: f.service.rp_id().into(),
        label: "Late start".into(),
        state,
    };
    let store = f.store.clone();
    let save = tokio::spawn(async move { store.save_enrollment(pending).await });
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .expect("test infrastructure: observer connection");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=200021 AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()))")
                .fetch_one(&observer).await.unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("test infrastructure: action must reach the insert gate");
    let expired = "SELECT authenticated_at<=clock_timestamp()-interval '5 minutes' FROM auth_sessions WHERE realm_id=$1";
    assert!(
        !sqlx::query_scalar::<_, bool>(expired)
            .bind(f.realm)
            .fetch_one(&observer)
            .await
            .unwrap(),
        "test infrastructure: wait must precede expiry"
    );
    tokio::time::timeout(Duration::from_secs(8), async {
        while !sqlx::query_scalar::<_, bool>(expired)
            .bind(f.realm)
            .fetch_one(&observer)
            .await
            .unwrap()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("test infrastructure: database deadline crossing");
    gate.commit().await.unwrap();
    assert!(
        matches!(
            tokio::time::timeout(Duration::from_secs(5), save)
                .await
                .expect("test infrastructure: save completion")
                .unwrap(),
            Err(Error::Unauthorized)
        ),
        "expired preparation must not persist pending registration"
    );
    assert_eq!(counts(&pool, f.realm).await, (0, 0, 0));
    observer.close().await;
}

#[sqlx::test(migrations = "./migrations")]
async fn a_key_committed_while_context_waits_for_owner_changes_required_authority(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let (_, _, proof) = prepare(&f).await;
    let user = f
        .store
        .authenticate(f.realm, f.session.verifier())
        .await
        .unwrap()
        .id;
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(f.realm)
        .bind(user)
        .execute(&mut *gate)
        .await
        .unwrap();
    // Valid registration storage fixture; its presence, not an invented session,
    // changes the required authority after the observed unchanged-owner lock wait.
    sqlx::query("INSERT INTO auth_passkeys(realm_id,id,user_id,rp_id,credential_id,credential,label) VALUES ($1,$2,$3,$4,$5,$6,'Committed while waiting')")
        .bind(f.realm).bind(Uuid::new_v4()).bind(user).bind(proof.rp_id()).bind(proof.credential_id()).bind(proof.encode_for_database().unwrap())
        .execute(&mut *gate).await.unwrap();
    let store = f.store.clone();
    let realm = f.realm;
    let session = f.session.verifier();
    let rp = f.service.rp_id().to_owned();
    let context = tokio::spawn(async move { store.enrollment_context(realm, session, &rp).await });
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .expect("test infrastructure: observer connection");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%SELECT u.id,coalesce(u.email,u.display_name) FROM auth_users u%FOR UPDATE OF u%')")
                .fetch_one(&observer).await.unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("test infrastructure: context must wait for owner");
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), context)
            .await
            .expect("test infrastructure: context completion")
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    assert_eq!(counts(&pool, f.realm).await, (1, 0, 1));
    observer.close().await;
}

#[sqlx::test(migrations = "./migrations")]
async fn final_consumption_trigger_wait_cannot_outlive_the_locked_proof_deadline(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let (request, encoded, proof) = prepare(&f).await;
    sqlx::query("UPDATE auth_passkey_enrollments SET expires_at=clock_timestamp()+interval '5 seconds' WHERE realm_id=$1")
        .bind(f.realm).execute(&pool).await.unwrap();
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(200022)")
        .execute(&mut *gate)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION enrollment_consume_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(200022); RETURN OLD; END $$; CREATE TRIGGER enrollment_consume_gate BEFORE DELETE ON auth_passkey_enrollments FOR EACH ROW EXECUTE FUNCTION enrollment_consume_gate();")
        .execute(&pool).await.unwrap();
    let store = f.store.clone();
    let finish =
        tokio::spawn(async move { store.commit_enrollment(&request, &encoded, proof).await });
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .expect("test infrastructure: observer connection");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=200022 AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()))")
                .fetch_one(&observer).await.unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("test infrastructure: completion must reach consume trigger");
    let query =
        "SELECT expires_at<=clock_timestamp() FROM auth_passkey_enrollments WHERE realm_id=$1";
    assert!(
        !sqlx::query_scalar::<_, bool>(query)
            .bind(f.realm)
            .fetch_one(&observer)
            .await
            .unwrap(),
        "test infrastructure: consume wait precedes proof expiry"
    );
    tokio::time::timeout(Duration::from_secs(8), async {
        while !sqlx::query_scalar::<_, bool>(query)
            .bind(f.realm)
            .fetch_one(&observer)
            .await
            .unwrap()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("test infrastructure: proof deadline crossing");
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), finish)
            .await
            .expect("test infrastructure: completion timeout")
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    assert_eq!(counts(&pool, f.realm).await, (0, 0, 1));
    observer.close().await;
}
