use super::*;
use crate::support::lock_observation::{locked, observer};
use auth_core::Error;

#[sqlx::test]
async fn subject_waiting_for_client_rechecks_committed_disable(pool: PgPool) {
    let (store, realm, user) = setup(&pool).await;
    let client = store
        .configure_issuer_client(&public(realm, Uuid::new_v4(), "https://app.example/cb"))
        .await
        .unwrap();
    let view = observer(&pool).await;
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_issuer_clients WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(realm)
        .bind(client.client())
        .execute(&mut *blocker)
        .await
        .unwrap();
    let id = client.client();
    let task = tokio::spawn(async move { store.issuer_subject(&client, user).await });
    locked(&view, "%SELECT enabled FROM auth_issuer_clients%").await;
    // An owned administrative commit, observed before the waiting lookup resumes.
    // Sequential coverage separately exercises the public disable API itself.
    sqlx::query(
        "UPDATE auth_issuer_clients SET enabled=false,revision=$3 WHERE realm_id=$1 AND id=$2",
    )
    .bind(realm)
    .bind(id)
    .bind(Uuid::new_v4())
    .execute(&mut *blocker)
    .await
    .unwrap();
    blocker.commit().await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(Error::Unauthorized)));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth_issuer_subjects")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    view.close().await;
}

#[sqlx::test]
async fn owner_deleted_during_observed_wait_cannot_gain_a_new_subject(pool: PgPool) {
    let (store, realm, user) = setup(&pool).await;
    let client = store
        .configure_issuer_client(&public(realm, Uuid::new_v4(), "https://app.example/cb"))
        .await
        .unwrap();
    let session = crate::support::signed_in(&store, realm, "owner@example.test").await;
    let token = auth_core::Secret::generate().unwrap();
    let browser = auth_core::Secret::generate().unwrap();
    store
        .begin_account_deletion(
            realm,
            session.verifier(),
            token.verifier(),
            browser.verifier(),
        )
        .await
        .unwrap();
    let view = observer(&pool).await;
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE auth_audit IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let erasure_store = store.clone();
    let erasure = tokio::spawn(async move {
        erasure_store
            .finish_account_deletion(
                realm,
                session.verifier(),
                token.verifier(),
                browser.verifier(),
            )
            .await
    });
    // The actual erasure owns its account row before its audit tail blocks.
    locked(&view, "%UPDATE auth_audit%").await;
    let subject = tokio::spawn(async move { store.issuer_subject(&client, user).await });
    locked(
        &view,
        "%SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR KEY SHARE%",
    )
    .await;
    blocker.commit().await.unwrap();
    erasure.await.unwrap().unwrap();
    assert!(matches!(subject.await.unwrap(), Err(Error::Unauthorized)));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM auth_issuer_subjects")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    view.close().await;
}
