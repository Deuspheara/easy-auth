use super::*;
use crate::support::lock_observation::{locked, observer};
use auth_core::{Error, IssuerClientAuthentication, Secret};

#[sqlx::test]
async fn waiting_authentication_rechecks_a_committed_credential_replacement(pool: PgPool) {
    let (store, realm, _) = setup(&pool).await;
    let id = Uuid::new_v4();
    let secret = Secret::generate().unwrap();
    let client = store
        .configure_issuer_client(
            &IssuerClientRegistration::confidential(
                realm,
                id,
                &["https://app.example/cb"],
                &secret,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let authentication = IssuerClientAuthentication::basic(id, &secret).unwrap();
    let view = observer(&pool).await;
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_issuer_clients WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(realm)
        .bind(id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        store
            .validate_issuer_client_authentication(&client, &authentication)
            .await
    });
    locked(&view, "%SELECT enabled FROM auth_issuer_clients%").await;
    sqlx::query(
        "UPDATE auth_issuer_clients SET revision=$3,secret_verifier=$4 WHERE realm_id=$1 AND id=$2",
    )
    .bind(realm)
    .bind(id)
    .bind(Uuid::new_v4())
    .bind(Secret::generate().unwrap().verifier().to_vec())
    .execute(&mut *blocker)
    .await
    .unwrap();
    blocker.commit().await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(Error::Unauthorized)));
    view.close().await;
}

#[sqlx::test]
async fn waiting_native_subject_cannot_survive_committed_operator_disable(pool: PgPool) {
    let (store, realm, owner) = setup(&pool).await;
    let id = Uuid::new_v4();
    let client = store
        .configure_issuer_client(&native(realm, id, "http://127.0.0.1/cb"))
        .await
        .unwrap();
    let view = observer(&pool).await;
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_issuer_clients WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(realm)
        .bind(id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let task = tokio::spawn(async move { store.issuer_subject(&client, owner).await });
    locked(&view, "%SELECT enabled FROM auth_issuer_clients%").await;
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
