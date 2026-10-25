use crate::support::lock_observation as locks;
use crate::support::{linked_provider_records, realm, signed_in};
use auth_core::{Error, LinkedProviderCursor, ProviderKind, Repository};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test]
async fn provider_pages_are_bounded_and_protocol_cursor_preserves_equal_identity_ids(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let session = signed_in(&store, realm, "owner@example.test").await;
    let owner = store.authenticate(realm, session.verifier()).await.unwrap();
    for id in 1..=51 {
        linked_provider_records::insert(
            &pool,
            realm,
            owner.id,
            Uuid::from_u128(id),
            ProviderKind::Oidc,
        )
        .await;
    }
    linked_provider_records::insert(
        &pool,
        realm,
        owner.id,
        Uuid::from_u128(1),
        ProviderKind::Saml,
    )
    .await;
    let first = store
        .linked_providers(realm, session.verifier(), None)
        .await
        .unwrap();
    assert_eq!(first.providers.len(), 50);
    assert!(first.providers.iter().all(|p| p.kind == ProviderKind::Oidc));
    assert_eq!(
        first.next,
        Some(LinkedProviderCursor {
            kind: ProviderKind::Oidc,
            id: Uuid::from_u128(50),
        })
    );
    let second = store
        .linked_providers(realm, session.verifier(), first.next)
        .await
        .unwrap();
    assert_eq!(second.providers.len(), 2);
    assert_eq!(second.providers[0].id, Uuid::from_u128(51));
    assert_eq!(second.providers[1].kind, ProviderKind::Saml);
    assert_eq!(second.providers[1].id, Uuid::from_u128(1));
    assert_eq!(second.next, None);
    let end = store
        .linked_providers(
            realm,
            session.verifier(),
            Some(LinkedProviderCursor {
                kind: ProviderKind::Saml,
                id: Uuid::from_u128(1),
            }),
        )
        .await
        .unwrap();
    assert!(end.providers.is_empty());
}

#[sqlx::test]
async fn provider_metadata_never_crosses_owner_realm_or_revoked_caller(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let session = signed_in(&store, realm, "owner@example.test").await;
    let owner = store.authenticate(realm, session.verifier()).await.unwrap();
    let other = signed_in(&store, realm, "other@example.test").await;
    let other_owner = store.authenticate(realm, other.verifier()).await.unwrap();
    let foreign_realm = Uuid::new_v4();
    store.ensure_realm(foreign_realm).await.unwrap();
    let foreign = signed_in(&store, foreign_realm, "owner@example.test").await;
    let foreign_owner = store
        .authenticate(foreign_realm, foreign.verifier())
        .await
        .unwrap();
    let id = Uuid::new_v4();
    for (realm, owner, id) in [
        (realm, owner.id, id),
        (realm, other_owner.id, Uuid::new_v4()),
        (foreign_realm, foreign_owner.id, id),
    ] {
        linked_provider_records::insert(&pool, realm, owner, id, ProviderKind::Oidc).await;
    }
    let page = store
        .linked_providers(realm, session.verifier(), None)
        .await
        .unwrap();
    assert_eq!(page.providers.len(), 1);
    assert_eq!(page.providers[0].id, id);
    assert_eq!(page.providers[0].issuer, "https://oidc.example");
    assert!(matches!(
        store
            .linked_providers(foreign_realm, session.verifier(), None)
            .await,
        Err(Error::Unauthorized)
    ));
    store.revoke(realm, session.verifier()).await.unwrap();
    assert!(matches!(
        store
            .linked_providers(realm, session.verifier(), None)
            .await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test]
async fn provider_read_waiting_for_owner_rejects_committed_revocation(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let session = signed_in(&store, realm, "owner@example.test").await;
    let owner = store.authenticate(realm, session.verifier()).await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(realm)
        .bind(owner.id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let reader = store.clone();
    let verifier = session.verifier();
    let task = tokio::spawn(async move { reader.linked_providers(realm, verifier, None).await });
    let observer = locks::observer(&pool).await;
    locks::locked(&observer, "%FOR SHARE OF u%").await;
    sqlx::query(
        "UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1 AND token_hash=$2",
    )
    .bind(realm)
    .bind(session.verifier().as_slice())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(Error::Unauthorized)));
    observer.close().await;
}

#[sqlx::test]
async fn provider_storage_failure_is_unavailable_and_rolls_back_session_touch(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let session = signed_in(&store, realm, "owner@example.test").await;
    let before: String = sqlx::query_scalar(
        "SELECT last_seen_at::text FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2",
    )
    .bind(realm)
    .bind(session.verifier().as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("ALTER TABLE auth_oidc_identities RENAME TO unavailable_oidc_identities")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        store
            .linked_providers(realm, session.verifier(), None)
            .await,
        Err(Error::Unavailable)
    ));
    let after: String = sqlx::query_scalar(
        "SELECT last_seen_at::text FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2",
    )
    .bind(realm)
    .bind(session.verifier().as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(before, after);
}

#[cfg(any(feature = "saml-identities", feature = "google"))]
#[sqlx::test]
async fn provider_read_retains_original_deadline_after_an_observed_inventory_wait(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let session = signed_in(&store, realm, "owner@example.test").await;
    let cap: i64 = sqlx::query_scalar(
        "UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '1 second'
        WHERE realm_id=$1 AND token_hash=$2
        RETURNING (extract(epoch FROM expires_at)*1000000)::bigint",
    )
    .bind(realm)
    .bind(session.verifier().as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    let before: String = sqlx::query_scalar(
        "SELECT last_seen_at::text FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2",
    )
    .bind(realm)
    .bind(session.verifier().as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE auth_oidc_identities IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *gate)
        .await
        .unwrap();
    let reader = store.clone();
    let current = session.verifier();
    let task = tokio::spawn(async move { reader.linked_providers(realm, current, None).await });
    let observer = locks::observer(&pool).await;
    locks::locked(&observer, "%SELECT id,kind,issuer%").await;
    crate::support::observation::expired(&observer, cap).await;
    gate.commit().await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(Error::Unauthorized)));
    let after: String = sqlx::query_scalar(
        "SELECT last_seen_at::text FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2",
    )
    .bind(realm)
    .bind(session.verifier().as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(before, after);
    let fresh = signed_in(&store, realm, "owner@example.test").await;
    assert!(
        store
            .linked_providers(realm, fresh.verifier(), None)
            .await
            .unwrap()
            .providers
            .is_empty()
    );
    observer.close().await;
}
