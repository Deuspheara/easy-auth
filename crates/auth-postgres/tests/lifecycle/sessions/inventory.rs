use super::session;
use crate::support::{realm, signed_in};
use auth_core::{Error, Repository};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn inventory_is_owned_active_and_does_not_touch_other_devices(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    let (other, other_id) = session(&pool, realm, user.id).await;
    sqlx::query(
        "UPDATE auth_sessions SET last_seen_at=clock_timestamp()-interval '1 minute' WHERE id=$1",
    )
    .bind(other_id)
    .execute(&pool)
    .await
    .unwrap();
    let before:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM last_seen_at)*1000)::bigint FROM auth_sessions WHERE id=$1")
        .bind(other_id).fetch_one(&pool).await.unwrap();
    let (_, legacy_id) = session(&pool, realm, user.id).await;
    sqlx::query("UPDATE auth_sessions SET authenticated_at='-infinity' WHERE id=$1")
        .bind(legacy_id)
        .execute(&pool)
        .await
        .unwrap();
    for assignment in [
        "expires_at=clock_timestamp()",
        "last_seen_at=clock_timestamp()-interval '30 minutes'",
        "revoked_at=clock_timestamp()",
    ] {
        let (_, id) = session(&pool, realm, user.id).await;
        sqlx::query(&format!(
            "UPDATE auth_sessions SET {assignment} WHERE id=$1"
        ))
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    }
    let bob = signed_in(&store, realm, "bob@example.com").await;
    let other_realm = Uuid::new_v4();
    store.ensure_realm(other_realm).await.unwrap();
    let foreign = signed_in(&store, other_realm, "alice@example.com").await;
    let page = store
        .list_sessions(realm, current.verifier(), None)
        .await
        .unwrap();
    assert_eq!(page.sessions.len(), 3);
    assert!(page.next.is_none());
    assert_eq!(page.sessions.iter().filter(|s| s.current).count(), 1);
    let other_info = page.sessions.iter().find(|s| s.id == other_id).unwrap();
    assert_eq!(other_info.last_seen_at_ms, before);
    assert_eq!(other_info.idle_expires_at_ms, before + 30 * 60 * 1000);
    assert!(other_info.idle_expires_at_ms <= other_info.expires_at_ms);
    assert_eq!(
        page.sessions
            .iter()
            .find(|s| s.id == legacy_id)
            .unwrap()
            .authenticated_at_ms,
        None
    );
    let after:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM last_seen_at)*1000)::bigint FROM auth_sessions WHERE id=$1")
        .bind(other_id).fetch_one(&pool).await.unwrap();
    assert_eq!(before, after);
    for (r, s) in [(realm, &other), (realm, &bob), (other_realm, &foreign)] {
        assert!(store.authenticate(r, s.verifier()).await.is_ok());
    }
    assert!(matches!(
        store
            .list_sessions(other_realm, current.verifier(), None)
            .await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn cursor_pages_are_bounded_complete_and_cannot_widen_ownership(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    let mut expected: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM auth_sessions WHERE user_id=$1")
            .bind(user.id)
            .fetch_all(&pool)
            .await
            .unwrap();
    for _ in 0..102 {
        expected.push(session(&pool, realm, user.id).await.1);
    }
    let bob = signed_in(&store, realm, "bob@example.com").await;
    let foreign_id: Uuid = sqlx::query_scalar("SELECT id FROM auth_sessions WHERE token_hash=$1")
        .bind(bob.verifier().as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
    expected.sort_unstable();
    let mut found = Vec::new();
    let mut after = None;
    for size in [50, 50, 3] {
        let page = store
            .list_sessions(realm, current.verifier(), after)
            .await
            .unwrap();
        assert_eq!(page.sessions.len(), size);
        if size == 50 {
            assert_eq!(page.next, page.sessions.last().map(|s| s.id));
        } else {
            assert!(page.next.is_none());
        }
        found.extend(page.sessions.iter().map(|s| s.id));
        after = page.next;
    }
    assert_eq!(found, expected);
    let page = store
        .list_sessions(realm, current.verifier(), Some(foreign_id))
        .await
        .unwrap();
    assert!(
        page.sessions
            .iter()
            .all(|s| expected.contains(&s.id) && s.id > foreign_id)
    );
    let page = store
        .list_sessions(realm, current.verifier(), expected.last().copied())
        .await
        .unwrap();
    assert!(page.sessions.is_empty());
    assert!(page.next.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn expired_and_revoked_callers_cannot_list_even_an_empty_cursor_page(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    for assignment in [
        "expires_at=clock_timestamp()",
        "last_seen_at=clock_timestamp()-interval '30 minutes'",
        "revoked_at=clock_timestamp()",
    ] {
        let (invalid, id) = session(&pool, realm, user.id).await;
        sqlx::query(&format!(
            "UPDATE auth_sessions SET {assignment} WHERE id=$1"
        ))
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
        assert!(matches!(
            store
                .list_sessions(realm, invalid.verifier(), Some(Uuid::max()))
                .await,
            Err(Error::Unauthorized)
        ));
    }
    assert_eq!(
        store
            .list_sessions(realm, current.verifier(), None)
            .await
            .unwrap()
            .sessions
            .len(),
        1
    );
}
