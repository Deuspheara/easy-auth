use super::*;

#[sqlx::test]
async fn explicit_capture_protects_each_verified_result_but_default_builder_discards(pool: PgPool) {
    let ordinary = Fixture::with_origin(pool.clone(), "https://ordinary.example").await;
    ordinary.signin().await;
    assert_eq!(
        grants(&ordinary).await,
        0,
        "compiling capture does not select it"
    );
    let f = captured(pool).await;
    for _ in 0..2 {
        let a = f.start().await;
        let raw = f.issue(&a, json!({}), None).await;
        let response = f.post("finish", json!({"response":raw}), &a.cookie).await;
        assert_eq!(response.status(), 204);
        let _session = session(&response);
        assert!(to_bytes(response.into_body(), 1).await.unwrap().is_empty());
    }
    assert_eq!(f.facts().await, (1, 1, 2, 2, 0));
    assert_eq!(grants(&f).await, 2);
    let rows: Vec<(String, String, Uuid, Uuid)> = sqlx::query_as(
        "SELECT state,ciphertext,identity_id,binding_identity_id FROM auth_apple_grants WHERE realm_id=$1")
        .bind(f.realm()).fetch_all(&f.pool).await.unwrap();
    for (state, encrypted, identity, binding) in rows {
        assert_eq!(state, "active");
        assert_eq!(identity, binding);
        assert!(!encrypted.contains("unused-owned-refresh"));
        assert!(!encrypted.contains("unused-owned-token"));
        assert_eq!(encrypted.split('.').count(), 5);
    }
}

#[sqlx::test]
async fn capture_without_configured_vault_fails_final_commit_and_never_falls_back(pool: PgPool) {
    let f = super::super::composition::with_grants(pool, ORIGIN, None).await;
    let a = f.start().await;
    let raw = f.issue(&a, json!({}), None).await;
    let response = f.post("finish", json!({"response":raw}), &a.cookie).await;
    assert_eq!(response.status(), 503);
    no_session(&response);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(grants(&f).await, 0);
    assert_eq!(f.provider.signed.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.post("finish", json!({"response":raw}), &a.cookie)
            .await
            .status(),
        401
    );
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
}

#[sqlx::test]
async fn captured_callback_keeps_nonce_realm_private_cookie_and_one_use_boundaries(pool: PgPool) {
    let f = captured(pool.clone()).await;
    let other =
        super::super::composition::with_grants(pool, "https://other.example", Some(vault())).await;
    let a = f.start().await;
    let raw = f.issue(&a, json!({}), None).await;
    let denied = other
        .post("finish", json!({"response":raw}), &a.cookie)
        .await;
    assert_eq!(denied.status(), 401);
    no_session(&denied);
    assert_eq!(grants(&other).await, 0);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    let (left, right) = tokio::join!(
        f.post("finish", json!({"response":raw}), &a.cookie),
        f.post("finish", json!({"response":raw}), &a.cookie)
    );
    let mut status = [left.status().as_u16(), right.status().as_u16()];
    status.sort();
    assert_eq!(status, [204, 401]);
    assert_eq!(grants(&f).await, 1);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    let a = f.start().await;
    let raw = f
        .issue(&a, json!({"nonce":"wrong-signed-nonce"}), None)
        .await;
    let response = f.post("finish", json!({"response":raw}), &a.cookie).await;
    assert_eq!(response.status(), 401);
    no_session(&response);
    assert_eq!(grants(&f).await, 1);
}
