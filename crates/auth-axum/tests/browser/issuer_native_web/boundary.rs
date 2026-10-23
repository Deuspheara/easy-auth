use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn mixed_wire_forms_scope_peer_and_authentication_cannot_use_cookie_or_type_fallback(
    pool: PgPool,
) {
    let f = fixture(pool).await;
    let initial = issued(&f).await;
    let token = initial["refresh_token"].as_str().unwrap();
    for extra in [
        "&code=wrong",
        "&redirect_uri=http%3A%2F%2Flocalhost",
        "&client_secret=wrong",
        "&grant_type=authorization_code",
        "&%67rant_type=refresh_token",
    ] {
        assert_eq!(
            f.base
                .send(refresh_body(&f, token) + extra, None)
                .await
                .status(),
            400
        );
    }
    let response = f
        .base
        .send(refresh_body(&f, token) + "&scope=openid", None)
        .await;
    assert_eq!(response.status(), 400);
    assert_eq!(read(response).await, json!({"error":"invalid_scope"}));
    let request = token_request("/oidc/token", refresh_body(&f, token), None, false);
    assert_eq!(
        f.base.app.clone().oneshot(request).await.unwrap().status(),
        503
    );
    let mut request = token_request("/oidc/token", refresh_body(&f, token), None, true);
    *request.uri_mut() = "/oidc/token?untrusted=1".parse().unwrap();
    assert_eq!(
        f.base.app.clone().oneshot(request).await.unwrap().status(),
        400
    );
    let mut request = token_request(
        "/oidc/introspect",
        status_body(f.base.client.client(), token),
        None,
        true,
    );
    request
        .headers_mut()
        .insert(header::COOKIE, f.base.current.parse().unwrap());
    assert_eq!(
        f.base.app.clone().oneshot(request).await.unwrap().status(),
        401
    );
    let response = f
        .base
        .send(
            refresh_body(&f, token) + "&scope=openid%20offline_access",
            None,
        )
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(f.base.facts().await, (1, 1, 2));
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn unknown_client_still_spends_one_source_admission_and_cannot_consume_genuine_code(
    pool: PgPool,
) {
    let f = fixture(pool).await;
    let code = code(&f).await;
    let body = f.base.body(&code).replace(
        &f.base.client.client().to_string(),
        &uuid::Uuid::new_v4().to_string(),
    );
    assert_eq!(f.base.send(body, None).await.status(), 401);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT sum(attempts)::bigint FROM auth_issuer_token_admission WHERE realm_id=$1"
        )
        .bind(f.base.realm)
        .fetch_one(&f.base.pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(f.facts().await, (1, 1, 0, 1));
    assert_eq!(f.base.send(f.base.body(&code), None).await.status(), 200);
}
