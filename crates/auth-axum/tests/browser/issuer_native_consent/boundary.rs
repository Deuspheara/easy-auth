use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn native_prepare_keeps_closed_same_origin_private_cookie_and_protocol_boundaries(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    for origin in [None, Some("https://evil.example")] {
        let response = f
            .base
            .app
            .clone()
            .oneshot(post(
                "/v1/oidc/native/consent/prepare",
                &f.input().to_string(),
                Some(&f.base.current),
                origin,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
    }
    for (name, value) in [
        ("prompt", json!("none")),
        ("scope", json!("openid")),
        ("code_challenge_method", json!("plain")),
        ("redirect_uri", json!("http://localhost:49152/callback")),
        ("untrusted", json!(true)),
    ] {
        let mut input = f.input();
        input[name] = value;
        assert_eq!(
            f.send("prepare", &input, &f.base.current).await.status(),
            400
        );
    }
    let response = f
        .base
        .app
        .clone()
        .oneshot(post(
            "/v1/oidc/native/consent/prepare?extra=1",
            &f.input().to_string(),
            Some(&f.base.current),
            Some(ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert_eq!(f.facts().await, (0, 0, 0, 0));
    let (proofs, preview) = f.prepare().await;
    assert_eq!(f.send("prepare", &f.input(), &proofs).await.status(), 401);
    let decision = json!({"authorization":preview["authorization"]});
    assert_eq!(
        f.send("approve", &decision, &f.base.current).await.status(),
        401
    );
    let mut wrong = decision.clone();
    wrong["authorization"] = json!(uuid::Uuid::new_v4());
    assert_eq!(f.send("approve", &wrong, &proofs).await.status(), 401);
    assert_eq!(f.facts().await, (1, 1, 0, 0));
    assert_eq!(f.send("cancel", &decision, &proofs).await.status(), 200);
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn bounded_closed_native_forms_and_private_cookie_hygiene_cannot_allocate_extra_state(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let path = "/v1/oidc/native/consent/prepare";
    let mut duplicate = f.input().to_string();
    duplicate.pop();
    duplicate.push_str(",\"prompt\":\"consent\"}");
    for (body, status) in [
        (duplicate, 400),
        (json!({"oversized":"x".repeat(17000)}).to_string(), 413),
    ] {
        let response = f
            .base
            .app
            .clone()
            .oneshot(post(path, &body, Some(&f.base.current), Some(ORIGIN)))
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
    let mut media = post(
        path,
        &f.input().to_string(),
        Some(&f.base.current),
        Some(ORIGIN),
    );
    media
        .headers_mut()
        .insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
    assert_eq!(
        f.base.app.clone().oneshot(media).await.unwrap().status(),
        415
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0));
    let response = f.send("prepare", &f.input(), &f.base.current).await;
    assert_eq!(response.status(), 200);
    let values: Vec<_> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(values.len(), 3);
    for value in values {
        assert!(value.starts_with("__Host-auth-issuer-"));
        for required in [
            "Path=/",
            "HttpOnly",
            "Secure",
            "SameSite=Lax",
            "Max-Age=300",
        ] {
            assert!(value.contains(required));
        }
    }
    let proofs = format!(
        "{}; {}; {}; {}",
        f.base.current,
        cookie(&response, "__Host-auth-issuer-browser="),
        cookie(&response, "__Host-auth-issuer-handle="),
        cookie(&response, "__Host-auth-issuer-operation=")
    );
    let duplicate_browser = format!(
        "{}; {}",
        proofs,
        cookie(&response, "__Host-auth-issuer-browser=")
    );
    let preview = read(response).await;
    let rejected = f
        .send(
            "approve",
            &json!({"authorization":preview["authorization"]}),
            &duplicate_browser,
        )
        .await;
    assert_eq!(rejected.status(), 401);
    assert!(!rejected.headers().contains_key(header::SET_COOKIE));
    assert_eq!(f.facts().await, (1, 1, 0, 0));
}
