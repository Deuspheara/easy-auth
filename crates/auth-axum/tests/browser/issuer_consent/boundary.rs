use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn consent_requires_same_origin_closed_input_and_actual_session_cookies(pool: PgPool) {
    let f = Fixture::new(pool).await;
    for origin in [None, Some("https://other.example"), Some("null")] {
        let response = f
            .app
            .clone()
            .oneshot(post(
                "/v1/oidc/consent/prepare",
                &f.input().to_string(),
                Some(&f.current),
                origin,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
    }
    let duplicate = post(
        "/v1/oidc/consent/prepare",
        &f.input().to_string(),
        Some(&f.current),
        Some(ORIGIN),
    );
    let (mut parts, body) = duplicate.into_parts();
    parts
        .headers
        .append(header::ORIGIN, ORIGIN.parse().unwrap());
    assert_eq!(
        f.app
            .clone()
            .oneshot(Request::from_parts(parts, body))
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        f.send("/v1/oidc/consent/prepare", f.input(), "")
            .await
            .status(),
        401
    );
    let duplicate_cookie = format!("{}; {}", f.current, f.current);
    assert_eq!(
        f.send("/v1/oidc/consent/prepare", f.input(), &duplicate_cookie)
            .await
            .status(),
        401
    );
    for (name, value) in [
        ("owner", json!(Uuid::new_v4())),
        ("realm", json!(f.realm)),
        ("scope", json!("openid email")),
        ("code_challenge_method", json!("plain")),
        ("redirect_uri", json!("https://other.example/cb")),
    ] {
        let mut input = f.input();
        input[name] = value;
        assert_eq!(
            f.send("/v1/oidc/consent/prepare", input, &f.current)
                .await
                .status(),
            400
        );
    }
    assert_eq!(
        f.send(
            "/v1/oidc/consent/prepare?realm=other",
            f.input(),
            &f.current
        )
        .await
        .status(),
        400
    );
    let invalid = post(
        "/v1/oidc/consent/prepare",
        &f.input().to_string(),
        Some(&f.current),
        Some(ORIGIN),
    );
    let (mut parts, body) = invalid.into_parts();
    parts
        .headers
        .insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
    assert_eq!(
        f.app
            .clone()
            .oneshot(Request::from_parts(parts, body))
            .await
            .unwrap()
            .status(),
        415
    );
    let oversized = f
        .send(
            "/v1/oidc/consent/prepare",
            json!({"padding":"x".repeat(17000)}),
            &f.current,
        )
        .await;
    assert_eq!(oversized.status(), 413);
    assert_eq!(f.count("auth_issuer_authorizations").await, 0);
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn old_tab_wrong_session_missing_or_duplicate_proofs_cannot_decide_or_clear_new_request(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let old = f.prepare().await;
    assert_eq!(
        f.send(
            "/v1/oidc/consent/cancel",
            Fixture::decision(&old),
            &old.cookies
        )
        .await
        .status(),
        200
    );
    let current = f.prepare().await;
    for (body, cookies) in [
        (Fixture::decision(&old), current.cookies.clone()),
        (Fixture::decision(&current), f.current.clone()),
        (
            Fixture::decision(&current),
            format!(
                "{}; {}",
                current.cookies,
                cookie_component(&current.cookies, "__Host-auth-issuer-handle=")
            ),
        ),
    ] {
        for path in ["/v1/oidc/consent/approve", "/v1/oidc/consent/cancel"] {
            let denied = f.send(path, body.clone(), &cookies).await;
            assert_eq!(denied.status(), 401);
            assert!(!denied.headers().contains_key(header::SET_COOKIE));
        }
    }
    // Real independent sign-ins, not owner/session identifiers supplied by a body.
    let proofs = current
        .cookies
        .split("; ")
        .skip(1)
        .collect::<Vec<_>>()
        .join("; ");
    for email in ["owner@example.test", "other@example.test"] {
        let session = sign_in(&f.app, &f.mail, email).await;
        let cookies = format!("{session}; {proofs}");
        let denied = f
            .send(
                "/v1/oidc/consent/approve",
                Fixture::decision(&current),
                &cookies,
            )
            .await;
        assert_eq!(denied.status(), 401);
        assert!(!denied.headers().contains_key(header::SET_COOKIE));
    }
    let mut wrong_owner = Fixture::decision(&current);
    wrong_owner["owner"] = json!(Uuid::new_v4());
    assert_eq!(
        f.send("/v1/oidc/consent/approve", wrong_owner, &current.cookies)
            .await
            .status(),
        400
    );
    assert_eq!(
        f.send("/v1/oidc/consent/approve", json!({}), &current.cookies)
            .await
            .status(),
        400
    );
    assert_eq!(
        f.send(
            "/v1/oidc/consent/approve",
            Fixture::decision(&current),
            &current.cookies
        )
        .await
        .status(),
        200
    );
}
fn cookie_component<'a>(cookies: &'a str, name: &str) -> &'a str {
    cookies
        .split("; ")
        .find(|pair| pair.starts_with(name))
        .unwrap()
}
