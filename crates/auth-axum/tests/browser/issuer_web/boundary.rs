use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn token_form_is_closed_bounded_and_strictly_decoded_without_cookies_or_proxy_fallback(
    pool: PgPool,
) {
    let f = Fixture::new(pool, Profile::Public).await;
    let code = f.code().await;
    let valid = f.body(&code);
    for body in [
        format!("{valid}&client%5Fid={}", f.client.client()),
        format!("{valid}&realm={}", f.realm),
        format!("{valid}&client_secret=unsupported"),
        format!("{valid}&owner=unselected"),
        format!("{valid}&"),
        valid.replace(&f.verifier, "%FF"),
        valid.replace(&f.verifier, "bad%"),
        "{}".to_owned(),
    ] {
        let response = f.send(body, None).await;
        assert_eq!(response.status(), 400);
        assert_eq!(read(response).await["error"], "invalid_request");
    }
    let missing_peer = f
        .app
        .clone()
        .oneshot(token_request("/oidc/token", valid.clone(), None, false))
        .await
        .unwrap();
    assert_eq!(missing_peer.status(), 503);
    assert_eq!(read(missing_peer).await["error"], "temporarily_unavailable");
    assert_eq!(
        f.app
            .clone()
            .oneshot(token_request(
                "/oidc/token?realm=other",
                valid.clone(),
                None,
                true
            ))
            .await
            .unwrap()
            .status(),
        400
    );
    let mut compressed = token_request("/oidc/token", valid.clone(), None, true);
    compressed
        .headers_mut()
        .insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
    assert_eq!(
        f.app.clone().oneshot(compressed).await.unwrap().status(),
        415
    );
    let mut json = token_request("/oidc/token", valid.clone(), None, true);
    json.headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    assert_eq!(f.app.clone().oneshot(json).await.unwrap().status(), 415);
    assert_eq!(f.send("x".repeat(9000), None).await.status(), 413);
    assert_eq!(
        f.app
            .clone()
            .oneshot(get("/oidc/token"))
            .await
            .unwrap()
            .status(),
        405
    );
    assert_eq!(f.facts().await, (1, 1, 0));
    assert_eq!(f.send(valid, None).await.status(), 200);
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn basic_header_and_body_identifiers_must_agree_and_decoded_duplicates_never_select_authentication(
    pool: PgPool,
) {
    let f = Fixture::new(pool, Profile::Confidential).await;
    let code = f.code().await;
    let basic = f.basic().unwrap();
    let mut duplicate = token_request("/oidc/token", f.body(&code), Some(&basic), true);
    duplicate
        .headers_mut()
        .append(header::AUTHORIZATION, basic.parse().unwrap());
    assert_eq!(
        f.app.clone().oneshot(duplicate).await.unwrap().status(),
        401
    );
    let mismatched = f
        .body(&code)
        .replace(&f.client.client().to_string(), &Uuid::new_v4().to_string());
    assert_eq!(f.send(mismatched, Some(&basic)).await.status(), 401);
    let encoded_client = f.client.client().to_string().replace('-', "%2d");
    let encoded_basic = format!(
        "Basic {}",
        STANDARD.encode(format!(
            "{}:{}",
            encoded_client,
            f.secret.as_ref().unwrap().expose()
        ))
    );
    assert_eq!(
        f.send(f.body(&code), Some(&encoded_basic)).await.status(),
        200
    );
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn same_trusted_peer_cannot_reset_admission_with_forwarding_headers(pool: PgPool) {
    let f = Fixture::new(pool, Profile::Public).await;
    let unknown = Secret::generate().unwrap();
    assert_eq!(f.send(f.body(&unknown), None).await.status(), 400);
    let mut refused = false;
    // At most three bounded requests tolerate one database window rollover.
    for _ in 0..3 {
        sqlx::query("UPDATE auth_issuer_token_admission SET attempts=$2 WHERE realm_id=$1")
            .bind(f.realm)
            .bind(ISSUER_TOKEN_ATTEMPTS_PER_MINUTE)
            .execute(&f.pool)
            .await
            .unwrap();
        let mut request = token_request("/oidc/token", f.body(&unknown), None, true);
        request
            .headers_mut()
            .insert("x-forwarded-for", "8.8.8.8".parse().unwrap());
        request
            .headers_mut()
            .insert("forwarded", "for=9.9.9.9".parse().unwrap());
        let response = f.app.clone().oneshot(request).await.unwrap();
        if response.status() == 429 {
            assert_eq!(read(response).await["error"], "temporarily_unavailable");
            refused = true;
            break;
        }
        assert_eq!(response.status(), 400);
    }
    assert!(refused);
    assert_eq!(f.facts().await, (1, 1, 0));
}
