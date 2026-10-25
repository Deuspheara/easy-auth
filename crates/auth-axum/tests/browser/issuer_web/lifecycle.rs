use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn actual_consent_and_native_or_confidential_token_posts_need_no_origin_or_local_cookie(
    pool: PgPool,
) {
    for profile in [Profile::Public, Profile::Confidential, Profile::Native] {
        let f = Fixture::new(pool.clone(), profile).await;
        let code = f.code().await;
        let basic = f.basic();
        let response = f.send(f.body(&code), basic.as_deref()).await;
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        let tokens = read(response).await;
        assert_eq!(tokens["token_type"], "Bearer");
        assert_eq!(tokens["scope"], "openid");
        assert!(
            tokens["expires_in"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= 60)
        );
        let key = josekit::jwk::Jwk::from_bytes(
            serde_json::to_vec(f.key.public_key().unwrap().document()).unwrap(),
        )
        .unwrap();
        let verifier = RS256.verifier_from_jwk(&key).unwrap();
        let verified =
            josekit::jws::deserialize_compact(tokens["id_token"].as_str().unwrap(), &verifier);
        assert!(
            verified.is_ok(),
            "actual wire token must have the configured production signature"
        );
        let (payload, _) = verified.unwrap();
        let claims: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(claims["iss"], ORIGIN);
        assert_eq!(claims["aud"], f.client.client().to_string());
        assert_eq!(claims["nonce"], "client-nonce");
        assert_eq!(f.facts().await, (1, 1, 1));
        let replay = f.send(f.body(&code), basic.as_deref()).await;
        assert_eq!(replay.status(), 400);
        assert_eq!(read(replay).await["error"], "invalid_grant");
        let access = Secret::parse(tokens["access_token"].as_str().unwrap().to_owned()).unwrap();
        assert!(matches!(
            f.store.authenticate(f.realm, access.verifier()).await,
            Err(Error::Unauthorized)
        ));
    }
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn confidential_wrong_credentials_and_methods_do_not_fall_back_to_ambient_session(
    pool: PgPool,
) {
    let f = Fixture::new(pool, Profile::Confidential).await;
    let code = f.code().await;
    let wrong = Secret::generate().unwrap();
    let wrong_basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{}:{}", f.client.client(), wrong.expose()))
    );
    for authentication in [None, Some("Bearer ignored"), Some(wrong_basic.as_str())] {
        let mut request = token_request("/oidc/token", f.body(&code), authentication, true);
        request
            .headers_mut()
            .insert(header::COOKIE, f.current.parse().unwrap());
        let response = f.app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), 401);
        assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
        assert_eq!(read(response).await["error"], "invalid_client");
    }
    assert_eq!(f.facts().await, (1, 1, 0));
    assert_eq!(
        f.send(f.body(&code), f.basic().as_deref()).await.status(),
        200
    );
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn bad_native_port_or_pkce_preserves_code_and_correct_actual_return_still_succeeds(
    pool: PgPool,
) {
    let f = Fixture::new(pool, Profile::Native).await;
    let code = f.code().await;
    let wrong_port = f.body(&code).replace("49152", "49153");
    assert_eq!(f.send(wrong_port, None).await.status(), 400);
    let wrong_pkce = f
        .body(&code)
        .replace(&f.verifier, Secret::generate().unwrap().expose());
    let refused = f.send(wrong_pkce, None).await;
    assert_eq!(refused.status(), 400);
    assert_eq!(read(refused).await["error"], "invalid_grant");
    assert_eq!(f.facts().await, (1, 1, 0));
    assert_eq!(f.send(f.body(&code), None).await.status(), 200);
}
