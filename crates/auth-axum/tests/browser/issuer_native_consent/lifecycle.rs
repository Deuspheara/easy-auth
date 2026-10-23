use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn native_preview_fixed_bounds_explicit_approval_and_separate_concrete_issuance(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let (proofs, preview) = f.prepare().await;
    assert_eq!(preview.as_object().unwrap().len(), 6);
    assert_eq!(preview["idle_seconds"], 600);
    assert!(
        preview["grant_expires_at_us"].as_i64().unwrap()
            > preview["expires_at_us"].as_i64().unwrap()
    );
    assert_eq!(f.facts().await, (1, 1, 0, 0));
    let resumed = f.send("resume", &json!({}), &proofs).await;
    assert_eq!(resumed.status(), 200);
    assert!(!resumed.headers().contains_key(header::SET_COOKIE));
    assert_eq!(read(resumed).await, preview);
    let decision = json!({"authorization":preview["authorization"]});
    let wrong = f
        .base
        .app
        .clone()
        .oneshot(post(
            "/v1/oidc/consent/approve",
            &decision.to_string(),
            Some(&proofs),
            Some(ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401);
    assert_eq!(f.facts().await, (1, 1, 0, 0));
    let response = f.send("approve", &decision, &proofs).await;
    assert_eq!(response.status(), 200);
    for name in [
        "__Host-auth-issuer-browser=",
        "__Host-auth-issuer-handle=",
        "__Host-auth-issuer-operation=",
    ] {
        assert!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|v| v.to_str().unwrap().starts_with(name)
                    && v.to_str().unwrap().contains("Max-Age=0"))
        );
    }
    let returned = read(response).await;
    let url = url::Url::parse(returned["redirect_uri"].as_str().unwrap()).unwrap();
    assert_eq!(url.host_str(), Some("127.0.0.1"));
    assert_eq!(url.port(), Some(49152));
    let fields: std::collections::BTreeMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(fields["state"], "native-http-state");
    assert_eq!(fields["iss"], ORIGIN);
    let code = Secret::parse(fields["code"].clone()).unwrap();
    assert_eq!(f.facts().await, (1, 1, 0, 1));
    assert_eq!(f.send("approve", &decision, &proofs).await.status(), 401);
    let signer = IssuerTokenIssuer::new(
        f.policy.authority().clone(),
        f.base.store.clone(),
        vec![f.base.key.clone()],
    )
    .unwrap();
    let auth = IssuerClientAuthentication::public(f.base.client.client()).unwrap();
    assert!(matches!(
        signer
            .exchange(&auth, &code, &f.base.redirect, &f.base.pkce, "127.0.0.1")
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    let native = IssuerNativeTokenIssuer::new(&signer, f.base.store.clone());
    let _issued = native
        .exchange(&auth, &code, &f.base.redirect, &f.base.pkce, "127.0.0.1")
        .await
        .unwrap();
    assert_eq!(f.facts().await, (1, 1, 1, 1));
    // The consent-only HTTP component does not mount a token/refresh endpoint.
    let absent = f
        .base
        .app
        .clone()
        .oneshot(post("/oidc/token", "{}", None, Some(ORIGIN)))
        .await
        .unwrap();
    assert_eq!(absent.status(), 404);
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn cancellation_after_disable_and_actual_new_session_cannot_approve_old_operation(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let (proofs, preview) = f.prepare().await;
    let current = crate::support::sign_in(&f.base.app, &f.mail, "owner@example.test").await;
    let foreign = proofs.replacen(&f.base.current, &current, 1);
    let decision = json!({"authorization":preview["authorization"]});
    assert_eq!(f.send("approve", &decision, &foreign).await.status(), 401);
    assert_eq!(f.facts().await, (1, 1, 0, 0));
    f.base
        .store
        .disable_issuer_native_refresh_policy(f.policy.authority(), f.base.client.client())
        .await
        .unwrap();
    assert_eq!(f.send("approve", &decision, &proofs).await.status(), 401);
    let response = f.send("cancel", &decision, &proofs).await;
    assert_eq!(response.status(), 200);
    let returned = read(response).await;
    let url = url::Url::parse(returned["redirect_uri"].as_str().unwrap()).unwrap();
    let fields: std::collections::BTreeMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(fields["error"], "access_denied");
    assert!(!fields.contains_key("code"));
    assert_eq!(f.facts().await, (0, 0, 0, 0));
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn actual_local_session_replacement_clears_native_private_transport_without_approving(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let (proofs, _) = f.prepare().await;
    let start = f
        .base
        .app
        .clone()
        .oneshot(post(
            "/v1/email/start",
            &json!({"email":"owner@example.test"}).to_string(),
            Some(&proofs),
            Some(ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(start.status(), 202);
    let browser = cookie(&start, "__Host-auth-browser=");
    let token = f.mail.sign_ins.lock().unwrap().last().unwrap().clone();
    let response = f
        .base
        .app
        .clone()
        .oneshot(post(
            "/v1/email/finish",
            &json!({"token":token}).to_string(),
            Some(&format!("{proofs}; {browser}")),
            Some(ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
    assert!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("__Host-auth-session="))
    );
    for name in [
        "__Host-auth-issuer-browser=",
        "__Host-auth-issuer-handle=",
        "__Host-auth-issuer-operation=",
    ] {
        assert!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|v| v.to_str().unwrap().starts_with(name)
                    && v.to_str().unwrap().contains("Max-Age=0"))
        );
    }
    assert_eq!(f.facts().await, (1, 1, 0, 0));
}
