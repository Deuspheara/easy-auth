use super::setup::*;
use uuid::Uuid;
fn response(state: &Secret) -> AppleAuthorizationResponse {
    AppleAuthorizationResponse::parse(&format!(
        "state={}&code=owned-apple-authorization-code",
        state.expose()
    ))
    .unwrap()
}
fn vault() -> AppleGrantVault {
    AppleGrantVault::new(
        AppleGrantKey::new(Uuid::new_v4(), vec![17; 32]).unwrap(),
        vec![],
    )
    .unwrap()
}

#[tokio::test]
async fn capture_only_after_signed_nonce_and_explicit_mapping_then_protect_actual_source() {
    for refresh in [false, true] {
        let f = fixture();
        let tokens = TokenHttp::new();
        let flow = AppleGrantAuthorization::sign_in(
            Arc::new(OAuthTransactions::new(
                f.store.connection.clone(),
                f.store.clone(),
            )),
            Arc::new(client(&f, tokens.clone(), AppleClientType::Web)),
        )
        .unwrap();
        let browser = Secret::generate().unwrap();
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned",
            purpose: OAuthPurpose::SignIn,
        };
        let start = flow.begin(&intent).await.unwrap();
        tokens.success(
            &f,
            &json!({"iss":"https://appleid.apple.com","sub":"owned","aud":start.request.client_id(),
            "nonce":start.request.nonce(),"iat":NOW_US/1_000_000,"exp":NOW_US/1_000_000+60}),
        );
        if refresh {
            let mut body: serde_json::Value =
                serde_json::from_slice(&tokens.body.lock().unwrap()).unwrap();
            body["refresh_token"] = json!("owned-refresh-only");
            body["expires_in"] = json!(0);
            *tokens.body.lock().unwrap() = serde_json::to_vec(&body).unwrap();
        }
        let result = flow
            .finish(
                &intent,
                &start.transaction.state,
                start.transaction.proof,
                f.store.connection.redirect(),
                response(&start.transaction.state),
            )
            .await
            .unwrap();
        let AppleGrantAuthorizationCompletion::Verified(grant) = result else {
            panic!("actual signed capture required")
        };
        assert_eq!(format!("{grant:?}"), "AppleVerifiedGrant([REDACTED])");
        let policy = OidcIdentityPolicy::new(
            f.store.connection.clone(),
            &["https://appleid.apple.com"],
            OidcDisplayNameClaim::Subject,
        )
        .unwrap();
        let (_, capture) = grant.map(&policy).unwrap().into_parts();
        let c = capture.configuration();
        let binding = AppleGrantBinding::new(
            c.realm(),
            c.connection(),
            c.client(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .unwrap();
        let vault = vault();
        let envelope = capture.seal(binding, &vault).await.unwrap();
        assert!(!envelope.ciphertext().contains("owned-refresh-only"));
        assert!(vault.rewrap(&envelope).await.is_ok());
        assert_eq!(tokens.posts(), 1);
    }
}

#[tokio::test]
async fn wrong_signed_nonce_cannot_return_credentials_and_missing_access_lifetime_is_unavailable() {
    for wrong_nonce in [true, false] {
        let f = fixture();
        let tokens = TokenHttp::new();
        let flow = AppleGrantAuthorization::sign_in(
            Arc::new(OAuthTransactions::new(
                f.store.connection.clone(),
                f.store.clone(),
            )),
            Arc::new(client(&f, tokens.clone(), AppleClientType::Web)),
        )
        .unwrap();
        let browser = Secret::generate().unwrap();
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned",
            purpose: OAuthPurpose::SignIn,
        };
        let start = flow.begin(&intent).await.unwrap();
        tokens.success(&f,&json!({"iss":"https://appleid.apple.com","sub":"owned","aud":start.request.client_id(),
            "nonce":if wrong_nonce {"wrong"}else{start.request.nonce()},"iat":NOW_US/1_000_000,"exp":NOW_US/1_000_000+60}));
        if !wrong_nonce {
            let mut body: serde_json::Value =
                serde_json::from_slice(&tokens.body.lock().unwrap()).unwrap();
            body.as_object_mut().unwrap().remove("expires_in");
            *tokens.body.lock().unwrap() = serde_json::to_vec(&body).unwrap();
        }
        let result = flow
            .finish(
                &intent,
                &start.transaction.state,
                start.transaction.proof,
                f.store.connection.redirect(),
                response(&start.transaction.state),
            )
            .await;
        if wrong_nonce {
            assert!(matches!(result, Err(Error::Unauthorized)));
        } else {
            assert!(matches!(result, Err(Error::Unavailable)));
        }
        assert_eq!(tokens.posts(), 1);
    }
}

#[test]
fn capturing_link_registration_stays_web_only() {
    let f = fixture();
    let tokens = TokenHttp::new();
    assert!(
        AppleGrantAuthorization::linking(
            Arc::new(OAuthTransactions::new(
                f.store.connection.clone(),
                f.store.clone()
            )),
            Arc::new(client(
                &f,
                tokens,
                AppleClientType::Native(AppleNonceEncoding::Plain)
            ))
        )
        .is_err()
    );
}

#[tokio::test]
async fn access_only_capture_rejects_zero_excessive_and_malformed_lifetimes() {
    for lifetime in [json!(0), json!(86401), json!(null), json!("60")] {
        let f = fixture();
        let tokens = TokenHttp::new();
        let flow = AppleGrantAuthorization::sign_in(
            Arc::new(OAuthTransactions::new(
                f.store.connection.clone(),
                f.store.clone(),
            )),
            Arc::new(client(&f, tokens.clone(), AppleClientType::Web)),
        )
        .unwrap();
        let browser = Secret::generate().unwrap();
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-lifetime",
            purpose: OAuthPurpose::SignIn,
        };
        let start = flow.begin(&intent).await.unwrap();
        tokens.success(
            &f,
            &json!({"iss":"https://appleid.apple.com","sub":"owned","aud":start.request.client_id(),
            "nonce":start.request.nonce(),"iat":NOW_US/1_000_000,"exp":NOW_US/1_000_000+60}),
        );
        let mut body: serde_json::Value =
            serde_json::from_slice(&tokens.body.lock().unwrap()).unwrap();
        body["expires_in"] = lifetime;
        *tokens.body.lock().unwrap() = serde_json::to_vec(&body).unwrap();
        let result = flow
            .finish(
                &intent,
                &start.transaction.state,
                start.transaction.proof,
                f.store.connection.redirect(),
                response(&start.transaction.state),
            )
            .await;
        assert!(matches!(result, Err(Error::Unavailable)));
        assert_eq!(tokens.posts(), 1);
    }
}
