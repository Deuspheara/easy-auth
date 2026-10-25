use super::setup::*;

#[tokio::test]
async fn actual_signed_web_and_native_code_results_retain_exact_nonce_client_and_return_policy() {
    for kind in [
        AppleClientType::Web,
        AppleClientType::Native(AppleNonceEncoding::Plain),
        AppleClientType::Native(AppleNonceEncoding::Sha256Hex),
    ] {
        let f = fixture();
        let (exchange, mut claims) = f.exchange().await;
        if let AppleClientType::Native(encoding) = kind {
            claims["nonce"] = json!(encoding.authorization_nonce(exchange.proof().nonce()));
        }
        claims["email"] = json!("owned@privaterelay.appleid.com");
        claims["email_verified"] = json!("true");
        let tokens = TokenHttp::new();
        tokens.success(&f, &claims);
        let client = client(&f, tokens.clone(), kind);
        let identity = client.exchange(exchange, code()).await.unwrap();
        assert_eq!(identity.subject(), "subject");
        assert_eq!(identity.email(), Some("owned@privaterelay.appleid.com"));
        assert!(identity.email_verified());
        assert_eq!(identity.authenticated_at(), None);
        assert_eq!(identity.configuration(), &f.store.connection);
        let seen = tokens.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].url, "https://appleid.apple.com/auth/token");
        assert!(seen[0].authorization.is_none());
        let form: std::collections::HashMap<_, _> =
            url::form_urlencoded::parse(seen[0].form.as_bytes()).collect();
        assert_eq!(form.len(), if kind == AppleClientType::Web { 5 } else { 4 });
        assert!(form["code"] == "owned-apple-authorization-code");
        assert_eq!(form["client_id"], "com.example.auth");
        assert_eq!(form["grant_type"], "authorization_code");
        assert!(!form.contains_key("code_verifier"));
        assert!(form["client_secret"].split('.').count() == 3);
        if kind == AppleClientType::Web {
            assert_eq!(form["redirect_uri"], f.store.connection.redirect());
        } else {
            assert!(!form.contains_key("redirect_uri"));
        }
    }
}

#[tokio::test]
async fn apple_email_encoding_is_explicit_and_empty_managed_email_grants_no_contact() {
    for email in [None, Some(""), Some("owned@example.test")] {
        for flag in [json!(true), json!(false), json!("true"), json!("false")] {
            let f = fixture();
            let (exchange, mut claims) = f.exchange().await;
            if let Some(email) = email {
                claims["email"] = json!(email);
            }
            claims["email_verified"] = flag.clone();
            let tokens = TokenHttp::new();
            tokens.success(&f, &claims);
            let identity = client(&f, tokens, AppleClientType::Web)
                .exchange(exchange, code())
                .await
                .unwrap();
            assert_eq!(identity.email(), email.filter(|s| !s.is_empty()));
            assert_eq!(
                identity.email_verified(),
                email.is_some_and(|s| !s.is_empty()) && (flag == true || flag == "true")
            );
        }
    }
}

#[tokio::test]
async fn disable_or_original_expiry_during_token_io_rejects_signed_result() {
    for disable in [true, false] {
        let f = fixture();
        let (exchange, claims) = f.exchange().await;
        let tokens = TokenHttp::new();
        tokens.success(&f, &claims);
        tokens.hold.store(true, Ordering::SeqCst);
        let client = client(&f, tokens.clone(), AppleClientType::Web);
        let task = tokio::spawn(async move { client.exchange(exchange, code()).await });
        tokens.entered.notified().await;
        if disable {
            f.store.enabled.store(false, Ordering::SeqCst);
        } else {
            f.store.now.store(NOW_US + 300_000_000, Ordering::SeqCst);
        }
        tokens.release.notify_one();
        assert!(matches!(task.await.unwrap(), Err(Error::Unauthorized)));
        assert_eq!(tokens.posts(), 1);
    }
}
