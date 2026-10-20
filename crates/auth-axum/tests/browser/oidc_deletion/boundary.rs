use super::setup::*;
use crate::support::post;
use auth_core::*;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use easy_auth_axum::{
    BrowserConfig, OidcAccountDeletionServices, experimental_oidc_account_deletion_router,
};
use http_body_util::BodyExt;
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

#[sqlx::test]
async fn constructors_reject_misaligned_trusted_services(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let other = OAuthConnection::new(
        f.auth.realm(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        "https://issuer.example",
        "client",
        "https://app.example/oidc/account-delete/callback",
        OAuthMixupDefense::RequireIssuer,
    )
    .unwrap();
    let wrong_flow = Arc::new(OAuthTransactions::new(other.clone(), f.store.clone()));
    let deletion = Arc::new(OidcAccountDeletion::new(f.store.clone()));
    assert!(matches!(
        OidcAccountDeletionServices::new(
            f.policy.clone(),
            wrong_flow,
            f.exchange.clone(),
            deletion.clone()
        ),
        Err(Error::InvalidInput)
    ));
    let wrong_documents = Arc::new(
        OidcDocuments::new(
            other.clone(),
            &["https://issuer.example"],
            f.store.clone(),
            f.provider.clone(),
        )
        .unwrap(),
    );
    let wrong_exchange = Arc::new(OidcCodeExchange::new(
        wrong_documents,
        f.store.clone(),
        OidcVerificationPolicy::new(&[OidcSigningAlgorithm::ES256], &[]).unwrap(),
        OidcClientAuthentication::Public,
        f.provider.clone(),
    ));
    assert!(matches!(
        OidcAccountDeletionServices::new(
            f.policy.clone(),
            f.transactions.clone(),
            wrong_exchange,
            deletion.clone()
        ),
        Err(Error::InvalidInput)
    ));
    let wrong_policy = OidcIdentityPolicy::new(
        other,
        &["https://issuer.example"],
        OidcDisplayNameClaim::Subject,
    )
    .unwrap();
    assert!(matches!(
        OidcAccountDeletionServices::new(
            wrong_policy,
            f.transactions.clone(),
            f.exchange.clone(),
            deletion
        ),
        Err(Error::InvalidInput)
    ));
    for origin in ["https://other.example", "http://localhost"] {
        assert!(matches!(
            experimental_oidc_account_deletion_router(
                f.auth.clone(),
                BrowserConfig::new(origin, true).unwrap(),
                f.services.clone()
            ),
            Err(Error::InvalidInput)
        ));
    }
    let other_auth = Auth::new(
        Uuid::new_v4(),
        f.store.clone(),
        Arc::new(crate::support::Mail::default()),
    );
    assert!(matches!(
        experimental_oidc_account_deletion_router(
            other_auth,
            BrowserConfig::new("https://app.example", false).unwrap(),
            f.services
        ),
        Err(Error::InvalidInput)
    ));
}

#[sqlx::test]
async fn origin_and_closed_inputs_cannot_begin_or_echo_proof(pool: PgPool) {
    let f = Fixture::new(pool).await;
    for origin in [
        None,
        Some("null"),
        Some("https://evil.example"),
        Some("https://app.example/"),
    ] {
        let response = f
            .app
            .clone()
            .oneshot(post(
                &format!("{ROOT}/start"),
                r#"{"confirmation":"delete my account"}"#,
                Some(&f.session_cookie()),
                origin,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(cleared(&response), 0);
    }
    let mut duplicate = post(
        &format!("{ROOT}/start"),
        r#"{"confirmation":"delete my account"}"#,
        Some(&f.session_cookie()),
        Some("https://app.example"),
    );
    duplicate
        .headers_mut()
        .append(header::ORIGIN, "https://app.example".parse().unwrap());
    assert_eq!(
        f.app.clone().oneshot(duplicate).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    for (path, input) in [
        ("start", r#"{"confirmation":"DELETE MY ACCOUNT"}"#),
        (
            "start",
            r#"{"confirmation":"delete my account","owner":"secret-marker"}"#,
        ),
        (
            "start",
            r#"{"confirmation":"delete my account","confirmation":"delete my account"}"#,
        ),
        (
            "start?secret-marker=proof",
            r#"{"confirmation":"delete my account"}"#,
        ),
        ("finish?secret-marker=proof", "{}"),
        ("cancel?secret-marker=proof", "{}"),
    ] {
        let response = f
            .app
            .clone()
            .oneshot(post(
                &format!("{ROOT}/{path}"),
                input,
                Some(&f.session_cookie()),
                Some("https://app.example"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let value = body(response).await;
        assert_eq!(value.as_object().unwrap().len(), 1);
        assert!(!value.to_string().contains("secret-marker"));
    }
    assert_eq!(f.pending().await, 0);
    assert!(f.exists().await);
}

#[sqlx::test]
async fn bounds_media_type_and_missing_session_are_explicit(pool: PgPool) {
    let f = Fixture::new(pool).await;
    assert_eq!(
        f.post("start", json!({"confirmation":"delete my account"}), "")
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let large = format!("{{\"confirmation\":\"{}\"}}", "x".repeat(9000));
    let response = f
        .app
        .clone()
        .oneshot(post(
            &format!("{ROOT}/start"),
            &large,
            Some(&f.session_cookie()),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let request = Request::builder()
        .method("POST")
        .uri(format!("{ROOT}/start"))
        .header(header::ORIGIN, "https://app.example")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(
        f.app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert_eq!(f.pending().await, 0);
}

#[sqlx::test]
async fn callback_get_is_static_and_normal_composition_has_no_deletion_routes(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let attempt = f.start().await;
    for path in [
        "/oidc/account-delete/callback?code=secret-marker&state=secret-marker",
        "/oidc/account-delete",
    ] {
        let response = f
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(header::COOKIE, &attempt.cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert!(
            response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!String::from_utf8_lossy(&bytes).contains("secret-marker"));
    }
    assert_eq!(f.pending().await, 1);
    assert!(f.exists().await);
    let normal = easy_auth_axum::router(
        f.auth.clone(),
        BrowserConfig::new("https://app.example", false).unwrap(),
    );
    let response = normal
        .oneshot(post(
            &format!("{ROOT}/start"),
            "{}",
            None,
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let base = serde_json::to_value(easy_auth_axum::openapi()).unwrap();
    let opt = serde_json::to_value(easy_auth_axum::oidc_account_deletion_openapi()).unwrap();
    assert!(base["paths"].get(format!("{ROOT}/start")).is_none());
    for action in ["start", "finish", "cancel"] {
        assert!(
            opt["paths"][format!("{ROOT}/{action}")]
                .get("post")
                .is_some()
        );
    }
}
