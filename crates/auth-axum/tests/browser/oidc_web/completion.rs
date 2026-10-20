use super::setup::*;
use auth_core::Error;
use axum::{
    body::Body,
    http::{Request, header},
};
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test]
async fn public_signin_commits_real_identity_session_and_supports_logout(pool: PgPool) {
    let f = Fixture::new(pool).await;
    assert_eq!(f.facts().await, (0, 0, 0, 0));
    let a = f.start().await;
    assert_eq!(f.facts().await, (0, 0, 0, 1));
    let r = f.post("finish", a.callback.clone(), &a.cookie).await;
    assert_eq!(r.status(), 204);
    cleared(&r);
    let cookie = session(&r);
    let secret = auth_core::Secret::parse(cookie.split_once('=').unwrap().1.to_owned()).unwrap();
    let user = f.auth.authenticate(&secret).await.unwrap();
    assert_eq!(user.realm_id, f.policy.configuration().realm());
    assert_eq!(user.email, None);
    assert_eq!(f.facts().await, (1, 1, 1, 0));
    let r = f
        .send(
            Request::builder()
                .uri("/v1/session")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.status(), 200);
    assert_eq!(body(r).await["id"], user.id.to_string());
    assert_eq!(f.post("finish", a.callback, &a.cookie).await.status(), 401);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 1);
    let r = f
        .send(crate::support::post(
            "/v1/logout",
            "{}",
            Some(&cookie),
            Some(ORIGIN),
        ))
        .await;
    assert_eq!(r.status(), 204);
    assert_eq!(r.headers().get_all(header::SET_COOKIE).iter().count(), 9);
    assert!(matches!(
        f.auth.authenticate(&secret).await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test]
async fn cancellation_does_not_replace_or_revoke_a_session_arriving_later(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    let pending = a.cookie.clone();
    let r = f.post("finish", a.callback.clone(), &a.cookie).await;
    assert_eq!(r.status(), 204);
    let cookie = session(&r);
    let another = f.start().await;
    let r = f
        .post(
            "cancel",
            json!({}),
            &format!("{}; {}", another.cookie, cookie),
        )
        .await;
    assert_eq!(r.status(), 204);
    no_session(&r);
    cleared(&r);
    let secret = auth_core::Secret::parse(cookie.split_once('=').unwrap().1.to_owned()).unwrap();
    assert!(f.auth.authenticate(&secret).await.is_ok());
    assert_eq!(f.facts().await, (1, 1, 1, 0));
    assert_eq!(
        f.post("finish", another.callback, &another.cookie)
            .await
            .status(),
        401
    );
    assert_eq!(f.post("cancel", json!({}), &pending).await.status(), 401);
}

#[sqlx::test]
async fn common_callback_can_reauthenticate_and_delete_the_publicly_signed_in_owner(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    let r = f.post("finish", a.callback, &a.cookie).await;
    assert_eq!(r.status(), 204);
    let current = session(&r);
    let r = f
        .send(crate::support::post(
            "/v1/account/provider-delete/start",
            r#"{"confirmation":"delete my account"}"#,
            Some(&current),
            Some(ORIGIN),
        ))
        .await;
    assert_eq!(r.status(), 200);
    let proof = format!("{}; {}", current, cookies(&r));
    let url = url::Url::parse(body(r).await["authorization_url"].as_str().unwrap()).unwrap();
    let params: std::collections::HashMap<String, String> =
        url.query_pairs().into_owned().collect();
    assert_eq!(params["redirect_uri"], CALLBACK);
    assert_eq!(params["prompt"], "login");
    assert_eq!(params["max_age"], "0");
    let a = Attempt {
        cookie: proof,
        callback: json!({"confirmation":"delete my account","state":params["state"],"code":"delete-code","issuer":"https://issuer.example"}),
        params,
    };
    f.prepare(&a, "owned", None).await;
    let r = f
        .send(crate::support::post(
            "/v1/account/provider-delete/finish",
            &a.callback.to_string(),
            Some(&a.cookie),
            Some(ORIGIN),
        ))
        .await;
    assert_eq!(r.status(), 204);
    assert_eq!(f.facts().await, (0, 0, 0, 0));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 2);
}

#[sqlx::test]
async fn trusted_name_mapping_requests_profile_without_contact_authority(pool: PgPool) {
    let f = Fixture::with_mapping(
        pool,
        auth_core::OidcJitPolicy::Allow,
        auth_core::OidcDisplayNameClaim::Name,
    )
    .await;
    let a = f.start().await;
    assert_eq!(a.params["scope"], "openid profile");
    assert!(!a.params.contains_key("email"));
    f.prepare(&a, "owned", Some(("name", json!("Provider display"))))
        .await;
    let r = f.post("finish", a.callback, &a.cookie).await;
    assert_eq!(r.status(), 204);
    let secret =
        auth_core::Secret::parse(session(&r).split_once('=').unwrap().1.to_owned()).unwrap();
    let user = f.auth.authenticate(&secret).await.unwrap();
    assert_eq!(user.display_name.as_deref(), Some("Provider display"));
    assert_eq!(user.email, None);
}
