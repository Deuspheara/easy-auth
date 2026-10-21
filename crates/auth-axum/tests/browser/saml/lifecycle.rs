use super::setup::{Fixture, ORIGIN};
use crate::support::{cookie, post};
use axum::{
    body::Body,
    http::{Request, header},
};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn cross_site_delivery_grants_nothing_until_same_origin_real_verified_commit_and_logout(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let attempt = f.start().await;
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    let delivery = f
        .deliver("/saml/acs", &attempt, None, Some("https://idp.example"))
        .await;
    assert_eq!(delivery.status(), 200);
    assert!(delivery.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(delivery.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(delivery.headers()["referrer-policy"], "no-referrer");
    assert!(
        delivery.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    let page = delivery.into_body().collect().await.unwrap().to_bytes();
    let page = std::str::from_utf8(&page).unwrap();
    assert!(page.contains("/saml/delivery.js") && !page.contains("<script>"));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    let result = f
        .deliver(
            "/v1/saml/sign-in/finish",
            &attempt,
            Some(&attempt.cookie),
            Some(ORIGIN),
        )
        .await;
    assert_eq!(result.status(), 204);
    let session = cookie(&result, "__Host-auth-session=");
    assert_eq!(f.facts().await, (1, 1, 1, 2, 0));
    let session_response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/session")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session_response.status(), 200);
    let user: serde_json::Value = serde_json::from_slice(
        &session_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert!(user["email"].is_null());
    assert_eq!(user["display_name"], "ordinary-subject");
    let repeated = f
        .deliver(
            "/v1/saml/sign-in/finish",
            &attempt,
            Some(&attempt.cookie),
            Some(ORIGIN),
        )
        .await;
    assert_eq!(repeated.status(), 401);
    let logout = f
        .app
        .clone()
        .oneshot(post("/v1/logout", "{}", Some(&session), Some(ORIGIN)))
        .await
        .unwrap();
    assert_eq!(logout.status(), 204);
    assert_eq!(
        logout.headers().get_all(header::SET_COOKIE).iter().count(),
        4
    );
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn cancellation_is_bound_and_source_disable_rejects_actual_signed_http_completion(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    let result = f
        .app
        .clone()
        .oneshot(post(
            "/v1/saml/sign-in/cancel",
            "{}",
            Some(&a.cookie),
            Some(ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(result.status(), 204);
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    assert_eq!(
        f.deliver("/v1/saml/sign-in/finish", &a, Some(&a.cookie), Some(ORIGIN))
            .await
            .status(),
        401
    );
    let b = f.start().await;
    let reg = f.policy.registration();
    f.store
        .disable_saml_registration(reg.realm(), reg.connection(), reg.client())
        .await
        .unwrap();
    assert_eq!(
        f.deliver("/v1/saml/sign-in/finish", &b, Some(&b.cookie), Some(ORIGIN))
            .await
            .status(),
        401
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
}
