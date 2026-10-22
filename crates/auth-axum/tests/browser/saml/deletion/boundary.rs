use super::super::setup::ORIGIN;
use super::setup::Fixture;
use crate::support::{cookie, post};
use auth_core::Secret;
use axum::{
    body::Body,
    http::{Request, header},
};
use sqlx::PgPool;
use tower::ServiceExt;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn start_requires_exact_confirmation_current_session_origin_and_closed_input_without_authority(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    for body in [
        "{}",
        "{\"confirmation\":\"DELETE MY ACCOUNT\"}",
        "{\"confirmation\":\"delete my account\",\"realm\":\"other\"}",
        "{\"confirmation\":\"delete my account\",\"confirmation\":\"delete my account\"}",
    ] {
        assert_eq!(
            f.base
                .app
                .clone()
                .oneshot(post(
                    "/v1/saml/account-delete/start",
                    body,
                    Some(&f.current),
                    Some(ORIGIN)
                ))
                .await
                .unwrap()
                .status(),
            400
        );
        assert_eq!(f.base.facts().await, (1, 1, 1, 2, 0));
    }
    for (current, origin, status) in [
        (None, Some(ORIGIN), 401),
        (Some(f.current.as_str()), None, 403),
        (Some(f.current.as_str()), Some("https://other.example"), 403),
    ] {
        assert_eq!(
            f.base
                .app
                .clone()
                .oneshot(post(
                    "/v1/saml/account-delete/start",
                    "{\"confirmation\":\"delete my account\"}",
                    current,
                    origin
                ))
                .await
                .unwrap()
                .status(),
            status
        );
    }
    let attempt = f.start("ordinary-subject").await;
    for path in [
        "/v1/saml/account-delete/start",
        "/v1/saml/account-delete/start?realm=other",
    ] {
        let status = if path.contains('?') { 400 } else { 401 };
        assert_eq!(
            f.base
                .app
                .clone()
                .oneshot(post(
                    path,
                    "{\"confirmation\":\"delete my account\"}",
                    Some(&attempt.cookie),
                    Some(ORIGIN)
                ))
                .await
                .unwrap()
                .status(),
            status
        );
    }
    assert_eq!(f.base.facts().await, (1, 1, 1, 2, 1));
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn operation_selection_rejects_missing_wrong_and_ambiguous_cookies_without_consumption(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let attempt = f.start("ordinary-subject").await;
    assert_eq!(f.select(&attempt, None).await.status(), 401);
    let wrong = Secret::generate().unwrap();
    let response = f
        .base
        .app
        .clone()
        .oneshot(post(
            "/v1/saml/operation",
            &serde_json::json!({"RelayState":wrong.expose()}).to_string(),
            Some(&attempt.cookie),
            Some(ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    // Cookie-only ambiguity control; no XML/signature/proof is changed or used.
    let aliases = attempt
        .cookie
        .split(';')
        .map(str::trim)
        .filter(|v| v.starts_with("__Host-auth-saml-delete-"))
        .map(|v| v.replace("__Host-auth-saml-delete-", "__Host-auth-saml-"))
        .collect::<Vec<_>>()
        .join("; ");
    let ambiguous = format!("{}; {aliases}", attempt.cookie);
    assert_eq!(f.select(&attempt, Some(&ambiguous)).await.status(), 401);
    assert_eq!(f.base.facts().await, (1, 1, 1, 2, 1));
    assert_eq!(
        f.finish(&attempt, "delete my account", Some(&attempt.cookie))
            .await
            .status(),
        204
    );
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn another_genuine_session_cannot_consume_original_deletion_and_stale_relay_cannot_clear_new_proofs(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let other = f.base.start().await;
    let login = f
        .base
        .deliver(
            "/v1/saml/sign-in/finish",
            &other,
            Some(&other.cookie),
            Some(ORIGIN),
        )
        .await;
    assert_eq!(login.status(), 204);
    let second = cookie(&login, "__Host-auth-session=");
    let attempt = f.start("ordinary-subject").await;
    let proof_cookies = attempt
        .cookie
        .split(';')
        .map(str::trim)
        .filter(|v| !v.starts_with("__Host-auth-session="))
        .collect::<Vec<_>>()
        .join("; ");
    let replaced = format!("{second}; {proof_cookies}");
    assert_eq!(
        f.finish(&attempt, "delete my account", Some(&replaced))
            .await
            .status(),
        401
    );
    assert_eq!(f.base.facts().await, (1, 1, 2, 4, 1));
    let wrong = Secret::generate().unwrap();
    let form = url::form_urlencoded::parse(attempt.form.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .map(|(name, value)| {
            if name == "RelayState" {
                (name, wrong.expose().to_owned())
            } else {
                (name, value)
            }
        })
        .collect::<Vec<_>>();
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form)
        .append_pair("confirmation", "delete my account")
        .finish();
    let response = f
        .base
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/saml/account-delete/finish")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, ORIGIN)
                .header(header::COOKIE, &attempt.cookie)
                .body(Body::from(encoded))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(f.base.facts().await, (1, 1, 2, 4, 1));
    assert_eq!(
        f.finish(&attempt, "delete my account", Some(&attempt.cookie))
            .await
            .status(),
        204
    );
    assert_eq!(f.base.facts().await, (0, 0, 0, 6, 0));
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn finish_transport_rejects_unconfirmed_duplicate_or_selected_source_input_before_consumption(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let attempt = f.start("ordinary-subject").await;
    for extra in [
        "",
        "&confirmation=wrong",
        "&confirmation=delete+my+account&realm=other",
        "&confirmation=delete+my+account&confirmation=delete+my+account",
        "&confirmation=delete+my+account&RelayState=duplicate",
    ] {
        let body = format!("{}{extra}", attempt.form);
        let response = f
            .base
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/saml/account-delete/finish")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::ORIGIN, ORIGIN)
                    .header(header::COOKIE, &attempt.cookie)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        assert_eq!(f.base.facts().await, (1, 1, 1, 2, 1));
    }
    let r = f.base.policy.registration();
    f.base
        .store
        .disable_saml_registration(r.realm(), r.connection(), r.client())
        .await
        .unwrap();
    assert_eq!(
        f.finish(&attempt, "delete my account", Some(&attempt.cookie))
            .await
            .status(),
        401
    );
    assert_eq!(f.base.facts().await, (1, 1, 1, 2, 0));
}
