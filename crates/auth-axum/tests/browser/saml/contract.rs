use super::setup::{Fixture, ORIGIN};
use crate::support::post;
use axum::{
    body::Body,
    http::{Request, header},
};
use sqlx::PgPool;
use tower::ServiceExt;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn closed_transport_fields_metadata_and_default_router_keep_source_selection_trusted(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let attempt = f.start().await;
    let again = f
        .app
        .clone()
        .oneshot(post(
            "/v1/saml/sign-in/start",
            "{}",
            Some(&attempt.cookie),
            Some(ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(again.status(), 401);
    for body in ["{}", "{\"realm\":\"other\"}"] {
        let response = f
            .app
            .clone()
            .oneshot(post("/saml/acs", body, None, None))
            .await
            .unwrap();
        assert_eq!(response.status(), 415);
    }
    assert_eq!(
        f.deliver("/saml/acs?source=other", &attempt, None, None)
            .await
            .status(),
        400
    );
    for extra in [
        "&SAMLResponse=duplicate",
        "&RelayState=duplicate",
        "&realm=other",
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/saml/acs")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("{}{extra}", attempt.form)))
            .unwrap();
        assert_eq!(f.app.clone().oneshot(request).await.unwrap().status(), 400);
    }
    let metadata = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/saml/metadata")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metadata.status(), 200);
    assert_eq!(
        metadata.headers()[header::CONTENT_TYPE],
        "application/samlmetadata+xml"
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    let base = crate::support::app(f.pool.clone()).await.0;
    assert_eq!(
        base.oneshot(
            Request::builder()
                .uri("/saml/metadata")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        404
    );
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn configuration_and_contract_keep_https_realm_and_exact_acs_fixed(pool: PgPool) {
    use auth_core::Auth;
    use easy_auth_axum::{BrowserConfig, SamlWebServices, experimental_saml_web_router};
    use std::sync::Arc;
    let f = Fixture::new(pool).await;
    for (realm, origin) in [
        (uuid::Uuid::new_v4(), ORIGIN),
        (f.policy.registration().realm(), "http://localhost"),
    ] {
        let services = SamlWebServices::new(
            f.policy.clone(),
            f.store.clone(),
            f.store.clone(),
            f.store.clone(),
        )
        .unwrap();
        let auth = Auth::new(
            realm,
            f.store.clone(),
            Arc::new(crate::support::Mail::default()),
        );
        assert!(
            experimental_saml_web_router(auth, BrowserConfig::new(origin, true).unwrap(), services)
                .is_err()
        );
    }
    let r = f.policy.registration();
    let wrong_acs = auth_core::SamlRegistration::unsigned_redirect(
        r.realm(),
        r.connection(),
        r.client(),
        r.sp_entity(),
        r.idp_entity(),
        r.sso(),
        "https://app.example/another-acs",
    )
    .unwrap();
    let services = SamlWebServices::new(
        auth_core::SamlIdentityPolicy::new(wrong_acs),
        f.store.clone(),
        f.store.clone(),
        f.store.clone(),
    )
    .unwrap();
    let auth = Auth::new(
        r.realm(),
        f.store.clone(),
        Arc::new(crate::support::Mail::default()),
    );
    assert!(
        experimental_saml_web_router(auth, BrowserConfig::new(ORIGIN, false).unwrap(), services)
            .is_err()
    );
    let api = serde_json::to_value(easy_auth_axum::saml_web_openapi()).unwrap();
    let documented: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/architecture/openapi-saml-web.json"
    )))
    .unwrap();
    assert_eq!(api, documented);
    let published = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    use http_body_util::BodyExt;
    let published: serde_json::Value =
        serde_json::from_slice(&published.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(api, published);
    assert!(api["paths"]["/saml/acs"]["post"].is_object());
    let fields = api["components"]["schemas"]["SamlPostDelivery"]["properties"]
        .as_object()
        .unwrap();
    assert_eq!(fields.len(), 2);
    assert!(fields.contains_key("SAMLResponse") && fields.contains_key("RelayState"));
    let base = serde_json::to_value(easy_auth_axum::openapi()).unwrap();
    assert!(
        base["paths"]
            .as_object()
            .unwrap()
            .keys()
            .all(|path| !path.contains("saml"))
    );
}
