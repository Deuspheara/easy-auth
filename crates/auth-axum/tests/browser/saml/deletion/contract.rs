use super::super::setup::{Fixture, ORIGIN};
use crate::support::post;
use axum::{body::Body, http::Request};
use easy_auth_axum::{
    SamlAccountDeletionWebServices, SamlWebServices, saml_account_deletion_web_openapi,
    saml_web_openapi,
};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn deletion_is_explicit_policy_aligned_and_published_contract_matches_selected_routes(
    pool: PgPool,
) {
    let f = Fixture::new(pool.clone()).await;
    for path in [
        "/v1/saml/account-delete/start",
        "/v1/saml/account-delete/finish",
        "/v1/saml/account-delete/cancel",
    ] {
        assert_eq!(
            f.app
                .clone()
                .oneshot(post(path, "{}", None, Some(ORIGIN)))
                .await
                .unwrap()
                .status(),
            404
        );
    }
    let base = serde_json::to_value(saml_web_openapi()).unwrap();
    assert!(base["paths"]["/v1/saml/account-delete/start"].is_null());
    assert!(!base["paths"]["/v1/saml/operation"].is_null());
    let mismatch = f.policy.clone().with_jit(auth_core::SamlJitPolicy::Deny);
    let services = SamlWebServices::new(
        f.policy.clone(),
        f.store.clone(),
        f.store.clone(),
        f.store.clone(),
    )
    .unwrap();
    assert!(
        services
            .with_account_deletion(
                SamlAccountDeletionWebServices::new(
                    mismatch,
                    f.store.clone(),
                    f.store.clone(),
                    f.store.clone()
                )
                .unwrap()
            )
            .is_err()
    );
    let enabled = super::setup::Fixture::new(pool).await;
    let spec = enabled
        .base
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
    assert_eq!(spec.status(), 200);
    let actual: serde_json::Value =
        serde_json::from_slice(&spec.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let expected = serde_json::to_value(saml_account_deletion_web_openapi()).unwrap();
    assert_eq!(actual, expected);
    let published: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../docs/architecture/openapi-saml-account-deletion.json"
    ))
    .unwrap();
    assert_eq!(expected, published);
    for path in [
        "/v1/saml/account-delete/start",
        "/v1/saml/account-delete/finish",
        "/v1/saml/account-delete/cancel",
        "/saml/account-delete",
    ] {
        assert!(!expected["paths"][path].is_null());
    }
    for (schema, mut properties) in [
        ("SamlDeletionConfirmation", vec!["confirmation"]),
        (
            "SamlDeletionDelivery",
            vec!["SAMLResponse", "RelayState", "confirmation"],
        ),
    ] {
        let value = &expected["components"]["schemas"][schema];
        assert_eq!(value["additionalProperties"], false);
        let mut actual = value["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        actual.sort_unstable();
        properties.sort_unstable();
        assert_eq!(
            actual, properties,
            "closed operation input has no owner/realm/source selector"
        );
    }
}
