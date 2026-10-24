//! Selected providers retain their own checks around the shared issuer router.
use super::*;
use uuid::Uuid;

#[cfg(feature = "oidc-web")]
async fn oidc(f: &Fixture, realm: Uuid) -> easy_auth_axum::OidcWebServices {
    use crate::support::oidc_provider::Provider;
    let connection = OAuthConnection::new(
        realm,
        Uuid::new_v4(),
        Uuid::new_v4(),
        "https://issuer.example",
        "client",
        "https://app.example/oidc/callback",
        OAuthMixupDefense::RequireIssuer,
    )
    .unwrap();
    let policy = OidcIdentityPolicy::new(
        connection,
        &["https://issuer.example"],
        OidcDisplayNameClaim::Subject,
    )
    .unwrap();
    let policy = f
        .base
        .store
        .load_or_initialize_oidc_identity_policy(&policy)
        .await
        .unwrap();
    let provider = Arc::new(Provider::new("https://app.example/oidc/callback"));
    let documents = Arc::new(
        OidcDocuments::new(
            policy.configuration().clone(),
            &["https://issuer.example"],
            f.base.store.clone(),
            provider.clone(),
        )
        .unwrap(),
    );
    easy_auth_axum::OidcWebServices::new(
        policy.clone(),
        Arc::new(OAuthTransactions::new(
            policy.configuration().clone(),
            f.base.store.clone(),
        )),
        Arc::new(OidcCodeExchange::new(
            documents,
            f.base.store.clone(),
            OidcVerificationPolicy::new(&[OidcSigningAlgorithm::ES256], &[]).unwrap(),
            OidcClientAuthentication::Public,
            provider,
        )),
        Arc::new(OidcSignIn::new(f.base.store.clone())),
        Arc::new(OidcAccountDeletion::new(f.base.store.clone())),
    )
    .unwrap()
}
#[cfg(feature = "saml-web")]
async fn saml(f: &Fixture, realm: Uuid) -> easy_auth_axum::SamlWebServices {
    let registration = SamlRegistration::unsigned_redirect(
        realm,
        Uuid::new_v4(),
        Uuid::new_v4(),
        "urn:example:sp",
        "urn:example:idp",
        "https://idp.example/sso",
        "https://app.example/saml/acs",
    )
    .unwrap();
    let policy = f
        .base
        .store
        .configure_saml_identity_policy(
            &SamlIdentityPolicy::new(registration),
            &crate::support::saml_provider::trust(),
        )
        .await
        .unwrap();
    easy_auth_axum::SamlWebServices::new(
        policy,
        f.base.store.clone(),
        f.base.store.clone(),
        f.base.store.clone(),
    )
    .unwrap()
}
fn services(f: &Fixture) -> IssuerNativeWebServices {
    let base = IssuerWebServices::new(
        f.policy.authority().clone(),
        f.base.store.clone(),
        f.base.store.clone(),
        vec![f.base.key.clone()],
    )
    .unwrap();
    IssuerNativeWebServices::new(
        base,
        f.base.store.clone(),
        f.base.store.clone(),
        f.base.store.clone(),
    )
}
fn router(f: &Fixture, services: IssuerNativeWebServices) -> Result<axum::Router> {
    experimental_issuer_native_web_router(
        Auth::new(f.base.realm, f.base.store.clone(), f.mail.clone()),
        BrowserConfig::new(ORIGIN, false).unwrap(),
        services,
    )
}
#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn selected_provider_routes_and_contracts_preserve_native_issuer_profile(pool: PgPool) {
    let f = fixture(pool).await;
    let selected = services(&f);
    #[cfg(feature = "oidc-web")]
    let selected = selected.with_oidc_provider(oidc(&f, f.base.realm).await);
    #[cfg(feature = "saml-web")]
    let selected = selected.with_saml_provider(saml(&f, f.base.realm).await);
    let app = router(&f, selected).unwrap();
    let api = read(app.clone().oneshot(get("/openapi.json")).await.unwrap()).await;
    assert!(api["paths"].get("/oidc/token").is_some());
    assert!(
        api["paths"]
            .get("/v1/oidc/native/consent/approve")
            .is_some()
    );
    #[cfg(feature = "oidc-web")]
    {
        assert!(api["paths"].get("/v1/oidc/sign-in/start").is_some());
        assert_eq!(
            app.clone()
                .oneshot(get("/oidc/sign-in"))
                .await
                .unwrap()
                .status(),
            200
        );
    }
    #[cfg(feature = "saml-web")]
    {
        assert!(api["paths"].get("/saml/acs").is_some());
        assert_eq!(
            app.clone()
                .oneshot(get("/saml/sign-in"))
                .await
                .unwrap()
                .status(),
            200
        );
    }
    let metadata = read(
        app.oneshot(get("/.well-known/openid-configuration"))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        metadata["grant_types_supported"],
        json!(["authorization_code", "refresh_token"])
    );
}
#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn provider_attachment_rejects_another_realm_before_serving_any_route(pool: PgPool) {
    let f = fixture(pool).await;
    let other = Uuid::new_v4();
    f.base.store.ensure_realm(other).await.unwrap();
    #[cfg(feature = "oidc-web")]
    assert!(router(&f, services(&f).with_oidc_provider(oidc(&f, other).await)).is_err());
    #[cfg(feature = "saml-web")]
    assert!(router(&f, services(&f).with_saml_provider(saml(&f, other).await)).is_err());
}
