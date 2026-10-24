use crate::*;
use uuid::Uuid;

#[test]
fn web_configuration_rejects_ambiguous_callbacks_and_insecure_issuers() {
    for redirect in [
        "http://rp.example/callback",
        "https://rp.example/",
        "https://someone@rp.example/callback",
        "https://rp.example/callback#fragment",
        "https://rp.example/callback?state=fixed",
        "https://rp.example/callback?%69ss=fixed",
        "https://rp.example/callback?x=one&%78=two",
        "https://rp.example/callback?x=%ZZ",
        "https://rp.example/callback?x=%FF",
    ] {
        assert!(
            matches!(
                OidcClientConfiguration::web(
                    "https://issuer.example",
                    Uuid::new_v4(),
                    redirect,
                    OidcClientAuthentication::Public
                ),
                Err(OidcClientError::Configuration)
            ),
            "{redirect}"
        );
    }
    for issuer in [
        "http://issuer.example",
        "https://127.0.0.1",
        "https://issuer.example?tenant=one",
        "https://issuer.example#fragment",
    ] {
        assert!(
            matches!(
                OidcClientConfiguration::web(
                    issuer,
                    Uuid::new_v4(),
                    "https://rp.example/callback",
                    OidcClientAuthentication::Public
                ),
                Err(OidcClientError::Configuration)
            ),
            "{issuer}"
        );
    }
}

#[test]
fn native_configuration_uses_exact_literal_loopback_listener_policy() {
    for listener in ["127.0.0.1:49152", "[::1]:49152", "127.0.0.1:80"] {
        let config = OidcClientConfiguration::native(
            "https://issuer.example",
            Uuid::new_v4(),
            listener.parse().unwrap(),
            "/callback",
            true,
        )
        .unwrap();
        assert_eq!(config.redirect_uri(), format!("http://{listener}/callback"));
    }
    for listener in ["127.0.0.1:0", "0.0.0.0:49152", "8.8.8.8:49152"] {
        assert!(matches!(
            OidcClientConfiguration::native(
                "https://issuer.example",
                Uuid::new_v4(),
                listener.parse().unwrap(),
                "/callback",
                true
            ),
            Err(OidcClientError::Configuration)
        ));
    }
}

#[test]
fn explicit_authentication_never_selects_secret_post_fallback() {
    assert!(matches!(
        OidcClientConfiguration::web(
            "https://issuer.example",
            Uuid::new_v4(),
            "https://rp.example/callback",
            OidcClientAuthentication::ClientSecretPost(
                OidcClientSecret::parse("owned-test-secret".into()).unwrap()
            )
        ),
        Err(OidcClientError::Configuration)
    ));
}
