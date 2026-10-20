use super::super::*;
use auth_axum::BrowserConfig;
use auth_core::{OAuthMixupDefense, OidcClientAuthentication, OidcDisplayNameClaim, OidcJitPolicy};
use uuid::Uuid;

fn environment() -> BTreeMap<String, String> {
    [
        ("AUTH_OIDC_ENABLED", "true".to_owned()),
        ("AUTH_OIDC_CONNECTION_ID", Uuid::new_v4().to_string()),
        ("AUTH_OIDC_LOCAL_CLIENT_ID", Uuid::new_v4().to_string()),
        (
            "AUTH_OIDC_ISSUER",
            "https://issuer.example/tenant".to_owned(),
        ),
        (
            "AUTH_OIDC_PROVIDER_CLIENT_ID",
            "registered-client".to_owned(),
        ),
        (
            "AUTH_OIDC_ALLOWED_ORIGINS",
            "https://issuer.example".to_owned(),
        ),
        ("AUTH_OIDC_CLIENT_AUTH_METHOD", "none".to_owned()),
        ("AUTH_OIDC_SIGNING_ALGORITHMS", "RS256".to_owned()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect()
}
fn prepared(values: BTreeMap<String, String>) -> StartupResult<settings::Prepared> {
    let Configuration::Enabled(settings) =
        parse(values.into_iter().map(|(k, v)| (k.into(), v.into())))?
    else {
        panic!("test infrastructure: expected activated settings");
    };
    settings.prepare(
        Uuid::new_v4(),
        &BrowserConfig::new("https://app.example", false).unwrap(),
    )
}
#[test]
fn explicit_public_client_defaults_to_denied_jit_and_issuer_defense() {
    let config = prepared(environment()).unwrap();
    assert_eq!(config.policy.jit(), OidcJitPolicy::Deny);
    assert_eq!(
        config.policy.display_name_claim(),
        OidcDisplayNameClaim::Subject
    );
    assert_eq!(
        config.policy.configuration().defense(),
        OAuthMixupDefense::RequireIssuer
    );
    assert_eq!(
        config.policy.configuration().redirect(),
        "https://app.example/oidc/callback"
    );
    assert_eq!(
        config.policy.allowed_issuers(),
        ["https://issuer.example/tenant"]
    );
    assert!(matches!(
        config.authentication,
        OidcClientAuthentication::Public
    ));
}
#[test]
fn each_required_setting_is_required_without_inferred_fallback() {
    for key in environment()
        .keys()
        .filter(|key| key.as_str() != "AUTH_OIDC_ENABLED")
    {
        let mut values = environment();
        values.remove(key);
        assert!(
            prepared(values).is_err(),
            "missing required field must fail startup"
        );
    }
}
#[test]
fn trusted_jit_display_and_dedicated_callback_choices_remain_explicit() {
    let mut values = environment();
    values.insert("AUTH_OIDC_JIT".into(), "allow".into());
    values.insert("AUTH_OIDC_DISPLAY_CLAIM".into(), "name".into());
    values.insert(
        "AUTH_OIDC_MIXUP_DEFENSE".into(),
        "dedicated_redirect".into(),
    );
    values.insert(
        "AUTH_OIDC_SIGNING_ALGORITHMS".into(),
        "RS256,PS256,ES256".into(),
    );
    let config = prepared(values).unwrap();
    assert_eq!(config.policy.jit(), OidcJitPolicy::Allow);
    assert_eq!(
        config.policy.display_name_claim(),
        OidcDisplayNameClaim::Name
    );
    assert_eq!(
        config.policy.configuration().defense(),
        OAuthMixupDefense::DedicatedRedirect
    );
}
#[test]
fn malformed_policy_algorithm_and_identity_values_fail_without_echo() {
    for (key, value) in [
        ("AUTH_OIDC_CONNECTION_ID", "private-invalid-id-marker"),
        (
            "AUTH_OIDC_LOCAL_CLIENT_ID",
            "00000000-0000-0000-0000-000000000000",
        ),
        ("AUTH_OIDC_JIT", "yes"),
        ("AUTH_OIDC_DISPLAY_CLAIM", "email"),
        ("AUTH_OIDC_MIXUP_DEFENSE", "automatic"),
        ("AUTH_OIDC_SIGNING_ALGORITHMS", "HS256"),
        ("AUTH_OIDC_SIGNING_ALGORITHMS", "none"),
        ("AUTH_OIDC_SIGNING_ALGORITHMS", "RS256,RS256"),
        ("AUTH_OIDC_CLIENT_AUTH_METHOD", "automatic"),
        ("AUTH_OIDC_CLIENT_AUTH_METHOD", "client_secret_basic"),
        ("AUTH_OIDC_ISSUER", "http://issuer.example"),
        ("AUTH_OIDC_PROVIDER_CLIENT_ID", " trailing "),
        ("AUTH_OIDC_ALLOWED_ORIGINS", "https://different.example"),
        ("AUTH_OIDC_ALLOWED_ORIGINS", "https://issuer.example/path"),
        (
            "AUTH_OIDC_ALLOWED_ORIGINS",
            "https://issuer.example,https://issuer.example",
        ),
    ] {
        let mut values = environment();
        values.insert(key.into(), value.into());
        let error = prepared(values)
            .err()
            .expect("invalid configuration must fail");
        assert!(!error.to_string().contains("private-invalid-id-marker"));
    }
}
#[test]
fn browser_https_and_public_egress_policy_have_no_development_override() {
    let Configuration::Enabled(settings) =
        parse(environment().into_iter().map(|(k, v)| (k.into(), v.into()))).unwrap()
    else {
        unreachable!()
    };
    assert!(
        settings
            .prepare(
                Uuid::new_v4(),
                &BrowserConfig::new("http://localhost", true).unwrap()
            )
            .is_err()
    );
    for issuer in [
        "https://127.0.0.1",
        "https://169.254.169.254",
        "https://[::1]",
    ] {
        let mut values = environment();
        values.insert("AUTH_OIDC_ISSUER".into(), issuer.into());
        values.insert("AUTH_OIDC_ALLOWED_ORIGINS".into(), issuer.into());
        assert!(prepared(values).is_err());
    }
}
#[test]
fn root_address_redirect_and_raw_secret_overrides_are_unknown_even_when_disabled() {
    for key in [
        "AUTH_OIDC_TLS_ROOT_FILE",
        "AUTH_OIDC_ADDRESS_OVERRIDE",
        "AUTH_OIDC_INSECURE",
        "AUTH_OIDC_REDIRECT_URI",
        "AUTH_OIDC_CLIENT_SECRET",
    ] {
        let values = [
            ("AUTH_OIDC_ENABLED".into(), "false".into()),
            (key.into(), "private-config-marker".into()),
        ];
        let error = parse(values).err().unwrap();
        assert_eq!(error.to_string(), "unknown AUTH_OIDC setting");
    }
}
