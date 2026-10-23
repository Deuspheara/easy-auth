use super::*;
fn values(items: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    items
        .iter()
        .map(|(k, v)| ((*k).into(), (*v).into()))
        .collect()
}
#[test]
fn absent_or_explicitly_disabled_settings_are_inactive() {
    assert!(matches!(
        parse(Vec::new()).unwrap(),
        Configuration::Disabled
    ));
    assert!(matches!(
        parse(values(&[("AUTH_SAML_ENABLED", "false")])).unwrap(),
        Configuration::Disabled
    ));
}
#[test]
fn partial_unknown_duplicate_and_populated_disabled_settings_reject() {
    for items in [
        vec![("AUTH_SAML_JIT", "allow")],
        vec![("AUTH_SAML_ENABLED", "TRUE")],
        vec![("AUTH_SAML_ENABLED", "false"), ("AUTH_SAML_JIT", "deny")],
        vec![
            ("AUTH_SAML_ENABLED", "false"),
            ("AUTH_SAML_ENABLED", "false"),
        ],
        vec![("AUTH_SAML_SECURITY_APPROVED", "true")],
    ] {
        assert!(parse(values(&items)).is_err());
    }
    assert!(
        parse([(
            OsString::from("AUTH_SAML_IDP_ENTITY"),
            OsString::from("x".repeat(8193))
        )])
        .is_err()
    );
}
#[cfg(not(feature = "saml-web"))]
#[test]
fn compiled_support_is_required() {
    let error = parse(values(&[("AUTH_SAML_ENABLED", "true")]))
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("requires the saml-web server feature")
    );
}
#[cfg(feature = "saml-web")]
fn complete() -> Vec<(OsString, OsString)> {
    values(&[
        ("AUTH_SAML_ENABLED", "true"),
        (
            "AUTH_SAML_CONNECTION_ID",
            "00000000-0000-0000-0000-000000000001",
        ),
        (
            "AUTH_SAML_LOCAL_CLIENT_ID",
            "00000000-0000-0000-0000-000000000002",
        ),
        ("AUTH_SAML_SP_ENTITY", "urn:easy-auth:sp"),
        ("AUTH_SAML_IDP_ENTITY", "https://idp.example/entity"),
        ("AUTH_SAML_SSO_URL", "https://idp.example/sso"),
    ])
}
#[cfg(feature = "saml-web")]
#[test]
fn complete_configuration_preserves_default_deny_and_trusted_registration() {
    let configuration = parse(complete()).unwrap();
    assert_eq!(
        configuration.require_disabled().unwrap_err().to_string(),
        "SAML browser settings require configured_application"
    );
    let prepared = configuration
        .prepare(
            uuid::Uuid::new_v4(),
            &auth_axum::BrowserConfig::new("https://app.example", false).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(prepared.policy.jit(), auth_core::SamlJitPolicy::Deny);
    assert_eq!(
        prepared.policy.registration().acs(),
        "https://app.example/saml/acs"
    );
}
#[cfg(feature = "saml-web")]
#[test]
fn invalid_trusted_endpoints_ids_and_policy_reject_before_composition() {
    for (key, value) in [
        ("AUTH_SAML_JIT", "email"),
        ("AUTH_SAML_CONNECTION_ID", "invalid"),
        (
            "AUTH_SAML_LOCAL_CLIENT_ID",
            "00000000-0000-0000-0000-000000000000",
        ),
        ("AUTH_SAML_SP_ENTITY", ""),
        ("AUTH_SAML_SSO_URL", "http://idp.example/sso"),
    ] {
        let mut items = complete();
        items.retain(|(k, _)| k != key);
        items.push((key.into(), value.into()));
        let result = parse(items).and_then(|c| {
            c.prepare(
                uuid::Uuid::new_v4(),
                &auth_axum::BrowserConfig::new("https://app.example", false).unwrap(),
            )
        });
        assert!(
            result.is_err(),
            "invalid trusted setting must reject: {key}"
        );
    }
    assert!(
        parse(complete())
            .unwrap()
            .prepare(
                uuid::Uuid::new_v4(),
                &auth_axum::BrowserConfig::new("http://127.0.0.1", true).unwrap()
            )
            .is_err()
    );
}
#[cfg(unix)]
#[test]
fn non_unicode_settings_reject_without_echoing_input() {
    use std::os::unix::ffi::OsStringExt;
    assert!(parse([("AUTH_SAML_ENABLED".into(), OsString::from_vec(vec![255]))]).is_err());
}
