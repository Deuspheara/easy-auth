use super::*;
fn values(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).into(), (*v).into()))
        .collect()
}
fn error(pairs: &[(&str, &str)]) -> String {
    parse(values(pairs))
        .err()
        .expect("configuration must fail")
        .to_string()
}
#[test]
fn absent_and_explicit_false_are_disabled() {
    assert!(!parse(values(&[])).unwrap().enabled());
    assert!(
        !parse(values(&[("AUTH_ISSUER_ENABLED", "false")]))
            .unwrap()
            .enabled()
    );
}
#[test]
fn partial_unknown_duplicate_and_inert_settings_fail_without_echoing_values() {
    assert_eq!(
        error(&[("AUTH_ISSUER_KEY_FILE", "private-marker")]),
        "issuer requires AUTH_ISSUER_ENABLED=true and a complete configuration"
    );
    assert_eq!(
        error(&[
            ("AUTH_ISSUER_ENABLED", "false"),
            ("AUTH_ISSUER_KEY_FILE", "private-marker")
        ]),
        "issuer requires AUTH_ISSUER_ENABLED=true and a complete configuration"
    );
    assert_eq!(
        error(&[("AUTH_ISSUER_UNKNOWN", "private-marker")]),
        "unknown AUTH_ISSUER setting"
    );
    assert_eq!(
        error(&[
            ("AUTH_ISSUER_ENABLED", "false"),
            ("AUTH_ISSUER_ENABLED", "false")
        ]),
        "duplicate issuer setting"
    );
}
#[cfg(not(feature = "issuer-web"))]
#[test]
fn enabled_configuration_requires_explicit_build_feature() {
    assert_eq!(
        error(&[("AUTH_ISSUER_ENABLED", "true")]),
        "issuer configuration requires the issuer-web server feature"
    );
}
#[cfg(feature = "issuer-web")]
#[test]
fn enabled_requires_explicit_nonzero_key_and_protected_file_input() {
    assert_eq!(
        error(&[("AUTH_ISSUER_ENABLED", "true")]),
        "AUTH_ISSUER_KEY_ID is required"
    );
    assert_eq!(
        error(&[
            ("AUTH_ISSUER_ENABLED", "true"),
            ("AUTH_ISSUER_KEY_ID", "00000000-0000-0000-0000-000000000000")
        ]),
        "AUTH_ISSUER_KEY_ID must be a nonzero UUID"
    );
    assert_eq!(
        error(&[
            ("AUTH_ISSUER_ENABLED", "true"),
            ("AUTH_ISSUER_KEY_ID", "87ff58bd-8073-42ae-afdd-d5a347bf2816")
        ]),
        "AUTH_ISSUER_KEY_FILE is required"
    );
    let configuration = parse(values(&[
        ("AUTH_ISSUER_ENABLED", "true"),
        ("AUTH_ISSUER_KEY_ID", "87ff58bd-8073-42ae-afdd-d5a347bf2816"),
        ("AUTH_ISSUER_KEY_FILE", "private-marker"),
    ]))
    .unwrap();
    let browser = auth_axum::BrowserConfig::new("http://127.0.0.1:8080", true).unwrap();
    assert_eq!(
        configuration
            .prepare(uuid::Uuid::new_v4(), &browser)
            .err()
            .unwrap()
            .to_string(),
        "issuer browser composition requires HTTPS"
    );
}
