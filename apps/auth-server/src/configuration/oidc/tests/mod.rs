use super::*;

#[test]
fn no_settings_and_explicit_disabled_are_inactive() {
    assert!(!parse(Vec::new()).unwrap().enabled());
    assert!(
        !parse([(OsString::from("AUTH_OIDC_ENABLED"), OsString::from("false"))])
            .unwrap()
            .enabled()
    );
}
#[test]
fn partial_unknown_and_disabled_but_populated_settings_fail_closed() {
    for values in [
        vec![("AUTH_OIDC_JIT", "allow")],
        vec![
            ("AUTH_OIDC_ENABLED", "false"),
            ("AUTH_OIDC_ISSUER", "https://issuer.example"),
        ],
        vec![("AUTH_OIDC_ENABLED", "TRUE")],
        vec![
            ("AUTH_OIDC_ENABLED", "false"),
            ("AUTH_OIDC_TLS_ROOT_FILE", "private-marker"),
        ],
    ] {
        assert!(parse(values.into_iter().map(|(k, v)| (k.into(), v.into()))).is_err());
    }
}
#[cfg(not(feature = "oidc-web"))]
#[test]
fn activation_without_compiled_support_is_an_explicit_failure() {
    let result = parse([("AUTH_OIDC_ENABLED".into(), "true".into())]);
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("requires the oidc-web server feature")
    );
}

#[cfg(feature = "oidc-web")]
mod secret_file;
#[cfg(feature = "oidc-web")]
mod settings;

#[cfg(unix)]
#[test]
fn non_unicode_and_duplicate_settings_are_rejected() {
    use std::os::unix::ffi::OsStringExt;
    assert!(parse([("AUTH_OIDC_ENABLED".into(), OsString::from_vec(vec![0xff]))]).is_err());
    assert!(
        parse([
            ("AUTH_OIDC_ENABLED".into(), "false".into()),
            ("AUTH_OIDC_ENABLED".into(), "false".into())
        ])
        .is_err()
    );
}
