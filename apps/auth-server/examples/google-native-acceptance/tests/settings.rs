use crate::settings::{ClaimsProfile, Settings};
use auth_core::OidcClientAuthentication;
use std::{collections::BTreeMap, ffi::OsString, fs::OpenOptions, io::Write, path::PathBuf};

struct File {
    directory: PathBuf,
    path: String,
}
impl File {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("easy-auth-google-input-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("client-secret");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(&path)
            .unwrap()
            .write_all(b"owned-manual-input-marker\r\n")
            .unwrap();
        Self {
            directory,
            path: path.to_str().unwrap().to_owned(),
        }
    }
    fn values(&self) -> BTreeMap<String, String> {
        [
            (
                "AUTH_GOOGLE_TEST_CLIENT_ID",
                "owned-google-client.apps.googleusercontent.com",
            ),
            ("AUTH_GOOGLE_TEST_CLIENT_SECRET_FILE", &self.path),
            ("AUTH_GOOGLE_TEST_CLIENT_AUTH_METHOD", "client_secret_post"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
    }
}
impl Drop for File {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory)
            .expect("test infrastructure: owned Google input cleanup");
    }
}
fn parse(values: BTreeMap<String, String>) -> crate::ProbeResult<Settings> {
    Settings::parse(
        values
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v))),
    )
}

#[test]
fn explicit_registered_methods_profiles_and_literal_ip_inputs_preserve_secret_redaction() {
    let file = File::new();
    let base = parse(file.values()).unwrap();
    assert!(matches!(base.profile, ClaimsProfile::Base));
    assert_eq!(base.ip.to_string(), "127.0.0.1");
    assert!(matches!(
        base.authentication,
        OidcClientAuthentication::ClientSecretPost(_)
    ));
    let mut values = file.values();
    values.insert(
        "AUTH_GOOGLE_TEST_CLIENT_AUTH_METHOD".into(),
        "client_secret_basic".into(),
    );
    values.insert("AUTH_GOOGLE_TEST_LOOPBACK_IP".into(), "::1".into());
    values.insert(
        "AUTH_GOOGLE_TEST_CLAIMS_PROFILE".into(),
        "session_age".into(),
    );
    let settings = parse(values).unwrap();
    assert_eq!(settings.ip.to_string(), "::1");
    assert!(matches!(settings.profile, ClaimsProfile::SessionAge));
    assert!(matches!(
        settings.authentication,
        OidcClientAuthentication::ClientSecretBasic(_)
    ));
    assert_eq!(
        format!("{:?}", settings.authentication),
        "OidcClientAuthentication([REDACTED])"
    );
}

#[test]
fn untrusted_or_incomplete_configuration_cannot_select_fallbacks_or_echo_values() {
    let file = File::new();
    assert!(parse(BTreeMap::new()).is_err());
    for (key, value) in [
        ("AUTH_GOOGLE_TEST_CLIENT_ID", ""),
        ("AUTH_GOOGLE_TEST_CLIENT_ID", " marker "),
        ("AUTH_GOOGLE_TEST_CLIENT_AUTH_METHOD", "none"),
        ("AUTH_GOOGLE_TEST_CLAIMS_PROFILE", "login"),
        ("AUTH_GOOGLE_TEST_LOOPBACK_IP", "localhost"),
        ("AUTH_GOOGLE_TEST_LOOPBACK_IP", "0.0.0.0"),
        ("AUTH_GOOGLE_TEST_LOOPBACK_IP", "127.0.0.2"),
        ("AUTH_GOOGLE_TEST_UNKNOWN", "owned-manual-input-marker"),
    ] {
        let mut values = file.values();
        values.insert(key.into(), value.into());
        let error = parse(values).err().unwrap();
        assert!(!error.contains("owned-manual-input-marker") && !error.contains(&file.path));
    }
    let mut values: Vec<_> = file
        .values()
        .into_iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect();
    values.push(("AUTH_GOOGLE_TEST_CLIENT_ID".into(), "duplicate".into()));
    assert_eq!(
        Settings::parse(values).err(),
        Some("invalid_google_test_setting")
    );
}

#[cfg(unix)]
#[test]
fn permissive_secret_file_cannot_pass_manual_configuration_check() {
    use std::os::unix::fs::PermissionsExt;
    let file = File::new();
    std::fs::set_permissions(&file.path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        parse(file.values()).err(),
        Some("protected_client_secret_file")
    );
}
