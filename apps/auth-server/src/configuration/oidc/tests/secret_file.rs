use super::super::secret_file;
use auth_core::OidcClientAuthentication;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::PathBuf,
};

struct OwnedFile {
    directory: PathBuf,
    path: String,
}
impl OwnedFile {
    fn new(bytes: &[u8]) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "easy-auth-oidc-secret-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("client-secret");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).unwrap();
        file.write_all(bytes).unwrap();
        Self {
            directory,
            path: path.to_str().unwrap().to_owned(),
        }
    }
}
impl Drop for OwnedFile {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory)
            .expect("test infrastructure: remove owned secret fixture");
    }
}
#[test]
fn registered_methods_require_consistent_protected_file_and_redact_debug() {
    let file = OwnedFile::new(b"owned-secret-marker\r\n");
    for method in ["client_secret_basic", "client_secret_post"] {
        let auth = secret_file::authentication(method, Some(&file.path)).unwrap();
        assert_eq!(format!("{auth:?}"), "OidcClientAuthentication([REDACTED])");
        assert!(!matches!(auth, OidcClientAuthentication::Public));
        assert!(secret_file::authentication(method, None).is_err());
    }
    assert!(secret_file::authentication("none", Some(&file.path)).is_err());
    assert!(matches!(
        secret_file::authentication("none", None).unwrap(),
        OidcClientAuthentication::Public
    ));
}
#[test]
fn empty_invalid_utf8_control_and_oversized_secret_files_fail_without_echo() {
    for bytes in [
        vec![],
        vec![0xff],
        b"owned-secret-marker\nextra".to_vec(),
        vec![b'a'; 4099],
        b"owned-secret-marker\n\n".to_vec(),
    ] {
        let file = OwnedFile::new(&bytes);
        let error = secret_file::authentication("client_secret_basic", Some(&file.path))
            .err()
            .unwrap();
        assert!(!error.to_string().contains("owned-secret-marker"));
        assert!(!error.to_string().contains(&file.path));
    }
}
#[test]
fn unavailable_and_non_regular_files_are_explicit_errors() {
    let file = OwnedFile::new(b"owned-secret-marker");
    let missing = format!("{}.missing", file.path);
    assert!(secret_file::authentication("client_secret_post", Some(&missing)).is_err());
    let directory = file.directory.to_str().unwrap().to_owned();
    assert!(secret_file::authentication("client_secret_post", Some(&directory)).is_err());
    let _ = File::open(&file.path).unwrap();
}
#[cfg(unix)]
#[test]
fn group_or_world_readable_secret_is_not_accepted() {
    use std::os::unix::fs::PermissionsExt;
    let file = OwnedFile::new(b"owned-secret-marker");
    std::fs::set_permissions(&file.path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(secret_file::authentication("client_secret_basic", Some(&file.path)).is_err());
}
