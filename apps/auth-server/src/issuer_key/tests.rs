use super::load_issuer_signing_key;
use josekit::{jwk::KeyPair, jws::RS256};
use std::{
    fs::{OpenOptions, Permissions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    path::PathBuf,
};
use uuid::Uuid;
use zeroize::Zeroizing;

struct OwnedKeyFile {
    directory: PathBuf,
    path: PathBuf,
}
impl OwnedKeyFile {
    fn new(bytes: &[u8]) -> Self {
        let directory =
            std::env::temp_dir().join(format!("easy-auth-issuer-key-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("operator-key");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        Self { directory, path }
    }
}
impl Drop for OwnedKeyFile {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).expect("remove owned key test directory");
    }
}

#[test]
fn protected_ordinary_operator_key_loads_without_private_debug_or_path_disclosure() {
    let pair = RS256.generate_key_pair(2048).unwrap();
    let pem = Zeroizing::new(pair.to_pem_private_key());
    let file = OwnedKeyFile::new(&pem);
    let id = Uuid::new_v4();
    let key = load_issuer_signing_key(id, &file.path).unwrap();
    assert_eq!(key.id(), id);
    assert_eq!(key.public_key().unwrap().id(), id);
    assert_eq!(format!("{key:?}"), "IssuerSigningKey([REDACTED])");
    let linked = file.directory.join("valid-key-symlink");
    symlink(&file.path, &linked).unwrap();
    assert!(load_issuer_signing_key(id, &linked).is_err());
    for mode in [0o640, 0o604, 0o660, 0o644] {
        std::fs::set_permissions(&file.path, Permissions::from_mode(mode)).unwrap();
        assert!(load_issuer_signing_key(id, &file.path).is_err());
    }
    std::fs::set_permissions(&file.path, Permissions::from_mode(0o400)).unwrap();
    assert!(load_issuer_signing_key(id, &file.path).is_ok());
    assert!(load_issuer_signing_key(Uuid::nil(), &file.path).is_err());
}

#[test]
fn symlinks_permissions_nonregular_missing_and_bounded_invalid_input_fail_closed() {
    let file = OwnedKeyFile::new(b"private-content-marker");
    let id = Uuid::new_v4();
    let linked = file.directory.join("symlink");
    symlink(&file.path, &linked).unwrap();
    for path in [
        linked,
        file.directory.clone(),
        file.directory.join("missing"),
    ] {
        let error = load_issuer_signing_key(id, &path).unwrap_err();
        assert!(!error.to_string().contains("private-content-marker"));
        assert!(!error.to_string().contains(path.to_str().unwrap()));
    }
    for bytes in [vec![], vec![0xff], vec![b'a'; 16 * 1024 + 1]] {
        let invalid = OwnedKeyFile::new(&bytes);
        assert!(load_issuer_signing_key(id, &invalid.path).is_err());
    }
}
