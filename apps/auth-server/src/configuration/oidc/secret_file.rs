use super::StartupResult;
use auth_core::{OidcClientAuthentication, OidcClientSecret};
use std::{fs::File, io::Read};
use zeroize::Zeroizing;

const MAX_FILE_BYTES: u64 = 4098; // Existing 4096-byte secret plus optional CRLF.

pub(super) fn authentication(
    method: &str,
    path: Option<&String>,
) -> StartupResult<OidcClientAuthentication> {
    match (method, path) {
        ("none", None) => Ok(OidcClientAuthentication::Public),
        ("client_secret_basic", Some(path)) => {
            Ok(OidcClientAuthentication::ClientSecretBasic(read(path)?))
        }
        ("client_secret_post", Some(path)) => {
            Ok(OidcClientAuthentication::ClientSecretPost(read(path)?))
        }
        _ => Err("OIDC client method and protected secret file must agree explicitly".into()),
    }
}
fn read(path: &str) -> StartupResult<OidcClientSecret> {
    let metadata = std::fs::metadata(path).map_err(|_| "OIDC secret file unavailable")?;
    if !metadata.is_file() {
        return Err("OIDC secret must be a regular file".into());
    }
    let file = File::open(path).map_err(|_| "OIDC secret file unavailable")?;
    let metadata = file
        .metadata()
        .map_err(|_| "OIDC secret file unavailable")?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        return Err("OIDC secret file outside bounds".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("OIDC secret file must not be accessible to group or others".into());
        }
    }
    let mut value = Zeroizing::new(String::new());
    file.take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut value)
        .map_err(|_| "OIDC secret file must be bounded UTF-8")?;
    if value.len() as u64 > MAX_FILE_BYTES {
        return Err("OIDC secret file outside bounds".into());
    }
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    // Parsing takes ownership in a zeroizing core type; no content/path in errors.
    OidcClientSecret::parse(std::mem::take(&mut *value))
        .map_err(|_| "OIDC secret file contains an invalid secret".into())
}
