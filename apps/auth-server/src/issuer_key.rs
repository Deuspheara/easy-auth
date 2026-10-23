//! Trusted embedding input only; no environment activation or key provisioning.
use auth_core::{Error, IssuerSigningKey, Result};
use std::path::Path;
use uuid::Uuid;

/// Load one explicit operator key. The caller must control the path and all its
/// parent directories. Unix enforces a regular, owner-only file and refuses a
/// final symlink at open time. Other platforms fail closed until an ACL-backed
/// loader is provided. No file path, native error or private text escapes.
pub fn load_issuer_signing_key(id: Uuid, path: &Path) -> Result<IssuerSigningKey> {
    if id.is_nil() {
        return Err(Error::InvalidInput);
    }
    #[cfg(unix)]
    {
        load_unix(id, path)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(Error::Unavailable)
    }
}

#[cfg(unix)]
fn load_unix(id: Uuid, path: &Path) -> Result<IssuerSigningKey> {
    use std::{
        fs::OpenOptions,
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    use zeroize::Zeroizing;
    const MAX_PEM_BYTES: u64 = 16 * 1024;
    // NONBLOCK prevents an unexpected FIFO from blocking before the opened
    // descriptor can be checked. NOFOLLOW is atomic for the final path component.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::Unavailable)?;
    let metadata = file.metadata().map_err(|_| Error::Unavailable)?;
    if !metadata.is_file()
        || metadata.mode() & 0o077 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_PEM_BYTES
    {
        return Err(Error::InvalidInput);
    }
    let mut input = Zeroizing::new(String::new());
    file.take(MAX_PEM_BYTES + 1)
        .read_to_string(&mut input)
        .map_err(|_| Error::InvalidInput)?;
    if input.len() as u64 > MAX_PEM_BYTES {
        return Err(Error::InvalidInput);
    }
    IssuerSigningKey::from_pkcs8_pem(id, std::mem::take(&mut *input))
}

#[cfg(all(test, unix))]
mod tests;
