//! Ordinary maintained producer and lifetime of one protected fixture key file.
use super::FixtureResult;
use auth_core::IssuerSigningKey;
use josekit::{jwk::KeyPair, jws::RS256};
use std::{
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(super) struct OperatorKey {
    pub key: IssuerSigningKey,
    pub file: PathBuf,
}
impl OperatorKey {
    pub fn new(directory: &Path) -> FixtureResult<Self> {
        let pair = RS256.generate_key_pair(2048)?;
        let pem = Zeroizing::new(pair.to_pem_private_key());
        let key_id = Uuid::new_v4();
        let key = IssuerSigningKey::from_pkcs8_pem(key_id, String::from_utf8(pem.to_vec())?)?;
        let file = directory.join(format!("issuer-{}.pem", key_id.simple()));
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(&file)?;
        output.write_all(&pem)?;
        drop(output);
        Ok(Self { key, file })
    }
}
impl Drop for OperatorKey {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.file);
    }
}
