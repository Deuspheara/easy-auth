use super::optional_setting;
use auth_core::{Auth, PasswordService};
use std::sync::Arc;

pub(super) fn attach(
    mut auth: Auth,
    development: bool,
) -> Result<Auth, Box<dyn std::error::Error>> {
    let blocklist = optional_setting("AUTH_PASSWORD_BLOCKLIST_FILE")?;
    if let Some(path) = blocklist {
        // Limit startup memory: one local UTF-8 file, at most 32 MiB. Never log contents.
        use std::io::Read;
        let file = std::fs::File::open(path).map_err(|_| "password blocklist cannot be opened")?;
        let mut corpus = zeroize::Zeroizing::new(String::new());
        file.take(32 * 1024 * 1024 + 1)
            .read_to_string(&mut corpus)
            .map_err(|_| "password blocklist must be UTF-8")?;
        if corpus.len() > 32 * 1024 * 1024 {
            return Err("password blocklist exceeds 32 MiB".into());
        }
        let passwords = PasswordService::new(&corpus)?;
        if !development && passwords.corpus_size() < 10_000 {
            return Err(
                "production password blocklist requires at least 10000 distinct eligible passwords"
                    .into(),
            );
        }
        auth = auth.with_passwords(Arc::new(passwords));
    }
    Ok(auth)
}
