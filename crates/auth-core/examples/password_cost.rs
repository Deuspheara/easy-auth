//! Local KDF timing; synthetic input, no credentials are read or printed.
use easy_auth_core::{Password, PasswordService};
use std::time::Instant;
#[tokio::main]
async fn main() {
    let policy = PasswordService::new("a compromised example password").unwrap();
    let mut hash_ms = Vec::new();
    let mut verify_ms = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let hash = policy
            .enroll(Password::parse("synthetic benchmark input phrase".into()).unwrap())
            .await
            .unwrap();
        hash_ms.push(start.elapsed().as_millis());
        let start = Instant::now();
        assert!(
            policy
                .verify(
                    Password::parse("synthetic benchmark input phrase".into()).unwrap(),
                    Some(hash.to_string())
                )
                .await
                .unwrap()
        );
        verify_ms.push(start.elapsed().as_millis());
    }
    println!(
        "argon2id v19 m=65536 KiB t=3 p=1; platform={}-{}; hash_ms={hash_ms:?}; verify_ms={verify_ms:?}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
}
