//! Existing public PasswordService, including dummy work and finite admission.
use super::load::{Report, measure};
use auth_core::{Error, Password, PasswordService};
use serde_json::json;
use std::sync::Arc;

const INPUT: &str = "synthetic benchmark input phrase";
const WRONG: &str = "different synthetic benchmark phrase";

pub(super) async fn run() -> Report {
    let service = Arc::new(PasswordService::new("a compromised example password")?);
    let stored = Arc::new(service.enroll(Password::parse(INPUT.into())?).await?);
    let mut reports = Vec::new();
    for concurrency in [1, 2, 8] {
        for name in ["enroll", "verify", "wrong_password", "unknown_account"] {
            let service = service.clone();
            let stored = stored.clone();
            let report = measure(name, concurrency, 4, move |_| {
                let service = service.clone();
                let stored = stored.clone();
                async move {
                    let input = if name == "wrong_password" {
                        WRONG
                    } else {
                        INPUT
                    };
                    let password = Password::parse(input.into())?;
                    if name == "enroll" {
                        service.enroll(password).await?;
                        return Ok(());
                    }
                    let hash = (name != "unknown_account").then(|| stored.to_string());
                    let verified = service.verify(password, hash).await?;
                    if verified != (name == "verify") {
                        return Err(Error::Unavailable);
                    }
                    if verified {
                        Ok(())
                    } else {
                        Err(Error::Unauthorized)
                    }
                }
            })
            .await?;
            reports.push(report);
        }
    }
    Ok(json!({"profile": "argon2", "algorithm": "argon2id-v19",
        "memory_kib": 65536, "iterations": 3, "lanes": 1, "workers": 2,
        "reports": reports}))
}
