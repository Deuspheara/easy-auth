//! Explicit registered-client acceptance, never ordinary application startup.
mod attempt;
mod completion;
#[path = "../../../../tests/support/google/database.rs"]
mod database;
mod errors;
mod observations;
#[path = "../../src/configuration/oidc/secret_file.rs"]
mod secret_file;
mod settings;
mod setup;
#[cfg(test)]
mod tests;

type ProbeResult<T> = Result<T, &'static str>;
type StartupResult<T> = Result<T, Box<dyn std::error::Error>>;

enum OwnedMode {
    SetupOnly,
    SignIn,
}

#[tokio::main]
async fn main() {
    let result = run().await;
    match result {
        Ok(report) => println!("{report}"),
        Err(stage) => {
            eprintln!("{}", serde_json::json!({"status":"failed","stage":stage}));
            std::process::exit(1);
        }
    }
}

async fn run() -> ProbeResult<serde_json::Value> {
    let arguments = std::env::args_os()
        .skip(1)
        .map(|value| value.into_string())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "manual_cli_unicode_required")?;
    match arguments
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--check-configuration"] => {
            let settings = settings::Settings::read()?;
            Ok(
                serde_json::json!({"status":"inputs_checked","registered_client_confirmed":false,
                "claims_profile":settings.profile.name(),"loopback":settings.ip.to_string(),
                "browser_launched":false,"credentials_submitted":false}),
            )
        }
        ["--check-owned-setup"] => owned(settings::Settings::read()?, OwnedMode::SetupOnly).await,
        ["--run-manual-signin", "--disposable-account-consent"] => {
            owned(settings::Settings::read()?, OwnedMode::SignIn).await
        }
        _ => Err("explicit_manual_mode_and_consent_required"),
    }
}

async fn owned(settings: settings::Settings, mode: OwnedMode) -> ProbeResult<serde_json::Value> {
    let database = database::Database::create().await?;
    let result = match mode {
        OwnedMode::SignIn => attempt::run(&database.pool, settings).await,
        OwnedMode::SetupOnly => attempt::check_setup(&database.pool, settings).await,
    };
    database.close().await?;
    let mut report = result?;
    report["owned_database_removed"] = true.into();
    Ok(report)
}
