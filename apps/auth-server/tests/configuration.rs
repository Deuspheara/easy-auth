use std::process::Command;

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_easy-auth"));
    command
        .env_clear()
        .env("AUTH_DEVELOPMENT", "true")
        .env("AUTH_REALM_ID", uuid::Uuid::new_v4().to_string());
    command
}

fn assert_configuration_error(mut command: Command, expected: &str) {
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    // Exact output proves neither input values nor an unrelated DB error appear.
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!("Error: {expected:?}\n")
    );
}

#[test]
fn malformed_settings_identify_the_field_without_reflecting_the_value() {
    for (name, value, expected) in [
        (
            "AUTH_DEVELOPMENT",
            "private-marker",
            "AUTH_DEVELOPMENT must be true or false",
        ),
        (
            "AUTH_PUBLIC_URL",
            "https://private-marker@example.test/",
            "AUTH_PUBLIC_URL must be an allowed origin (HTTPS, or loopback HTTP in development)",
        ),
        (
            "AUTH_BIND",
            "private-marker",
            "AUTH_BIND must be a socket address",
        ),
        (
            "AUTH_REALM_ID",
            "private-marker",
            "AUTH_REALM_ID must be a UUID",
        ),
        (
            "SMTP_PORT",
            "private-marker",
            "SMTP_PORT must be a valid port number",
        ),
        (
            "SMTP_FROM",
            "private-marker",
            "SMTP_FROM must be a valid mailbox",
        ),
        (
            "AUTH_DATABASE_MIGRATIONS",
            "private-marker",
            "AUTH_DATABASE_MIGRATIONS must be run or verify",
        ),
    ] {
        let mut command = command();
        command.env(name, value);
        assert_configuration_error(command, expected);
    }
}

#[cfg(unix)]
#[test]
fn non_unicode_settings_cannot_select_defaults_or_disable_credentials() {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
    for name in [
        "AUTH_DEVELOPMENT",
        "AUTH_PUBLIC_URL",
        "AUTH_BIND",
        "AUTH_REALM_ID",
        "DATABASE_URL",
        "AUTH_DATABASE_MIGRATIONS",
        "SMTP_HOST",
        "SMTP_PORT",
        "SMTP_FROM",
        "SMTP_USERNAME",
        "SMTP_PASSWORD",
    ] {
        let mut command = command();
        command.env(name, OsStr::from_bytes(b"private-marker-\xff"));
        assert_configuration_error(command, &format!("{name} must be valid Unicode"));
    }
}

#[test]
fn absent_settings_retain_defaults_and_missing_requirements_are_named() {
    assert_configuration_error(command(), "DATABASE_URL is required");
    let mut missing_realm = command();
    missing_realm.env_remove("AUTH_REALM_ID");
    assert_configuration_error(missing_realm, "AUTH_REALM_ID is required");
}

#[test]
fn schema_selection_is_explicit_and_never_falls_back_from_invalid_values() {
    for value in ["", " run", "RUN", "false", "verify "] {
        let mut command = command();
        command.env("AUTH_DATABASE_MIGRATIONS", value);
        assert_configuration_error(command, "AUTH_DATABASE_MIGRATIONS must be run or verify");
    }
    for value in ["run", "verify"] {
        let mut command = command();
        command.env("AUTH_DATABASE_MIGRATIONS", value);
        assert_configuration_error(command, "DATABASE_URL is required");
    }
}

#[test]
fn valid_explicit_settings_and_credentials_reach_the_database_requirement() {
    for development in ["true", "false"] {
        let mut command = command();
        command
            .env("AUTH_DEVELOPMENT", development)
            .env("AUTH_PUBLIC_URL", "https://app.example")
            .env("AUTH_BIND", "127.0.0.1:8080")
            .env("SMTP_HOST", "localhost")
            .env("SMTP_PORT", "465")
            .env("SMTP_FROM", "auth@example.test")
            .env("SMTP_USERNAME", "private-marker")
            .env("SMTP_PASSWORD", "private-marker");
        assert_configuration_error(command, "DATABASE_URL is required");
    }
}

#[test]
fn production_http_and_development_remote_origins_still_reject() {
    for (development, origin) in [
        ("false", "http://localhost"),
        ("true", "http://private-marker.example"),
    ] {
        let mut command = command();
        command
            .env("AUTH_DEVELOPMENT", development)
            .env("AUTH_PUBLIC_URL", origin);
        assert_configuration_error(
            command,
            "AUTH_PUBLIC_URL must be an allowed origin (HTTPS, or loopback HTTP in development)",
        );
    }
}

#[test]
fn development_bind_and_smtp_loopback_requirements_are_preserved() {
    let mut bind = command();
    bind.env("AUTH_BIND", "0.0.0.0:8080");
    assert_configuration_error(bind, "development bind must be loopback");
    let mut smtp = command();
    smtp.env("SMTP_HOST", "private-marker.example");
    assert_configuration_error(smtp, "development SMTP must be loopback");
}

#[test]
fn partial_credentials_and_missing_production_credentials_still_reject() {
    for name in ["SMTP_USERNAME", "SMTP_PASSWORD"] {
        let mut command = command();
        command.env(name, "private-marker");
        assert_configuration_error(
            command,
            "SMTP_USERNAME and SMTP_PASSWORD are required together in production",
        );
    }
    let mut production = command();
    production
        .env("AUTH_DEVELOPMENT", "false")
        .env("AUTH_PUBLIC_URL", "https://app.example");
    assert_configuration_error(
        production,
        "SMTP_USERNAME and SMTP_PASSWORD are required together in production",
    );
}
