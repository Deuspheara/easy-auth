use std::{ffi::OsStr, process::Command};

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_easy-auth"));
    command.env_clear();
    command
}

#[test]
fn help_does_not_require_configuration_or_database_access() {
    for flag in ["--help", "-h"] {
        let output = command().arg(flag).output().unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.starts_with("Usage: easy-auth"));
        assert!(help.contains("AUTH_REALM_ID"));
        assert!(help.contains("SAML and outbound OIDC require explicit build features"));
        assert!(help.contains("Compiling a feature does not establish security approval"));
    }
}

#[test]
fn version_reports_the_package_version_without_startup() {
    for flag in ["--version", "-V"] {
        let output = command().arg(flag).output().unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert_eq!(
            output.stdout,
            format!("easy-auth {}\n", env!("CARGO_PKG_VERSION")).as_bytes()
        );
    }
}

fn assert_invalid(arguments: &[&OsStr]) {
    let output = command().args(arguments).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"invalid command line; run easy-auth --help\n"
    );
}

#[test]
fn unsupported_arguments_reject_without_reflecting_values_or_starting() {
    for argument in ["--unknown=private-marker", "private-marker", "", "--"] {
        assert_invalid(&[OsStr::new(argument)]);
    }
}

#[test]
fn help_and_version_do_not_hide_extra_arguments() {
    for arguments in [
        ["--help", "private-marker"],
        ["private-marker", "--help"],
        ["--version", "--help"],
        ["--help", "--help"],
        ["--version", "--version"],
        ["migrate", "private-marker"],
        ["migrate", "--help"],
        ["retention", "private-marker"],
        ["retention", "--help"],
    ] {
        assert_invalid(&arguments.map(OsStr::new));
    }
}

#[cfg(unix)]
#[test]
fn non_unicode_arguments_reject_without_panicking_or_reflection() {
    use std::os::unix::ffi::OsStrExt;
    assert_invalid(&[OsStr::from_bytes(b"private-marker-\xff")]);
}

#[test]
fn no_arguments_still_enter_existing_configuration_validation() {
    let output = command().env("AUTH_DEVELOPMENT", "true").output().unwrap();
    assert!(!output.status.success());
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(diagnostic.contains("AUTH_REALM_ID is required"));
    assert!(!diagnostic.contains("invalid command line"));
}

#[test]
fn migration_administration_requires_only_database_configuration() {
    let output = command()
        .arg("migrate")
        .env("AUTH_REALM_ID", "private-marker")
        .env("SMTP_PASSWORD", "private-marker")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"Error: \"DATABASE_URL is required\"\n");
}

#[test]
fn migration_connection_failures_do_not_reflect_the_url_or_server_settings() {
    let output = command()
        .arg("migrate")
        .env("DATABASE_URL", "private-marker")
        .env("AUTH_PUBLIC_URL", "private-marker")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"Error: \"database connection failed\"\n");
}

fn retention_command() -> Command {
    let mut command = command();
    command
        .arg("retention")
        .env("AUTH_REALM_ID", "a9400000-0000-4000-8000-000000000001")
        .env("AUTH_RETENTION_AUDIT", "keep")
        .env("AUTH_RETENTION_NOTICES", "keep");
    command
}

#[test]
fn retention_requires_explicit_valid_choices_before_connecting() {
    for name in ["AUTH_RETENTION_AUDIT", "AUTH_RETENTION_NOTICES"] {
        let output = retention_command().env_remove(name).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(
            output.stderr,
            format!("Error: \"{name} is required\"\n").as_bytes()
        );
        let output = retention_command()
            .env(name, "private-marker")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(
            output.stderr,
            format!("Error: \"{name} must be keep or a supported positive whole-second age\"\n")
                .as_bytes()
        );
    }
}

#[test]
fn retention_rejects_nil_realm_before_database_work() {
    let output = retention_command()
        .env("AUTH_REALM_ID", "00000000-0000-0000-0000-000000000000")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"Error: \"AUTH_REALM_ID must be a non-nil UUID\"\n"
    );
}

#[test]
fn retention_needs_no_server_smtp_provider_or_migration_mode_settings() {
    let output = retention_command()
        .env("AUTH_DATABASE_MIGRATIONS", "private-marker")
        .env("AUTH_PUBLIC_URL", "private-marker")
        .env("SMTP_PASSWORD", "private-marker")
        .env("AUTH_OIDC_ISSUER", "private-marker")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"Error: \"DATABASE_URL is required\"\n");
    let output = retention_command()
        .env("DATABASE_URL", "private-marker")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"Error: \"database connection failed\"\n");
}

#[cfg(unix)]
#[test]
fn retention_non_unicode_configuration_never_reflects_values() {
    use std::os::unix::ffi::OsStrExt;
    for name in [
        "AUTH_REALM_ID",
        "AUTH_RETENTION_AUDIT",
        "AUTH_RETENTION_NOTICES",
    ] {
        let output = retention_command()
            .env(name, OsStr::from_bytes(b"private-marker-\xff"))
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(
            output.stderr,
            format!("Error: \"{name} must be valid Unicode\"\n").as_bytes()
        );
    }
}
