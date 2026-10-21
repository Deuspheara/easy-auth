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
        assert!(help.contains("SAML is unavailable"));
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
