use std::ffi::OsString;

pub(super) const HELP: &str = "\
Usage: easy-auth [migrate | retention | --help | --version]

With no arguments, start the authentication server using environment settings.

Options:
  migrate         Apply database migrations and exit (DATABASE_URL only)
  retention       Run one bounded realm cleanup pass and exit
  -h, --help       Print this help and exit
  -V, --version    Print the package version and exit

Setup:
  AUTH_REALM_ID    Required realm UUID
  DATABASE_URL     Required PostgreSQL connection URL
  AUTH_DATABASE_MIGRATIONS  run (default) or verify before serving
  AUTH_RETENTION_AUDIT     Required for retention: keep or whole-second age
  AUTH_RETENTION_NOTICES   Required for retention: keep or whole-second age
  AUTH_PUBLIC_URL  Public origin; production requires HTTPS
  AUTH_BIND        Listener address (default: 127.0.0.1:8080)
  AUTH_DEVELOPMENT Explicit true for loopback-only HTTP/development SMTP

Configure SMTP and optional password/provider/issuer settings through the environment.
The binary does not load .env files. Help/version do not validate configuration,
connect to PostgreSQL, run migrations, or start a listener.

Setup and provider status:
  https://github.com/Deuspheara/easy-auth/blob/main/docs/guides/server-cli.md

SAML and outbound OIDC require explicit build features, complete trusted settings
and persisted policy. Compiling a feature does not establish security approval.
";

pub(super) enum Command {
    Serve,
    Help,
    Version,
    Migrate,
    Retention,
}

pub(super) fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Command, ()> {
    let mut arguments = arguments.into_iter();
    let Some(argument) = arguments.next() else {
        return Ok(Command::Serve);
    };
    if arguments.next().is_some() {
        return Err(());
    }
    if argument == "--help" || argument == "-h" {
        Ok(Command::Help)
    } else if argument == "--version" || argument == "-V" {
        Ok(Command::Version)
    } else if argument == "migrate" {
        Ok(Command::Migrate)
    } else if argument == "retention" {
        Ok(Command::Retention)
    } else {
        Err(())
    }
}
