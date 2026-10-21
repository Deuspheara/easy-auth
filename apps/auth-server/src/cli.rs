use std::ffi::OsString;

pub(super) const HELP: &str = "\
Usage: easy-auth [--help | --version]

With no arguments, start the authentication server using environment settings.

Options:
  -h, --help       Print this help and exit
  -V, --version    Print the package version and exit

Setup:
  AUTH_REALM_ID    Required realm UUID
  DATABASE_URL     Required PostgreSQL connection URL
  AUTH_PUBLIC_URL  Public origin; production requires HTTPS
  AUTH_BIND        Listener address (default: 127.0.0.1:8080)
  AUTH_DEVELOPMENT Explicit true for loopback-only HTTP/development SMTP

Configure SMTP and optional password/OIDC settings through the environment.
The binary does not load .env files. Help/version do not validate configuration,
connect to PostgreSQL, run migrations, or start a listener.

Setup and provider status:
  https://github.com/Deuspheara/easy-auth/blob/main/docs/guides/server-cli.md

SAML is unavailable; unfinished providers are not enabled by these options.
";

pub(super) enum Command {
    Serve,
    Help,
    Version,
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
    } else {
        Err(())
    }
}
