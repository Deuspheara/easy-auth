# Owned executable / embedded issuer parity

Run from the repository root with local PostgreSQL/Mailpit and the existing
Playwright installation. See [the setup and limits](../../../docs/guides/issuer-standalone.md).
The runner uses the actual server binary and the shared configured embedded factory,
real SMTP, browser consent, separate Node and Rust clients, and disposable storage.
Only summary booleans escape private IPC. No token, email message, private key,
trace, browser profile or callback URL is saved. Cleanup removes only this run's
random database, recipient messages and private directory. Fixture services must
never be deployed or connected to production data.
