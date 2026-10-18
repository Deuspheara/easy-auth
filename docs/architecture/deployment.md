# Deployment design

One auth-server process, PostgreSQL and a configurable SMTP relay. Compose development starts PostgreSQL and Mailpit with loopback-only ports and disposable development credentials. Production requires HTTPS at a trusted reverse proxy, private database access, SMTP TLS, persistent database backups and protected environment/file secrets. No Redis or Node runtime required.

Typed startup validation rejects production HTTP, public development HTTP, malformed public URLs and unsafe SMTP configuration. Bind loopback by default; proxy headers are not trusted to select origins, realms, secure cookies or identity. The configured public URL is authoritative. A production proxy must enforce body/time/connection limits and forward only the intended host; application limits also apply. Migration runs before readiness, fails closed, and must have backup/restore compatibility tests before a release.

Sessions and challenges remain durable across processes. Admission counters use database atomicity and a database clock; service replicas must not introduce local-only revocation or rate-limit semantics. SMTP delivery cannot be rolled back with database transactions; tokens remain expiring and require browser binding. A durable encrypted delivery outbox is a later reliability improvement, not a reason to store plaintext session secrets.

Graceful shutdown drains requests. Structured logs include safe event names/request IDs and opaque identifiers only. Never trace raw headers, URLs containing credentials, email contents, passwords, tokens, assertions or provider client secrets. Health is liveness; readiness checks the database. Metrics use bounded labels, no user/email/client-generated labels.

Before production: define retention/cleanup schedules for expired challenges, rate counters and revoked sessions; encrypted backups, least-privilege runtime and separate migration roles, tested restoration, rolling migration procedure, secret/signing-key rotation and incident revocation runbook. These are M09 release requirements, not current operational guarantees.
