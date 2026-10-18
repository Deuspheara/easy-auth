# ADR 0003: Explicit password policy and verified enrollment

Status: accepted for alpha, AUTH-12, 2026-10-18.

Use RustCrypto Argon2id and Unicode NFC normalization rather than custom password hashing. Enrollment requires a verified email session authenticated within five minutes. It inserts one password credential and replaces all prior sessions transactionally. Replacing an existing password is reserved for the separate recovery/change flow; concurrent enrollment cannot overwrite another request's credential. Password sign-in issues the existing opaque PostgreSQL-backed session type.

A local operator-supplied compromised-password corpus is mandatory to enable passwords. The server rejects a small production corpus; the supplied example is explicitly development-only. We do not send candidate passwords to a network service. Corpus quality, licensing and updates remain operator/release responsibilities. Broadly accepting weak passwords because no corpus was configured is not an available fallback.

Argon2 runs in bounded Tokio blocking jobs, so auth-core now depends on Tokio for this actual use case. Share a PasswordService across routers/realms to share its two-worker memory bound. 64 MiB/three passes was selected after local release measurements (see the password guide). The API currently fixes and validates the hash profile; later profile upgrades need explicit compatibility, migration/rehash and resource-limit tests.

Alternative password-first signup would require holding pending credentials until verified email ownership, or risk pre-registration takeover. Requiring email proof first keeps account ownership explicit and reuses a tested transaction. Tradeoffs are an extra initial email step, a local corpus, approximately 128 MiB of concurrent KDF memory, and continued mailbox authentication at the same alpha assurance level. Reset, password change and phishing-resistant authentication remain separate requirements.
