# ADR 0002: PostgreSQL-owned opaque sessions and browser-bound email proof

Status: accepted for first alpha slice, 2026-10-18.

Choose 32 random bytes encoded base64url for email and session secrets. Persist SHA-256 verifiers, not plaintext bearer values. Use OS CSPRNG and established hashing; no custom cryptography. No JWT session or cache, so logout is enforced on the next database verification across replicas. Realm participates in lookup and relational constraints. Database time governs expiry/admission.

The first method is email magic-link proof, not password signup. Email proof creates an account only after control is demonstrated. Links put the token in a fragment; the first-party page removes it before a same-origin POST. An independent HttpOnly browser binding prevents an attacker from signing a victim browser into the attacker account. Cross-device redemption is deliberately unsupported in this increment. GET never consumes a token. A session and challenge consumption commit together.

Alternatives: password-first adds compromised-password corpus and Argon2/resource tuning before value; unbound magic links permit login CSRF; JWTs add revocation complexity; Redis introduces consistency/failure semantics. Tradeoff: database roundtrip on session validation and reliance on SMTP/mailbox security. The contract must disclose these limits.
