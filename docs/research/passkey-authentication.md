# Passkey assertion boundary

AUTH-19, 2026-10-19. This checkpoint implements an optional protocol verifier;
it does not implement login, a durable authentication transaction or session issuance.
AUTH-19 and M03 remain in progress. Ordinary server composition remains gated.

## Reviewed source and policy

Reviewed the registry release of [webauthn-rs 0.5.5](https://docs.rs/crate/webauthn-rs/0.5.5/source/src/lib.rs),
its [credential types](https://docs.rs/crate/webauthn-rs/0.5.5/source/src/interface.rs)
and [core verifier](https://docs.rs/webauthn-rs-core/0.5.5/src/webauthn_rs_core/core.rs.html),
against [WebAuthn Level 3 assertion verification](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion).
Production calls only the high-level library. No credential-internals feature,
custom assertion parsing or signature implementation is introduced.

- Account-bound authentication uses `start_passkey_authentication` and
  `finish_passkey_authentication` with a nonempty, bounded trusted credential list.
  The private envelope binds realm, owner, exact origin and SHA-256 fingerprints
  of the original database credential bytes. A changed credential requires a new
  ceremony, preventing cached counter/state from overwriting a newer snapshot.
- Discoverable authentication uses the high-level `conditional-ui` feature and
  preserves its conditional mediation. This is opportunistic resident-credential
  autofill, not a general modal discoverable flow. Registration still does not
  promise residence. Do not silently change mediation or claim a resident credential
  from unsigned client extension results.
- A response credential ID is only a lookup hint. The adapter must load by trusted
  realm and RP. Verification requires the loaded ID, realm and RP to match, checks
  optional account-bound `userHandle` against its owner UUID, and requires that exact
  UUID handle for discoverable proof. Incoming handles never authorize ownership.
- Canonical base64url `id` and `rawId` must agree, type must be `public-key`, IDs
  are at most 1,024 bytes and the combined assertion buffers at most 16 KiB. The
  owning HTTP boundary must additionally bound the complete JSON request.
- The library verifies challenge, exact origin, RP hash, UP, required UV, signature
  and counter. Its constructor sets `require_valid_counter_value=true`: if either
  stored or asserted counter is nonzero, the new counter must be larger. Two zero
  counters are supported by library policy; this checkpoint does not yet provide a
  real signed zero-counter authenticator test. Counter failure rejects that attempt;
  it does not permanently disable an account.
- Backup eligibility is immutable in both modes. The bound library API permits
  false-to-true upgrades whereas discovery rejects them, so the wrapper additionally
  compares the verified result with the trusted stored eligibility. A narrow Serde
  projection reads `cred.backup_eligible` from the pinned library's database format,
  after decoding the complete `Passkey`; missing/malformed metadata fails closed.
  This couples persistence to the reviewed version and must be revisited on upgrades.
  Backup state can change for previously eligible credentials using the library's
  update method. Signed BE-upgrade/BS-transition browser cases remain required.

Private state is versioned, bounded to 128 KiB, explicitly encoded only for trusted
database storage and has no public Serialize implementation. Stored credential
objects are bounded to 64 KiB and checked against separately loaded ownership/ID
metadata. All new sensitive wrappers redact Debug. Synchronous library calls use
the existing scoped tracing suppression and restore caller logging immediately.

The returned proof carries the expected original credential bytes and the library's
updated credential. It is not a session or permission to write unconditionally.
The repository must compare both exact ceremony and credential snapshots under
locks, recheck expiry and ownership, and atomically consume state, update the key,
issue a new session with genuine method provenance and record its audit fact.
These transactions are the next implementation boundary, not claimed here.

## Evidence and remaining gates

Six software-authenticator tests use actual library registration and assertion
signatures. They cover increasing and cloned counters with a subsequent valid
control, wrong signed challenge/RP/origin/missing UV, corrupted signatures,
cross-owner/realm/RP/origin state, contradictory handles, stale credential bytes,
version/size/canonical-envelope bounds and backup eligibility contradiction.
The discoverable protocol test supplies the known key to a test signer that lacks
residence and supplies its handle; it proves server verification and handle policy,
not discovery or native browser interoperability. No private token snapshots are
written to disk or logs.

Before AUTH-19 is Done: real PostgreSQL challenge expiry, browser/realm/purpose
binding, admission, concurrent consume/update/session/audit rollback and deletion
races; safe account selection without email enumeration; method provenance and
reviewed stronger-account boundaries; HTTP contracts and native platform/roaming
assertion plus real discovery tests. AUTH-53 owns genuine email-free enrollment;
AUTH-20 owns management/recovery. None of those gates is replaced by this verifier.
