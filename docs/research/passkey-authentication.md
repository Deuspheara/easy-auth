# Passkey assertion boundary

AUTH-19, 2026-10-19. Optional core/PostgreSQL sign-in now persists ceremonies and
atomically issues sessions after verified proof. No HTTP login route or native
browser assertion flow enables it yet. AUTH-19 and M03 remain in progress;
ordinary server composition stays gated on the remaining policy and browser work.

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

Private state is versioned, bounded to 1 MiB, explicitly encoded only for trusted
database storage and has no public Serialize implementation. Stored credential
objects are bounded to 64 KiB and checked against separately loaded ownership/ID
metadata. All new sensitive wrappers redact Debug. Synchronous library calls use
the existing scoped tracing suppression and restore caller logging immediately.
The private-state cap accommodates ten stored credentials of up to 64 KiB each
plus the library and ownership snapshots; it is not an HTTP response/body limit.

The returned proof carries the actual loaded ceremony bytes, original credential
bytes and the library's updated credential. It is not a session or permission to
write unconditionally. `PasskeySignIn` calls the PostgreSQL authentication repository,
which locks owner, credential and ceremony in that order; compares both exact proof
snapshots; then checks expiry in a separate statement after any ceremony-row wait.
It atomically consumes state, updates credential/last-use metadata, inserts a fresh
256-bit verifier-only session and records the owned `passkey_authenticated` audit
fact. Any failure rolls everything back. Different pending challenges verified from
one old credential snapshot cannot both overwrite it; start a new ceremony after
the losing attempt. The existing session idle/absolute/revocation rules apply.

Migration 0008 adds two-minute, browser/realm/RP/purpose-bound private ceremonies,
three pending per browser and separate start/finish admission: 20 per browser and
40 per source per ten-minute window. Admission commits before lookup/verification,
including invalid attempts. Account-bound starts currently accept an opaque account
ID lookup hint; no email-to-credential lookup is exposed. The HTTP account-selection
experience still needs privacy review before enabling this flow. Discoverable
ceremonies have no claimed owner until the actual key and handle verify.

Session authentication methods are stored as `email`, `password`, `passkey` or
`legacy_unknown`. Existing methods are not inferred during migration; password
enrollment rotations copy their initiating method and authentication time. This
metadata does not yet enforce stronger-account recovery or sensitive-action policy.
Revoke-all cancels account-bound pending ceremonies. Anonymous discovery has no
owner to cancel: a new valid private-key proof can log in after revocation, serialized
on the owner lock like password login. Account deletion cascades owned ceremonies
and credentials and deidentifies the new audit fact. Anonymous expired-state/bucket
retention remains part of the existing operational hardening work.

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

Twelve real PostgreSQL tests additionally cover successful session/key/audit commit,
browser/realm/handle binding, replay, concurrent completion and different-challenge
snapshot races, audit rollback with a valid retry, proof/ceremony mismatch, changed
credentials, owner-lock expiry, expiry after an unchanged ceremony-row lock wait,
pending/source/browser admission, revoke-all/deletion and method migration/rotation.
The database discovery signer has the same residence limitation as the protocol
fixture; these are not native discovery checks.

Before AUTH-19 is Done: safe account selection without email enumeration, enforcement
of reviewed stronger-account boundaries, HTTP contracts and native platform/roaming
assertion plus real discovery and backup/zero-counter tests. AUTH-53 owns genuine email-free enrollment;
AUTH-20 owns management/recovery. None of those gates is replaced by this verifier.
