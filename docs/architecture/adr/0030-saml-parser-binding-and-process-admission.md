# ADR 0030: Bind SAML extraction to the verifier DOM and bound process admission

Status: accepted for gated engineering, 2026-10-22. Production SAML remains
source-disabled. This decision is not independent security approval.

## Problem

The local quick-xml extraction DOM and the backend uppsala DOM previously had
separate namespace, normalization, element-range and Assertion-selection paths.
Local extraction exposed namespace declarations as local-name attributes and
retained literal text/CDATA line endings. The backend's permissive DTD defaults
also depended on the earlier local prepass. Per-instance admission could still
multiply native verification work across independently constructed services.

## Decision

Maintain incremental patch0009 on top of the unchanged eight-patch source.

- Exclude namespace declarations from extracted attributes while still counting
  and bounding every declaration/value. Normalize literal text/CDATA using
  quick-xml's XML1.0 API; decode character references separately as before.
- Construct the namespace-aware backend Parser with DTD and entity declarations
  forbidden and depth capped at the lower of local limits and its established128
  ceiling. Never raise the backend ceiling to match the old local1024 default.
- Before signature processing, compare the local DOM against the exact backend
  DOM: original element ranges, tree shape/order, local names, ordered ordinary
  attribute values and concatenated direct text/CDATA. A streaming NsReader pass
  independently compares expanded element/attribute names and normalized namespace
  URIs. A disagreement fails closed; it never selects a fallback interpretation.
- Require unqualified Algorithm/Reference URI selectors in strict execution and
  accepted signature policy. Qualify the backend-read InclusiveNamespaces parameter
  by the exclusive-C14N namespace, allow at most one and reject qualified PrefixList
  aliases. Backend local-name lookup cannot select a different controlling field.
- Use the same first-bearer-Assertion selection for extraction and evidence. Map
  its original byte range to the agreed backend NodeId and compare verified
  references against that actual selected node, rather than the first Assertion.
  Preserve the existing all-assertion coverage and principal/issuer checks.
- Strict profiles accept XML1.0 declarations (or an implied1.0), not XML1.1.
  Explicit compatibility APIs retain their separate broader declaration policy;
  the application always selects StrictRsaSha256.

These are parsed-view and admission checks, not an XML cryptographic verifier.
Digests, signatures and canonicalization stay delegated. Trusted manager keys and
authenticated algorithm/transform URI allowlists are unchanged; namespace/selector
checks are strengthened. No signed XML is
serialized or rewritten to supply verification or acceptance evidence. Original
source slices still feed extraction, now bound to the verified DOM's interpretation.

Core uses a192KiB decoded XML ceiling derived from its existing256KiB encoded
POST cap, and depth128 from the first local parse. The other existing parser and
namespace bounds remain. All concrete SamlResponseVerifier constructors share a
process admission semaphore with two permits, alongside the existing two-operation
per-instance/composed budget. A different service can await process admission for
up to the existing15s boundary; local overload still rejects immediately. Fresh
verification material/DB time is loaded after admission. Both permits move into
the blocking closure and remain held until actual exit after caller cancellation
or timeout. Joining an occupied old instance budget remains prohibited.

## Consequences and evidence

High-level APIs and immutable migrations are preserved. The public local DOM no
longer presents xmlns bindings as attributes and now returns XML1.0-normalized
literal text/CDATA. These are deliberate XML interpretation corrections. Strict
XML1.1 input now rejects. No existing test/assertion/fixture is changed to obtain
those behaviors; all original patches and historical receipts remain intact.

A separate qualification runner copies the lock-verified, unchanged
bergshamra-c14n0.9.2 archive into a disposable test workspace, proves that copy is
selected and that the application's selected SAML normal/build versions/features
are identical, then runs the existing SAML/core and C14N tests locked. It reuses
the existing graph/report logic and checks source identities before/after testing.
The application lock/runtime dependencies are never changed. CI runs this combined
qualification instead of duplicating the previous SAML-only execution.

This bounds admitted blocking tasks in this linked core, not every crypto caller
or OS thread. Other processes have their own budgets. Queued fields, HTTP form
parsing and instance counts still require deployment budgets. Admission, material
lookup and blocking await have separate15s boundaries; none terminates native
work. No hard CPU/RSS/job-duration limit, exhaustive C14N conformance, independent
review or production approval is inferred. See the [follow-up assessment](../../security/saml-parser-native-follow-up.md).
