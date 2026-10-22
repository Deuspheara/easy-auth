# ADR 0028: Exact SAML attribute records and established authentication time

Date: 2026-10-22. Status: accepted for gated ordinary engineering; production
security approval remains separate under ADR 0021.

## Attribute projection

The legacy saml-rs name-keyed attribute view cannot distinguish equal names with
different NameFormat or preserve record groups. Keep that public view unchanged
for compatibility. Add a separate `SsoSession::attribute_records()` contract.

The maintained library extracts document-order records from the exact Assertion
shortcut already selected by signature verification. It uses the existing bounded
DOM and the same XML limits, not an application parser or a second cryptographic
verifier. Preserve Name, optional NameFormat (including absent versus empty), all
scalar text values, duplicates, empty values and record groups. No normalization,
format inference, name-based merge or schema-type coercion is performed.

Patch0007 declares NameFormat and all consumed NameID qualifiers in the existing
unqualified-attribute validation list before the local-name DOM projection. Static
source review found these consumed-field declarations missing. This reuses the
existing namespace validator; it adds no parser, cryptographic verifier or custom
XML probe. The broader namespace/ID/backend equivalence review remains pending.

The new accessor returns Some(empty) for an assertion without attributes. It
returns None when a complete scalar projection is unavailable, including a legacy
manually constructed raw FlowResult, XML-valued or nil data. Partial projection
must never masquerade as complete. The legacy accessor remains usable by existing
library clients; easy-auth requires the complete accessor and rejects unavailable
projection instead of falling back. Existing verifier signature/coverage, issuer,
conditions, request, trust, algorithm and tenant requirements remain unchanged.

The concrete core verifier retains zeroizing, debug-redacted `SamlAttribute`
records in its opaque `VerifiedSamlAssertion`. The existing encoded input/XML
limits also bound this collection. These are verified provider facts, not grants.
Persistent NameID still selects ownership. Email, displayName, role and attribute
format cannot select or merge an owner, install a contact, override default-deny
JIT, change registration or grant application permissions. No attribute-selected
metadata/role policy or storage schema is introduced by exposing these facts.

The normal typed IdP producer gains an additive scalar attribute option, rendered
by its existing XML writer and signer. Mixing it with template attributes or
custom rendering fails explicitly. This produces ordinary integration scenarios
without handwritten XML, cryptographic fixtures or signature manipulation.

## Authentication time

A newly issued SSO response can describe a previously established authentication.
The producer must be able to carry that event's AuthnInstant separately from
Response/Assertion IssueInstant. An additive trusted producer option supplies a
valid UTC authentication instant no later than issuance. It requires the built-in
Web Browser SSO generation path; it cannot silently disappear into a legacy
response without an AuthnStatement. Omitting it retains existing producer behavior.
No actual authentication event or authentication strength is inferred by this API.

Response issuance, original admission, signed authentication age and signed session
bounds remain separate. Easy-auth retains the 24-hour sign-in authentication-age
limit and five-minute sensitive-action freshness rule. The verifier and database
clock are unchanged. Ordinary signed retained-authentication scenarios must prove
that recent response issuance does not refresh stored authentication or make stale
authentication eligible for account deletion. These component scenarios do not
replace actual IdP reauthentication/SSO interoperability or independent review.

## Delivery and release

Retain original fixtures, tests, source/patch provenance and historical receipts.
Record incremental maintenance patches and requalify the selected application
backend graph. Keep source-specific engineering tests, internal review and
independent approval distinct. Normal SAML remains disabled; no PR or external
reviewer/upstream contact is part of this change.
