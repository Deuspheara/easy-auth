# Signed-content engine observations

AUTH-32 research overlay, using the unchanged source-pinned samael candidate in
the [native assessment](../README.md). No production verifier or ACS is selected.
From the repository root, after building the native parent image:

```sh
docker build --platform linux/arm64 --network none --build-arg NATIVE_IMAGE=easy-auth-saml-native-assessment -t easy-auth-saml-signature-assessment tests/provider/saml/native/signature-probe
probe_image=$(docker image inspect --format '{{.Id}}' easy-auth-saml-signature-assessment)
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --cpus 2 --memory 3g --tmpfs /tmp:rw,nosuid,nodev,size=128m "$probe_image"
```

The owned fixture generates two ephemeral RSA-2048 keys/certificates in memory,
uses the candidate's existing response builder and signer, and explicitly replaces
its default SHA-1 reference digest with SHA-256 **before signing**. Verification
always supplies `Some(&[AllowedSignatureAlgorithm::RsaSha256])`, restricting both
the signature and reference digest. No verifier, canonicalizer or cryptographic
primitive is implemented here. Keys, XML and native diagnostics are never emitted
in reports. Fixture construction failure exits 2; it cannot count as rejection.

Both `ValidateAndMarkNoAncestors` and `PreDigest` are exercised. Healthy signed
Responses and Assertions must produce a parsed trusted subject with no
attacker/envelope marker, before and after negatives. A second independently signed control and configured
rollover exercise actual keys, rather than a pre-existing upstream fixture with
legacy algorithms or mismatched metadata. SHA-1 is generated only as a negative
input and is never permitted by the verification allowlist.

The [expanded record](../results/2026-10-20/assertion-signature-observation.json)
contains 56 case/mode rows. All ten healthy controls and both rollover rows pass. Both
modes reject unsigned content, altered signatures, altered subjects, wrong keys,
missing trust, untrusted embedded KeyInfo, SHA-1 digests and duplicate IDs.
Forged siblings before/after the signed Response are excluded from the returned
verified content in both modes. These are bounded engine/extraction observations,
not authentication or SAML profile acceptance.

The Assertion cases sign only the Assertion inside an unsigned Response, whose
destination contains the fixed envelope marker. Both modes omit that marker and
forged unsigned Assertions inserted before/after the signed Assertion. Wrong or
missing trust, unsigned/tampered Assertions and duplicate signed Assertion IDs are
rejected. Output parsing uses the candidate's existing Response/Assertion types;
it does not supply profile validation or local authentication authority.

A separate negative is actually signed with RSA-SHA1 and a SHA-256 digest using
the upstream signer; both modes reject it under the unchanged allowlist. The
existing SHA-1-digest negative retains RSA-SHA256, so the two controls vary the
signature and digest independently. Neither weak algorithm is allowed during
verification. The [earlier 34-row record](../results/2026-10-20/signature-observation.json)
remains immutable; reproduce that exact overlay from commit `4e912ba`.

**Exit 1: six XML-policy failures remain.** A DOCTYPE, truncated closing tag and
multiple document roots are accepted in both modes while still returning the
signed trusted subject. Dropping forbidden syntax during reduction does not meet
the application's strict input rejection policy. This observation does not prove
an authentication bypass. Resource access during signature/canonicalization or
fragment parsing is not independently observed by this probe; network isolation
alone supplies no such proof.

The separate [signature-resource observer](RESOURCES.md) now adds bounded signed
DTD/entity observations with the existing parser I/O controls. It preserves policy
failures and opaque errors separately; zero observed access is not general XXE safety.

Infrastructure controls:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/provider/saml/native/signature-probe -v
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --cpus 2 --memory 3g --tmpfs /tmp:rw,nosuid,nodev,size=128m --tmpfs /work/target:rw,nosuid,nodev,size=1m "$probe_image"
```

The second command actually hides the executable and exits 2 with
`infrastructure_failed`, without rejection observations. A subsequent normal run
reproduces all 56 outcomes. Four reporting tests check missing/duplicate/
contradictory rows, failed positives, unresolved engine errors and unsafe accepted
content, including each Response/Assertion positive independently. Mocked reporting
tests supply no cryptographic evidence. The actual child
has a ten-second deadline and two-second post-kill reap bound. Unknown engine
errors remain unresolved; only finite known failure categories count as rejection.

For linting, fetch the matching Clippy component only inside a disposable
container; dependencies compile offline. The image and host toolchain stay intact:

```sh
docker run --rm -i --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --cpus 2 --memory 3g --entrypoint sh "$probe_image" -c 'rustup component add clippy </dev/null && python3 -' < tests/provider/saml/native/signature-probe/lint.py
```

`lint.py` retains full upstream strict Clippy separately from owned-source lint
using the actual compiled samael/libxml artifacts. Full upstream lint remains a
failure on unchanged library diagnostics; no upstream patch or warning exemption
is applied to obtain an owned-source result. See the finite record for exact
counts and exit codes. `rustfmt --edition 2021 --check` covers the overlay modules,
which live outside the application workspace.

Broader wrapping/transforms/algorithm/resource corpus, strict profile and
application/PostgreSQL correlation/replay/isolation,
native advisory/license review and focused independent security review remain
gates. No identity proof, session, migration or public API is added by this probe.
