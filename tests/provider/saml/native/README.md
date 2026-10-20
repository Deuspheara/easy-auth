# Isolated native SAML candidate assessment

AUTH-32 research only. This recipe builds unchanged upstream samael 0.0.22 at
`2d27dfe4930c4632b202f32886a85b2d1f9226c2`; it adds no easy-auth runtime dependency,
SAML route or trusted identity. No production verifier is selected.
The [recorded run](results/2026-10-20/upstream-native.json) preserves both the
default-suite success and the separately executed ignored-positive failure.

The Dockerfile verifies the complete `git archive` SHA256 before extraction and
compiles the upstream library tests with its unchanged lockfile. The Rust base
image is pinned by digest. Debian native packages are resolved at build time:
record their actual versions and the resulting image ID for every new run. This
is source provenance and an executable recipe, not a reproducible-binary claim or
native advisory/license clearance.

Use an external checkout of the pinned public upstream repository. From the
easy-auth repository root:

```sh
samael_checkout=/path/to/samael
assessment_dir=$(mktemp -d)
git -C "$samael_checkout" archive --format=tar 2d27dfe4930c4632b202f32886a85b2d1f9226c2 > "$assessment_dir/source.tar"
cp tests/provider/saml/native/Dockerfile tests/provider/saml/native/run-tests.py tests/provider/saml/native/.dockerignore "$assessment_dir/"
docker build --platform linux/arm64 -t easy-auth-saml-native-assessment "$assessment_dir"
assessment_image=$(docker image inspect --format '{{.Id}}' easy-auth-saml-native-assessment)
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --cpus 2 --memory 3g --tmpfs /tmp:rw,nosuid,nodev,size=128m "$assessment_image"
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --cpus 2 --memory 3g --tmpfs /tmp:rw,nosuid,nodev,size=128m "$assessment_image" python3 /work/run-tests.py --case ignored-positive
```

The first observed run passed 86 tests and retained one upstream ignored case.
The second command explicitly runs that ignored positive and **exited 101 with
one failed assertion**. Do not combine these into an all-passing result, remove
the assertion, or enable a weaker algorithm to change the outcome. The native
engine reports an RSA-SHA1 signature failure. Independent OpenSSL extraction of
the public fixture certificate keys finds that the ignored fixture's metadata
key differs from its embedded certificate key; the passing companion fixture's
keys match. This is consistent with the observed trust mismatch, not proof of a
library vulnerability or permission to trust attacker-supplied KeyInfo.

The default upstream suite includes legacy algorithm positives. Its success does
not establish easy-auth's required algorithm allowlist, no-DTD/XXE/resource policy,
strict verified-node consumption, profile checks or PostgreSQL correlation/replay.
Network isolation and absence of host mounts contain the research run; they do
not demonstrate that a parser never attempted a forbidden resource access.
Independent file/network observers, hostile-input controls, native advisory/license
review and focused independent security review remain required. See the
[prior assessment](../../../../docs/research/saml-assessment.md).

The separate [parser-defaults probe](parser-probe/README.md) now supplies bounded
direct-parser observations and independent positive file/network controls. It
reproduces permissive XML acceptance, not SAML authentication. Other signature/
canonicalization/resource paths remain open; the historical upstream result above
is unchanged.

The [signature-engine probe](signature-probe/README.md) adds generated strong
signed Response controls, trust/unsigned/tamper/digest negatives and verified
content observations in both nonlegacy reduction modes. It reproduces six
XML-policy failures; its completed execution does not clear the SAML gate.

Do not copy upstream fixture/private-key files or raw protocol payloads into this
repository or reports. Keep new reports finite and sanitized; preserve historical
records. Only the temporary build context contains upstream source. The context
allowlist excludes unrelated host files, and execution mounts no host source or
credentials. No host libraries or system trust settings are modified.
