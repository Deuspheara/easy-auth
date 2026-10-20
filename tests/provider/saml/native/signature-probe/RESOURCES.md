# Observed resources during signature and reduction calls

AUTH-32 research only. This extends the [signed-content assessment](README.md)
with a separate bounded observer; no production verifier or ACS is selected.
Build the source-pinned native, parser and signature images first, then:

```sh
docker build --platform linux/arm64 --network none -f tests/provider/saml/native/signature-probe/resource.Dockerfile --build-arg PARSER_IMAGE=easy-auth-saml-parser-assessment --build-arg SIGNATURE_IMAGE=easy-auth-saml-signature-assessment -t easy-auth-saml-signature-resources tests/provider/saml/native/signature-probe
resource_image=$(docker image inspect --format '{{.Id}}' easy-auth-saml-signature-resources)
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --cpus 2 --memory 3g --tmpfs /tmp:rw,nosuid,nodev,size=128m "$resource_image"
```

The image reuses the existing parser observer and independent file/HTTP-control
executable from the parser image. Their fingerprints match the earlier parser
record. The resource image inherits the verified signature-image layers and uses
the same unchanged candidate source/lockfile/native libraries. Builds are offline;
no host files or credentials are mounted.

The existing `strace` observer follows only the signature child and descendants.
The child creates ephemeral signed fixtures, then invokes the same engine and
explicit RSA-SHA256/SHA-256 allowlist in both reduction modes. Healthy signed
Response/Assertion controls surround six bounded DTD/entity variants. Entity
references are inserted into the signed subject, so native canonicalization is
an intended evaluation boundary; opaque errors do not prove which internal stage
completed. No custom verifier is used.

An independent loopback HTTP trap and syscall counts cover actual sentinel-file,
connection and HTTP accesses. The existing direct-parser/file/HTTP controls must
work before and after the signed-input child. The five-second child deadline,
two-second post-kill reap bound and trap cleanup come from the existing observer.
Counts aggregate fixture generation, verification and reduction over the child;
they are not attributed to individual cases or internal parser stages.

The [finite record](../results/2026-10-20/signature-resource-observation.json)
contains 20 case/mode rows and working before/after controls. Both modes pass the
healthy signed Response and Assertion controls. The child records zero sentinel
file calls, connection calls and HTTP requests. **Exit 1 remains a failure:**

- DOCTYPE, external DTD and parameter-entity inputs are accepted in both modes:
  six strict XML-policy failures.
- Internal, file and HTTP entity references return six opaque engine errors.
  These remain unresolved; they are not counted as successful security rejections.

Zero observed access applies only to these inputs on this native stack. It is not
general XXE safety or proof that every transform/fragment path denies resources.
No authentication bypass, full SAML profile or application/DB acceptance is claimed.

An actual missing-observer control:

```sh
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --cpus 2 --memory 3g --tmpfs /tmp:rw,nosuid,nodev,size=128m --env PATH=/nonexistent --entrypoint /usr/bin/python3 "$resource_image" /work/resource_observe.py
```

That command exits 2 with `infrastructure_failed` and no rejection observations.
A subsequent normal run reproduces the original outcomes and counts. Eight
reporting tests pass, covering failed positives, incomplete IPC, opaque engine
errors and resource calls that prevent a passing report. Mocked reporting tests
provide no cryptographic or resource-access evidence. Run them with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/provider/saml/native/signature-probe -v
docker run --rm -i --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --cpus 2 --memory 3g --entrypoint sh "$resource_image" -c 'rustup component add clippy </dev/null && python3 - --resources' < tests/provider/saml/native/signature-probe/lint.py
```

Owned strict Clippy passes with no diagnostics; full upstream Clippy separately
retains its 20 unchanged diagnostics and exit 101. No warning exemption or upstream
patch is applied. Component fetching is confined to a disposable online container;
Cargo compilation is offline. The new resource binary's no-argument path also
reproduces all 56 earlier signature outcomes unchanged.

Strict XML/resource policy, opaque error review, broader hostile/transform/profile
coverage, native advisory/license review, SAML PostgreSQL acceptance and independent
security review remain gates. Full application regression remains the previous
97/639-test real-PostgreSQL checkpoint at `4e912ba`; it is not rerun for these
isolated research inputs and reporting changes.
