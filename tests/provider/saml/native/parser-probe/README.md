# Observed native parser defaults

AUTH-32 research overlay only. Build the
[source-verified native image](../README.md) first, then:

```sh
docker build --platform linux/arm64 --network none --build-arg NATIVE_IMAGE=easy-auth-saml-native-assessment -t easy-auth-saml-parser-assessment tests/provider/saml/native/parser-probe
probe_image=$(docker image inspect --format '{{.Id}}' easy-auth-saml-parser-assessment)
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --cpus 2 --memory 3g --tmpfs /tmp:rw,nosuid,nodev,size=128m "$probe_image"
```

The owned Rust example calls the pinned `libxml` 0.3.3 `Parser::default()` and
`get_content()` using fixed, bounded synthetic inputs. The same parser interface
appears in the upstream candidate. The example is overlaid into the isolated
upstream checkout; no upstream assertion, fixture or implementation is changed.
It performs no signature verification and imports no account/session authority.

The observer traces only the child process with `strace` and independently counts
requests in an owned loopback HTTP trap. Before and after the eight input cases,
it requires a healthy parse, an actual sentinel-file access and an actual HTTP
request. File/network controls use ordinary Rust I/O, not the parser. The trap is
outside the child, and counters are not set by the probe. Each subprocess group
has a bounded timeout and is killed/reaped on timeout. Trap shutdown is checked.

The [observed run](../results/2026-10-20/parser-defaults-observation.json) exited **1**
with `candidate_policy_gaps_observed`: all eight DTD/entity/malformed inputs were
accepted as XML. The observer saw zero sentinel-file calls, connection calls or
HTTP requests during those inputs; both sets of positive controls worked.
This reproduces the policy gap in permissive defaults. It proves neither an
authentication bypass nor general XXE safety. Signature/canonicalization/reduced-
fragment entry points and broader resource limits remain untested by this probe.

An actual missing-observer fault is checked separately:

```sh
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --cpus 2 --memory 3g --tmpfs /tmp:rw,nosuid,nodev,size=128m --env PATH=/nonexistent --entrypoint /usr/bin/python3 "$probe_image" /work/observe.py
```

That run exited **2**, `infrastructure_failed` / `observer_unavailable`, with no
parser-rejection observations. A subsequent valid run reproduced the original
observations. Failure to trace, missing tools, invalid IPC, timeout or failed
positive controls cannot become a successful security rejection. Exit 0 would
mean only that these bounded parser controls met their stated policy; it would
still not establish SAML acceptance.

Strict Clippy for the full upstream package/example failed on 20 diagnostics in
unchanged upstream library files. This failure is retained. Separately, the owned
probe passed `clippy-driver` with edition 2021, `-W clippy::all -D warnings`, using
the actual compiled `libxml` artifact and dependency search path. No warning
allowlist, assertion change or upstream patch was used. The matching Clippy
component was installed only in disposable lint containers; this tool download
was online, while compilation used locked/offline dependencies. Parser execution
and the probe image build were network-disabled. No host toolchain was changed.

Only finite outcomes, source/binary fingerprints and observer counts are published.
Raw syscall traces, payload contents and foreign errors are not reports. No host
files or credentials are mounted. Native package/advisory/license review, strict
verified-node/profile/algorithm handling, application/PostgreSQL acceptance and
focused independent security review remain gates. No SAML verifier is selected.
