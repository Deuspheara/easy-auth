# Disabled SAML reference release

This is a prepared release artifact and candidate operational profile, not
production SAML approval. [ADR0031](../architecture/adr/0031-saml-reference-release-profile.md)
fixes the supported contract. Normal SAML remains disabled in source, image,
Compose and proxy. No approval token or runtime switch can open it.

## Build and identify

The dedicated Dockerfile builds the normal release binary with `saml-web,oidc-web`
and runs the existing selected-graph SAML/core/C14N tests in the native build
environment. It selects pinned Rust1.95.0/Debian13 Trixie bases, current distribution
security packages, the maintained source and unchanged runtime Cargo.lock. The
allowlisted context excludes private drafts/comparison/bounds work and runtime
secrets; public packaged upstream fixtures remain build-only integrity inputs.
Both final images use a pinned Debian13 distroless base with no shell or package manager. The proxy adds only distribution nginx and its required extra libraries, retaining their package/license records. Readiness is checked externally through `/readyz`; no shell/curl health command is shipped.

From a verified source revision:

```sh
docker build -f deploy/saml/Dockerfile --build-arg SOURCE_REVISION=FULL_VERIFIED_COMMIT -t easy-auth-saml-release:review .
docker build -f deploy/saml/proxy.Dockerfile --build-arg SOURCE_REVISION=FULL_VERIFIED_COMMIT -t easy-auth-saml-proxy:review .
python3 scripts/check_saml_release.py --image easy-auth-saml-release:review --proxy-image easy-auth-saml-proxy:review
python3 scripts/scan_saml_release.py --image easy-auth-saml-release:review --proxy-image easy-auth-saml-proxy:review
```

Use the existing owned PostgreSQL setup and `DATABASE_URL`; set
`EASY_AUTH_SMOKE_POSTGRES_CONTAINER` when using the existing container. The checker
creates/drops only its random database and Compose project, records native/package
and resource metadata, checks CLI and closed activation, verifies ordinary database
readiness/absent SAML routes/zero authority creation, and validates nginx syntax
with existing public fixture files. It creates no XML/key fixture, performs no
signature/resource experiment and does not start a public deployment.

`target/saml-release-inventory.json` records the actual architecture/image ID,
release binary hash, packaged native libraries/packages, baked build-input hashes, build toolchain and qualification
receipt. Local Docker image IDs identify local content; they are not invented
registry manifest digests. No image is published by these commands. Promotion
requires recording the actual registry digest and deployment inputs separately.
Preserve failed initial scans/checks alongside final results and their causes.

## Selected single-instance limits

| Boundary | Reference policy |
| --- | --- |
| Composition | One normal app process, one realm/registration, one proxy; no autoscaling |
| App container | 2 CPUs; 1GiB memory; 1GiB combined memory+swap; 128 PIDs; 1024 FDs |
| Proxy container | 0.5 CPU; 128MiB memory; 128MiB combined memory+swap; 64 PIDs; 512 FDs |
| Filesystem/privilege | Non-root65532; read-only root; all capabilities dropped; no-new-privileges; init; 16MiB noexec/nosuid/nodev `/tmp` each |
| Proxy HTTP | One worker/128 connections including upstream sockets; 64 counted HTTP connections; global10 requests/s, burst20 with immediate rejection rather than a delayed rate queue |
| Body/XML | Proxy/router800KiB delivery body; core256KiB encoded response;192KiB decoded XML; depth128 plus existing syntax/attribute/text limits |
| Timeouts | Header/body inactivity10s; send15s; keepalive10s/100 requests; upstream connect3s/send10s/read45s; container stop grace30s |
| Verification | Existing local/composed two operations plus two process-wide native admission permits, retained until actual worker exit |

The configured container limits constrain the whole service, including other auth
features; `/tmp` pages are charged to container memory. HTTP connection counting
starts after headers; it is not a count of every TLS handshake. Body/read/send
timeouts are inactivity limits, not absolute request deadlines. Native admission,
material loading and worker await have separate15s boundaries and cannot kill
native work. An occupied worker keeps its permits after cancellation. No measured
throughput, worst-case CPU/RSS, hard per-job duration or absence of starvation is
claimed. Independent review must accept these residuals or request a separately
authorized change/assurance method. A source semaphore alone cannot budget multiple
replicas or arbitrary embedded service instances.

## Operator inputs and launch restrictions

`deploy/saml/compose.yaml` requires verified immutable app/proxy image identifiers,
a protected raw runtime environment file and operator TLS certificate/key paths.
Keep credentials outside the repository. The runtime file needs the exact realm,
HTTPS public origin, private production database connection and TLS SMTP settings;
the existing application validates these normally. Do not use development Compose
credentials/HTTP/Mailpit for production. Other provider settings remain absent or
explicitly disabled; populated disabled SAML settings still fail closed.

Replace `auth.example.invalid` consistently in the proxy with the exact public
hostname matching `AUTH_PUBLIC_URL` and the certificate. The default virtual host
rejects other hosts. Make mounted TLS files readable by UID65532 without granting
other access to the private key; production files are never fixture keys. The app
has no published host port; the proxy publishes443. The reference network is not
an egress firewall. Operators must restrict database/SMTP and other approved
destinations with their infrastructure controls, protect runtime files/ACLs and
complete backup/restore, cleanup, least-privilege database roles and incident
procedures in [deployment requirements](../architecture/deployment.md).

Keep both explicit SAML proxy route blocks. Keep `AUTH_SAML_ENABLED=false` and the
source approval guard unchanged. A deployment hostname, secret file, persisted
provider enable, compiled feature or CLI setting is not security approval.
`restart: no` makes recovery deliberate. Monitor readiness and sanitized errors;
if native work becomes stuck, an operator may restart the whole bounded process
under the incident procedure. Its durable replay/current-policy/original deadlines
remain mandatory across restart. Do not claim this is per-job containment.

## Advisory and review records

Assess each actual app/proxy image using an established local image scanner and
the distribution's advisory records; retain all severities and unfixed findings.
Do not copy advisory ignores, suppress unfixed findings or equate package name/
version matching with a reachable exploit. Compiled Rust advisory/license checks
remain unchanged. The native AWS-LC source and OpenSSL/distribution package scope
are separately recorded; none supplies FIPS certification or independent approval.

The final review packet must link exact source, platform-specific artifact IDs,
native regression receipts, full scan results/dispositions and enforced limits.
An updated package/base/source/configuration changes that scope. Independent
review/report/findings resolution and explicit approval are still required before
the separate activation change. This preparation creates no PR, publishes no
registry image and contacts no reviewer or upstream maintainer.
