# Disposable container walkthrough

This runs the default email/password/session application with PostgreSQL and
Mailpit. It uses development-only credentials and loopback HTTP. It does not
activate passkeys, providers or the outbound issuer. Production still requires
TLS, protected configuration, operational qualification and the existing release
gates in the [deployment design](../architecture/deployment.md).

## Build committed public source

Use Git, Python 3, Docker with Compose/BuildKit, and a POSIX shell. Export the selected
committed revision instead of building a working directory containing private
research, credentials or local account data:

```sh
revision=$(git rev-parse HEAD)
container_source=$(mktemp -d "${TMPDIR:-/tmp}/easy-auth-container.XXXXXX")
git archive "$revision" | tar -x -C "$container_source"
docker build --tag easy-auth-local:development "$container_source"
docker build --file "$container_source/deploy/saml/proxy.Dockerfile" \
  --tag easy-auth-local-proxy:development "$container_source"
```

The default Dockerfile copies named Rust build inputs and ships license notices.
Its deny-by-default context rules exclude `.env`, research/security packets,
planning, website artifacts and nested key/build directories. Filtering is not a
secret audit: review committed source too. The second build reuses the maintained
nginx runtime; the local Compose file mounts its own fixed HTTP configuration.
It does not enable SAML in the default application.

Cargo resolves the committed lockfile and base images have recorded digests.
Package repositories and advisory databases still change; a source pin alone is
not a byte-for-byte rebuild or an image-security approval. Rebuild and reassess
images rather than transferring an older scan to a new image ID.

## Start a separate development project

```sh
container_project="easy-auth-local-$(date +%s)-$$"
export EASY_AUTH_IMAGE=easy-auth-local:development
export EASY_AUTH_PROXY_IMAGE=easy-auth-local-proxy:development
container_private=$(mktemp -d "${TMPDIR:-/tmp}/easy-auth-local-settings.XXXXXX")
container_environment="$container_private/settings.env"
python3 "$container_source/scripts/write_local_container_environment.py" "$container_environment"
export EASY_AUTH_HTTP_PORT=58418
export EASY_AUTH_MAIL_HTTP_PORT=8026
docker compose --env-file "$container_environment" --project-name "$container_project" \
  --file "$container_source/deploy/local/compose.yaml" up --detach --wait
```

Choose unused loopback ports before starting; leave any retained preview running.
Use a separate browser profile/context: cookies are host-scoped, not port-scoped.
Keep these variables for the backup and cleanup commands. The explicit project
owns its database volume. PostgreSQL and SMTP have no published host port; only
the application and Mailpit HTTP interfaces are published on `127.0.0.1`.
Retain that generated mode 0600 settings file privately for this project's restarts.
It keeps the realm UUID and paired database settings stable. The UUID identifies
the namespace; it is not a credential or proof. Changing it does not migrate users.
Changing the environment value does not rotate a role in an existing PostgreSQL
volume. Use a new disposable project or explicit credential rotation; do not
silently delete a retained volume. The automated smoke always generates its own
password and never uses an operator's existing database credential.

The app/proxy run unprivileged with read-only filesystems, bounded temporary
storage, dropped capabilities and no new privileges. The small mounted password
corpus is public development data and is insufficient for production policy.

Development deliberately requires loopback bind **and** loopback SMTP. App and
proxy share Mailpit's private network namespace: the app listens on 127.0.0.1:8080,
SMTP is 127.0.0.1:1025, and the private proxy forwards the published port to that
listener. There is no host-network mode, relaxed bind check or forwarded-IP trust.
The fixed proxy accepts the configured `127.0.0.1` host, limits request size/time,
and records no raw request/credential logs. See Docker's
[service network mode](https://docs.docker.com/reference/compose-file/services/#network_mode).

## Verify the actual flow

Compose wait confirms processes/dependencies, not application readiness.
Open `http://127.0.0.1:58418/healthz` and `/readyz`: require 200 before continuing. Readiness proves
database startup/migration, not mail or provider delivery. Open the root page,
request a link for a disposable `example.test` address, then select that exact
recipient in `http://127.0.0.1:8026`. Open the link in the requesting browser.
The existing page scrubs the fragment and performs browser-bound completion.
Confirm the actual account view, log out, and require `/v1/session` to return 401.
Adjust these URLs if you selected different ports.

Use the [minimal clients](minimal-clients.md) for a separate Rust public-HTTP
probe and same-origin TypeScript session/sign-in/logout calls. Keep cookies,
mailbox links, passwords and response bodies out of logs and screenshots.
Do not clear admission state or weaken policy to make repeated trials pass.

## Preserve data or clean up

Use the [backup procedure](backups.md) before discarding data you need. This command
removes **only this disposable project**, including its database volume:

```sh
docker compose --env-file "$container_environment" --project-name "$container_project" \
  --file "$container_source/deploy/local/compose.yaml" down --volumes
```

Never substitute another project's name or use global Docker pruning. After
teardown, remove only the temporary source export you created. Images are local
artifacts; no registry push, public hosting or production deployment occurs here.
