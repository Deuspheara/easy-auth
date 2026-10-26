FROM rust:1.95.0-slim-trixie@sha256:e14e87345b4d5964ddcc3491d27ee046a0f23820f340c3c1e24da6880141f7c0 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY .cargo/config.toml .cargo/config.toml
COPY apps apps
COPY crates crates
COPY third-party third-party
RUN CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 cargo build --locked --release -p easy-auth-server --bin easy-auth

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:83b9b50586253821cf63ffcec87d3d94265a093ad30da232039af962dd8f4edf
COPY --from=build /src/target/release/easy-auth /usr/local/bin/easy-auth
COPY docs/security/third-party-licenses /usr/share/doc/easy-auth/licenses
COPY LICENSE-MIT LICENSE-APACHE /usr/share/doc/easy-auth/
USER 65532:65532
ENV AUTH_BIND=0.0.0.0:8080
EXPOSE 8080
# Probe /healthz and /readyz over HTTP from the orchestrator. No shell/curl runtime.
ENTRYPOINT ["/usr/local/bin/easy-auth"]
