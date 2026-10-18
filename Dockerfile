FROM rust:1.95-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p easy-auth-server --bin easy-auth

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/easy-auth /usr/local/bin/easy-auth
COPY docs/security/third-party-licenses /usr/share/doc/easy-auth/licenses
USER 65532:65532
ENV AUTH_BIND=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD curl --fail --silent http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/easy-auth"]
