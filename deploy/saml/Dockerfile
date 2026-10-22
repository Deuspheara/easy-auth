# syntax=docker/dockerfile:1
# Build SAML support without opening the source-locked production gate.
FROM rust:1.95.0-slim-trixie@sha256:e14e87345b4d5964ddcc3491d27ee046a0f23820f340c3c1e24da6880141f7c0 AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends cmake libssl-dev pkg-config python3 \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY .cargo/config.toml .cargo/config.toml
COPY apps apps
COPY crates crates
COPY third-party third-party
COPY scripts/check_saml_source.py scripts/check_saml_source.py
COPY scripts/qualify_saml_dependency.py scripts/qualify_saml_c14n.py scripts/
COPY tests/provider/saml/rust-policy/patches tests/provider/saml/rust-policy/patches
RUN python3 scripts/check_saml_source.py
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=easy-auth-release-trixie,target=/src/target \
    CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 cargo build --locked --release \
      -p easy-auth-server --bin easy-auth --features saml-web,oidc-web \
    && mkdir /out && cp target/release/easy-auth /out/easy-auth \
    && rustc -vV > /out/build.txt \
    && dpkg-query -W -f='${binary:Package}=${Version}\n' cmake gcc libssl-dev libc6-dev >> /out/build.txt
COPY tests/support tests/support
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=easy-auth-release-trixie,target=/src/target \
    CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 python3 scripts/qualify_saml_c14n.py \
    && cp target/saml-c14n-qualification.json /out/qualification.json
COPY scripts/record_saml_native.py scripts/record_saml_native.py
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    PYTHONPATH=scripts python3 -c 'import json; from record_saml_native import aws_lc_source; record=json.load(open("/out/qualification.json")); print(json.dumps(aws_lc_source(record)))' > /out/native-source.json \
    && sha256sum /usr/lib/*-linux-gnu/libcrypto.so.3 /usr/lib/*-linux-gnu/libssl.so.3 > /out/native-libraries.sha256
COPY scripts/record_saml_build.py scripts/record_saml_build.py
COPY deploy/saml deploy/saml
RUN python3 scripts/record_saml_build.py > /out/source-inputs.json

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:83b9b50586253821cf63ffcec87d3d94265a093ad30da232039af962dd8f4edf
ARG SOURCE_REVISION
LABEL org.opencontainers.image.source="https://github.com/Deuspheara/easy-auth" \
      org.opencontainers.image.revision="$SOURCE_REVISION" \
      org.opencontainers.image.title="easy-auth gated SAML reference release" \
      io.easy-auth.saml-activation="source-disabled"
COPY --from=build /out/easy-auth /usr/local/bin/easy-auth
COPY --from=build /out/build.txt /usr/share/doc/easy-auth/build.txt
COPY --from=build /out/qualification.json /usr/share/doc/easy-auth/qualification.json
COPY --from=build /out/native-source.json /out/native-libraries.sha256 /usr/share/doc/easy-auth/
COPY --from=build /out/source-inputs.json /usr/share/doc/easy-auth/source-inputs.json
COPY docs/security/third-party-licenses /usr/share/doc/easy-auth/licenses
COPY LICENSE-MIT LICENSE-APACHE /usr/share/doc/easy-auth/
USER 65532:65532
# Application defaults keep providers disabled and bind loopback. The reference
# Compose configuration supplies the private bind and explicit production flags.
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/easy-auth"]
