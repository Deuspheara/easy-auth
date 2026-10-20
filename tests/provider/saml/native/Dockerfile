# Upstream research only: no easy-auth runtime dependency or ACS.
FROM rust@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates pkg-config libxml2-dev libxmlsec1-dev libxmlsec1-openssl clang libclang-dev libssl-dev strace python3 && rm -rf /var/lib/apt/lists/*
ENV CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/work/target
COPY source.tar /work/source.tar
RUN echo "68c55b189bcaa0cc15b78f258befdf2b1dc0396e9c1d4bce19190c7c3dc48b24  /work/source.tar" | sha256sum --check - && mkdir /work/source && tar -xf /work/source.tar -C /work/source && rm /work/source.tar
WORKDIR /work/source
RUN cargo test --locked --lib --features xmlsec --no-run --message-format=json > /work/compiler-artifacts.json
COPY run-tests.py /work/run-tests.py
CMD ["python3", "/work/run-tests.py"]
