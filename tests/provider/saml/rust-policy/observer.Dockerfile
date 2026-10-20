# Research only; build context is assembled from the exact public source archive.
ARG CORPUS_IMAGE=easy-auth-auth32-corpus:comparison
FROM ${CORPUS_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends cmake patch && rm -rf /var/lib/apt/lists/*
COPY source.tar /work/rust-source.tar
RUN echo "5ac1dc497d608edf2c6b751751a6c86d2b935a6e6e56149c788bfe436198e3e1  /work/rust-source.tar" | sha256sum --check - && mkdir /work/rust-source && tar -xf /work/rust-source.tar -C /work/rust-source && rm /work/rust-source.tar
WORKDIR /work/rust-source
# Fetch unchanged locked dependencies before applying the policy-only source patch.
RUN cargo fetch --locked
COPY 0001-extract-verified-profile.patch 0002-exact-sha256-profile.patch /work/patches/
RUN patch --batch --fuzz=0 -p1 < /work/patches/0001-extract-verified-profile.patch && patch --batch --fuzz=0 -p1 < /work/patches/0002-exact-sha256-profile.patch
COPY exact_candidate.rs /work/rust-source/examples/auth32_policy/main.rs
COPY rust_candidate.rs /work/rust-source/examples/comparison/rust_candidate.rs
ENV CARGO_TARGET_DIR=/work/rust-target
RUN cargo build --locked --offline --no-default-features --features crypto-aws-lc --example auth32_policy
RUN cargo test --locked --offline --no-default-features --features crypto-aws-lc -p saml-rs > /work/policy-tests.log 2>&1
COPY profile_control.rs /work/source/examples/auth32_profile_export/main.rs
RUN CARGO_TARGET_DIR=/work/target cargo build --manifest-path /work/source/Cargo.toml --locked --offline --features xmlsec --example auth32_profile_export
COPY comparison_run.py /work/comparison_run.py
COPY observe.py /work/policy_observe.py
ENTRYPOINT ["python3", "/work/policy_observe.py"]
