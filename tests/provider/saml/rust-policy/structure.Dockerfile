# Extend only the already assessed exact-policy source and locked dependencies.
ARG POLICY_IMAGE=easy-auth-auth32-rust-policy:assessment
FROM ${POLICY_IMAGE}
RUN echo "bc7de003df7f6c839154fd009d0939443f6db25b6798e63daa580452ed3c1e7e  /work/rust-source/src/xml/dom.rs" | sha256sum --check -
COPY 0003-reject-unclosed-document.patch /work/patches/
RUN patch --batch --fuzz=0 -p1 < /work/patches/0003-reject-unclosed-document.patch
RUN cargo build --locked --offline --no-default-features --features crypto-aws-lc --example auth32_policy
RUN cargo test --locked --offline --no-default-features --features crypto-aws-lc -p saml-rs > /work/structure-tests.log 2>&1
COPY observe.py /work/policy_observe.py
COPY structure_observe.py /work/structure_observe.py
ENTRYPOINT ["python3", "/work/structure_observe.py"]
