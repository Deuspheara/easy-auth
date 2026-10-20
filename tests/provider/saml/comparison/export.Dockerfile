ARG RESOURCE_IMAGE=easy-auth-saml-signature-resources
FROM ${RESOURCE_IMAGE}
COPY native/signature-probe/resource_main.rs /work/source/examples/auth32_corpus_export/main.rs
COPY native/signature-probe/fixture.rs native/signature-probe/cases.rs native/signature-probe/assertion_cases.rs native/signature-probe/resource_cases.rs /work/source/examples/auth32_corpus_export/
COPY comparison/native_export.rs /work/source/examples/auth32_corpus_export/engine.rs
COPY comparison/native_replay.rs /work/source/examples/auth32_native_replay/main.rs
COPY native/signature-probe/fixture.rs native/signature-probe/engine.rs native/signature-probe/cases.rs native/signature-probe/assertion_cases.rs /work/source/examples/auth32_native_replay/
COPY comparison/profile_control.rs /work/source/examples/auth32_profile_export/main.rs
COPY comparison/native_export.rs /work/source/examples/auth32_profile_export/engine.rs
RUN cargo build --locked --offline --features xmlsec --example auth32_corpus_export --example auth32_native_replay --example auth32_profile_export
ENTRYPOINT ["/work/target/debug/examples/auth32_corpus_export"]
CMD []
