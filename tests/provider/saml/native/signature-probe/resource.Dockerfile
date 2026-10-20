ARG PARSER_IMAGE=easy-auth-saml-parser-assessment
ARG SIGNATURE_IMAGE=easy-auth-saml-signature-assessment
FROM ${PARSER_IMAGE} AS parser
FROM ${SIGNATURE_IMAGE}
# Reuse the already source-pinned observer and independent I/O-control executable.
COPY --from=parser /work/observe.py /work/parser_observe.py
COPY --from=parser /work/parser-artifacts.json /work/parser-artifacts.json
COPY --from=parser /work/target/debug/examples/auth32_parser_probe /work/target/debug/examples/auth32_parser_probe
COPY resource_main.rs /work/source/examples/auth32_signature_resources/main.rs
COPY fixture.rs engine.rs cases.rs assertion_cases.rs resource_cases.rs /work/source/examples/auth32_signature_resources/
RUN cargo build --locked --offline --features xmlsec --example auth32_signature_resources --message-format=json > /work/resource-artifacts.json
COPY observe.py /work/signature_observe.py
COPY resource_observe.py /work/resource_observe.py
ENTRYPOINT ["python3", "/work/resource_observe.py"]
CMD []
