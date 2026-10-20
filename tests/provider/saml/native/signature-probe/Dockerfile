ARG NATIVE_IMAGE=easy-auth-saml-native-assessment
FROM ${NATIVE_IMAGE}
COPY main.rs fixture.rs engine.rs cases.rs assertion_cases.rs /work/source/examples/auth32_signature_probe/
RUN cargo build --locked --offline --features xmlsec --example auth32_signature_probe --message-format=json > /work/signature-artifacts.json
COPY observe.py /work/signature-observe.py
ENTRYPOINT ["python3", "/work/signature-observe.py"]
CMD []
