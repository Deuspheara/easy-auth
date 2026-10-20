ARG NATIVE_IMAGE=easy-auth-saml-native-assessment
FROM ${NATIVE_IMAGE}
COPY parser-probe.rs /work/source/examples/auth32_parser_probe.rs
RUN cargo build --locked --offline --example auth32_parser_probe --message-format=json > /work/parser-artifacts.json
COPY observe.py /work/observe.py
ENTRYPOINT ["python3", "/work/observe.py"]
CMD []
