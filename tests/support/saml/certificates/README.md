# Public certificate fixtures

Unmodified public certificate fixtures from saml-rs commit
`3b289001a7a84d5a7ff7af2671991ab7098090bd`, MIT (retained in
`LICENSE.saml-rs`). `idp.cer` is `tests/fixtures/key/idp_cert.cer` and
`rotation.cer` is `tests/fixtures/key/sp_cert.cer` at that commit.

These certificates expired in 2018. Tests use explicit historical approval
windows for configuration and also check refusal at today's time. They contain
no private keys, and tests generate no cryptographic or adversarial fixtures.
