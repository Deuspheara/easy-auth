//! Expected protocol issuer policy; signature verification remains delegated.
use crate::{constants::ParserType, error::SamlError, util::Value};

pub(super) fn validate(
    parser: ParserType,
    extracted: &Value,
    expected: Option<&str>,
) -> Result<(), SamlError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if matches!(
        parser,
        ParserType::SamlRequest
            | ParserType::SamlResponse
            | ParserType::LogoutRequest
            | ParserType::LogoutResponse
    ) {
        require(extracted.get_str("issuer"), expected)?;
    }
    if parser == ParserType::SamlResponse {
        // The envelope and consumed Assertion are independently identified.
        // A configured IdP must issue both; an Assertion issuer is not a substitute.
        require(extracted.get_str("responseIssuer"), expected)?;
    }
    Ok(())
}

fn require(actual: Option<&str>, expected: &str) -> Result<(), SamlError> {
    if actual != Some(expected) {
        return Err(SamlError::issuer_mismatch(expected, actual));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(assertion: &str, response: Option<&str>) -> Value {
        let mut fields = vec![("issuer".into(), Value::Str(assertion.into()))];
        if let Some(response) = response {
            fields.push(("responseIssuer".into(), Value::Str(response.into())));
        }
        Value::Object(fields)
    }

    #[test]
    fn response_and_assertion_must_each_name_the_expected_idp() {
        for (assertion, response, accepted) in [
            ("urn:idp", Some("urn:idp"), true),
            ("urn:other", Some("urn:idp"), false),
            ("urn:idp", Some("urn:other"), false),
            ("urn:idp", None, false),
        ] {
            assert_eq!(
                validate(
                    ParserType::SamlResponse,
                    &claims(assertion, response),
                    Some("urn:idp")
                )
                .is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn other_message_issuer_contracts_remain_separate() {
        let fields = claims("urn:idp", None);
        for parser in [
            ParserType::SamlRequest,
            ParserType::LogoutRequest,
            ParserType::LogoutResponse,
        ] {
            assert!(validate(parser, &fields, Some("urn:idp")).is_ok());
        }
        assert!(validate(ParserType::SamlResponse, &fields, None).is_ok());
    }
}
