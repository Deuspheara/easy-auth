use crate::{error::SamlError, model::SamlInstant, xml::parse_generated_saml_utc_date_time};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub(super) fn instant<'a>(
    requested: Option<&'a SamlInstant>,
    issued: &'a str,
) -> Result<&'a str, SamlError> {
    let Some(requested) = requested else {
        return Ok(issued);
    };
    let value = parse_generated_saml_utc_date_time(requested.as_str()).ok_or_else(invalid)?;
    let authenticated = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| invalid())?;
    let issuance = OffsetDateTime::parse(issued, &Rfc3339).map_err(|_| invalid())?;
    if authenticated > issuance {
        return Err(invalid());
    }
    Ok(value)
}

fn invalid() -> SamlError {
    SamlError::Invalid("authentication instant must be valid UTC and no later than issuance".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn established_authentication_is_not_replaced_by_new_issuance() {
        let previous = SamlInstant::try_new("2026-10-21T10:00:00Z").unwrap();
        let issued = "2026-10-21T11:00:00Z";
        assert_eq!(instant(Some(&previous), issued).unwrap(), previous.as_str());
        assert_eq!(instant(None, issued).unwrap(), issued);
    }

    #[test]
    fn malformed_or_future_producer_authentication_is_rejected() {
        for value in ["not-a-date", "2026-10-21T12:00:00Z"] {
            let value = SamlInstant::try_new(value).unwrap();
            assert!(instant(Some(&value), "2026-10-21T11:00:00Z").is_err());
        }
    }
}
