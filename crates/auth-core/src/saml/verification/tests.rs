use super::{SamlPostResponse, input::MAX_POST_RESPONSE_BYTES, timing};
use crate::Error;
use saml_rs::SamlInstant;

#[test]
fn post_input_is_bounded_and_redacted_before_protocol_decoding() {
    for value in [
        String::new(),
        "a".repeat(MAX_POST_RESPONSE_BYTES + 1),
        "é".into(),
    ] {
        assert!(matches!(
            SamlPostResponse::parse(value),
            Err(Error::InvalidInput)
        ));
    }
    let input = SamlPostResponse::parse("bounded-untrusted-input".into()).unwrap();
    assert_eq!(
        format!("{input:?}"),
        "SamlPostResponse([REDACTED; untrusted])"
    );
}

#[test]
fn signed_instant_conversion_and_strict_age_edges_use_checked_arithmetic() {
    let value = SamlInstant::try_new("2026-10-21T00:00:00.123456Z").unwrap();
    let micros = timing::instant(&value).unwrap();
    assert_eq!(micros, 1_792_540_800_123_456);
    assert_eq!(
        timing::micros(timing::system(micros).unwrap()).unwrap(),
        micros
    );
    assert!(timing::recent(micros, micros, timing::MESSAGE_AGE_US).is_ok());
    assert!(timing::recent(micros, micros - 1, timing::MESSAGE_AGE_US).is_err());
    assert!(
        timing::recent(
            micros,
            micros + timing::MESSAGE_AGE_US,
            timing::MESSAGE_AGE_US
        )
        .is_err()
    );
    assert!(timing::recent(i64::MAX, i64::MAX, timing::MESSAGE_AGE_US).is_err());
    let finer_future = SamlInstant::try_new("2026-10-21T00:00:00.123456001Z").unwrap();
    assert!(timing::recent_instant(&finer_future, micros, timing::MESSAGE_AGE_US).is_err());
    assert!(timing::system(-1).is_err());
}
