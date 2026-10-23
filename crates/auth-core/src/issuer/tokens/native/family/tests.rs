use super::*;
use crate::{IssuerAuthority, IssuerClientRegistration, IssuerNativeRefreshPolicy, Secret};
use uuid::Uuid;

fn data() -> IssuerNativeRefreshData {
    let realm = Uuid::new_v4();
    let policy = IssuerNativeRefreshPolicy::new(
        IssuerAuthority::new(realm, "https://issuer.example").unwrap(),
        IssuerClientRegistration::public_native_refresh_loopback(
            realm,
            Uuid::new_v4(),
            &["http://127.0.0.1/cb"],
        )
        .unwrap(),
        3600,
        600,
    )
    .unwrap();
    IssuerNativeRefreshData {
        policy,
        family_id: Uuid::new_v4(),
        subject: Uuid::new_v4(),
        generation: 1,
        prepared_at_us: 1_000_000,
        source_absolute_cap_us: 4_000_000_000,
        family_expires_at_us: 3_601_000_000,
        issued_at_us: 10_000_000,
        access_expires_at_us: 310_000_000,
        refresh_expires_at_us: 610_000_000,
        checked_at_us: 11_000_000,
    }
}

#[test]
fn committed_credentials_refuse_mismatched_authority_or_client_and_invalid_caps() {
    let expected = data();
    let foreign =
        IssuerAuthority::new(Uuid::new_v4(), expected.policy.authority().issuer()).unwrap();
    assert!(
        IssuerNativeRotatedTokens::committed(
            data(),
            &foreign,
            expected.policy.client(),
            Secret::generate().unwrap(),
            Secret::generate().unwrap()
        )
        .is_err()
    );
    for change in 0..10 {
        let mut value = data();
        let policy = value.policy.clone();
        match change {
            0 => value.generation = 0,
            1 => value.generation = MAX_ISSUER_NATIVE_REFRESH_GENERATION + 1,
            2 => value.family_expires_at_us += 1,
            3 => value.refresh_expires_at_us = value.family_expires_at_us + 1,
            4 => value.access_expires_at_us += 1,
            5 => value.refresh_expires_at_us += 1,
            6 => value.checked_at_us = value.access_expires_at_us,
            7 => value.issued_at_us = value.checked_at_us + 1,
            8 => value.subject = Uuid::nil(),
            _ => value.family_id = Uuid::nil(),
        }
        assert!(
            IssuerNativeRotatedTokens::committed(
                value,
                policy.authority(),
                policy.client(),
                Secret::generate().unwrap(),
                Secret::generate().unwrap()
            )
            .is_err(),
            "reject malformed case {change}"
        );
    }
    let value = data();
    let policy = value.policy.clone();
    let result = IssuerNativeRotatedTokens::committed(
        value,
        policy.authority(),
        policy.client(),
        Secret::generate().unwrap(),
        Secret::generate().unwrap(),
    )
    .unwrap();
    assert_eq!(result.expires_in(), 299);
    assert_eq!(result.refresh_expires_in(), 599);
    assert_eq!(
        format!("{result:?}"),
        "IssuerNativeRotatedTokens([REDACTED])"
    );
}
