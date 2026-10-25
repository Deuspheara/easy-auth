use super::*;
use crate::{IssuerAccessData, IssuerAuthority, IssuerClientRegistration, Secret};
use uuid::Uuid;

fn policy() -> IssuerNativeConsumerPolicy {
    let authority = IssuerAuthority::new(Uuid::new_v4(), "https://issuer.example").unwrap();
    let reader = IssuerClientRegistration::confidential(
        authority.realm(),
        Uuid::new_v4(),
        &["https://reader.example/cb"],
        &Secret::generate().unwrap(),
    )
    .unwrap();
    let native = IssuerClientRegistration::public_native_refresh_loopback(
        authority.realm(),
        Uuid::new_v4(),
        &["http://127.0.0.1/cb"],
    )
    .unwrap();
    IssuerNativeConsumerPolicy::new(authority, reader, native).unwrap()
}
#[test]
fn consumer_configuration_requires_distinct_confidential_current_realm_and_native_audience() {
    let p = policy();
    let public = IssuerClientRegistration::public(
        p.authority().realm(),
        Uuid::new_v4(),
        &["https://reader.example/cb"],
    )
    .unwrap();
    assert!(
        IssuerNativeConsumerPolicy::new(
            p.authority().clone(),
            public.clone(),
            p.audience().clone()
        )
        .is_err()
    );
    assert!(
        IssuerNativeConsumerPolicy::new(p.authority().clone(), p.consumer().clone(), public)
            .is_err()
    );
    assert!(
        IssuerNativeConsumerPolicy::new(
            IssuerAuthority::new(Uuid::new_v4(), "https://issuer.example").unwrap(),
            p.consumer().clone(),
            p.audience().clone()
        )
        .is_err()
    );
    assert_ne!(p.reconfigured().revision(), p.revision());
    assert!(p.with_persisted_revision(Uuid::nil()).is_err());
}
#[test]
fn native_active_projection_cannot_substitute_consumer_audience_or_lifetime() {
    let p = policy();
    let data = || IssuerNativeAccessData {
        policy: p.clone(),
        access: IssuerAccessData {
            realm: p.authority().realm(),
            issuer: p.authority().issuer().into(),
            client: p.audience().client(),
            subject: Uuid::new_v4(),
            issued_at_us: 1_000_000,
            expires_at_us: 301_000_000,
            checked_at_us: 2_000_000,
        },
    };
    let active =
        IssuerNativeActiveAccess::from_repository(data(), p.authority(), p.consumer()).unwrap();
    assert_eq!(active.access().client(), p.audience().client());
    assert!(
        IssuerNativeActiveAccess::from_repository(data(), p.authority(), p.audience()).is_err()
    );
    let mut wrong = data();
    wrong.access.client = p.consumer().client();
    assert!(IssuerNativeActiveAccess::from_repository(wrong, p.authority(), p.consumer()).is_err());
    let mut wrong = data();
    wrong.access.expires_at_us += 1;
    assert!(IssuerNativeActiveAccess::from_repository(wrong, p.authority(), p.consumer()).is_err());
    let mut wrong = data();
    wrong.access.checked_at_us = wrong.access.expires_at_us;
    assert!(IssuerNativeActiveAccess::from_repository(wrong, p.authority(), p.consumer()).is_err());
}
