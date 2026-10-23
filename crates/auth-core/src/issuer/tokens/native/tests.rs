use super::*;
use crate::{IssuerAuthority, IssuerClientRegistration};
use uuid::Uuid;

#[test]
fn offline_policy_requires_explicit_native_profile_same_realm_and_bounded_lifetimes() {
    let realm = Uuid::new_v4();
    let id = Uuid::new_v4();
    let authority = IssuerAuthority::new(realm, "https://issuer.example").unwrap();
    let native = IssuerClientRegistration::public_native_refresh_loopback(
        realm,
        id,
        &["http://127.0.0.1:41001/cb"],
    )
    .unwrap();
    for client in [
        IssuerClientRegistration::public(realm, id, &["https://app.example/cb"]).unwrap(),
        IssuerClientRegistration::public_native_loopback(realm, id, &["http://127.0.0.1/cb"])
            .unwrap(),
        IssuerClientRegistration::public_native_refresh_loopback(
            Uuid::new_v4(),
            id,
            &["http://127.0.0.1/cb"],
        )
        .unwrap(),
    ] {
        assert!(IssuerNativeRefreshPolicy::new(authority.clone(), client, 3600, 600).is_err());
    }
    for (lifetime, idle) in [
        (0, 1),
        (1, 0),
        (1, 2),
        (MAX_NATIVE_REFRESH_LIFETIME_SECONDS + 1, 1),
        (
            MAX_NATIVE_REFRESH_LIFETIME_SECONDS,
            MAX_NATIVE_REFRESH_IDLE_SECONDS + 1,
        ),
    ] {
        assert!(
            IssuerNativeRefreshPolicy::new(authority.clone(), native.clone(), lifetime, idle)
                .is_err()
        );
    }
    let policy = IssuerNativeRefreshPolicy::new(
        authority.clone(),
        native.clone(),
        MAX_NATIVE_REFRESH_LIFETIME_SECONDS,
        MAX_NATIVE_REFRESH_IDLE_SECONDS,
    )
    .unwrap();
    assert!(!native.supports_online_authorization());
    let pkce = crate::IssuerPkceVerifier::parse("a".repeat(43)).unwrap();
    for scope in ["openid", "openid offline_access"] {
        assert!(
            crate::IssuerAuthorizationRequest::new(
                authority.clone(),
                native.clone(),
                &crate::IssuerAuthorizationInput {
                    client: id,
                    response_type: "code",
                    redirect_uri: "http://127.0.0.1:41002/cb",
                    scope,
                    state: "owned-state",
                    nonce: "owned-nonce",
                    code_challenge: &pkce.challenge(),
                    code_challenge_method: "S256",
                }
            )
            .is_err()
        );
    }
    assert!(native.permits_redirect("http://127.0.0.1:65535/cb"));
    for uri in [
        "http://localhost:41001/cb",
        "http://[::1]:41001/cb",
        "http://127.0.0.1:41001/other",
        "https://127.0.0.1:41001/cb",
    ] {
        assert!(!native.permits_redirect(uri));
    }
    assert_ne!(policy.reconfigured().revision(), policy.revision());
    assert!(policy.with_persisted_revision(Uuid::nil()).is_err());
}

#[test]
fn offline_absolute_expiry_cannot_exceed_original_source_or_configured_cap() {
    let realm = Uuid::new_v4();
    let policy = IssuerNativeRefreshPolicy::new(
        IssuerAuthority::new(realm, "https://issuer.example").unwrap(),
        IssuerClientRegistration::public_native_refresh_loopback(
            realm,
            Uuid::new_v4(),
            &["http://[::1]/return"],
        )
        .unwrap(),
        3600,
        600,
    )
    .unwrap();
    assert_eq!(policy.grant_expires_at_us(100, 500).unwrap(), 500);
    assert_eq!(
        policy.grant_expires_at_us(100, i64::MAX).unwrap(),
        3_600_000_100
    );
    for (consent, cap) in [(-1, 100), (100, 100), (100, 99), (i64::MAX - 1, i64::MAX)] {
        assert!(policy.grant_expires_at_us(consent, cap).is_err());
    }
}
