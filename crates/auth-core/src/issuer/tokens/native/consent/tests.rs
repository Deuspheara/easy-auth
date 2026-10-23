use super::*;
use crate::{
    IssuerAuthority, IssuerAuthorizationInput, IssuerAuthorizationRequest,
    IssuerClientRegistration, IssuerNativeRefreshPolicy, IssuerPkceVerifier,
};
use uuid::Uuid;

fn policy() -> IssuerNativeRefreshPolicy {
    let realm = Uuid::new_v4();
    IssuerNativeRefreshPolicy::new(
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
    .unwrap()
}
#[test]
fn native_consent_requires_explicit_prompt_exact_scope_and_same_existing_code_bindings() {
    let policy = policy();
    let pkce = IssuerPkceVerifier::parse("a".repeat(43)).unwrap();
    for (scope, prompt, redirect, valid) in [
        (
            "openid offline_access",
            "consent",
            "http://127.0.0.1:41002/cb",
            true,
        ),
        ("openid", "consent", "http://127.0.0.1:41002/cb", false),
        (
            "openid offline_access",
            "none",
            "http://127.0.0.1:41002/cb",
            false,
        ),
        (
            "openid offline_access",
            "consent",
            "http://localhost:41002/cb",
            false,
        ),
        (
            "offline_access openid",
            "consent",
            "http://127.0.0.1:41002/cb",
            false,
        ),
    ] {
        let input = IssuerAuthorizationInput {
            client: policy.client().client(),
            response_type: "code",
            redirect_uri: redirect,
            scope,
            state: "state",
            nonce: "nonce",
            code_challenge: &pkce.challenge(),
            code_challenge_method: "S256",
        };
        assert!(
            IssuerAuthorizationRequest::new(
                policy.authority().clone(),
                policy.client().clone(),
                &input
            )
            .is_err()
        );
        let native = IssuerNativeAuthorizationRequest::new(
            policy.clone(),
            &IssuerNativeAuthorizationInput {
                authorization: input,
                prompt,
            },
        );
        assert_eq!(native.is_ok(), valid);
        if let Ok(request) = native {
            assert_eq!(request.code().redirect_uri(), redirect);
            assert_eq!(request.policy(), &policy);
        }
    }
}
#[test]
fn consent_port_facts_cannot_widen_proposal_change_audience_or_invent_an_approval() {
    let policy = policy();
    let prepared = 1_000_000;
    let source_cap = 10_000_000_000;
    let mut data = IssuerNativeConsentData {
        grant_expires_at_us: policy.grant_expires_at_us(prepared, source_cap).unwrap(),
        policy: policy.clone(),
        prepared_at_us: prepared,
        source_absolute_cap_us: source_cap,
        approved_at_us: None,
    };
    assert!(
        data.validate(policy.authority(), policy.client(), 2_000_000, false)
            .is_ok()
    );
    assert!(
        data.validate(policy.authority(), policy.client(), 2_000_000, true)
            .is_err()
    );
    assert!(
        data.validate(
            policy.authority(),
            policy.client(),
            prepared + 301_000_000,
            false
        )
        .is_err()
    );
    let alien = IssuerAuthority::new(Uuid::new_v4(), policy.authority().issuer()).unwrap();
    assert!(
        data.validate(&alien, policy.client(), 2_000_000, false)
            .is_err()
    );
    data.grant_expires_at_us += 1;
    assert!(
        data.validate(policy.authority(), policy.client(), 2_000_000, false)
            .is_err()
    );
    data.grant_expires_at_us -= 1;
    data.approved_at_us = Some(1_100_000);
    assert!(
        data.validate(policy.authority(), policy.client(), 2_000_000, false)
            .is_err()
    );
    assert!(
        data.validate(policy.authority(), policy.client(), 2_000_000, true)
            .is_ok()
    );
    assert!(
        data.validate(policy.authority(), policy.client(), 62_000_000, true)
            .is_err()
    );
}
