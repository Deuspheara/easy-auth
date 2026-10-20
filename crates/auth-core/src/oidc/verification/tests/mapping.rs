use super::setup::Fixture;
use crate::*;
use serde_json::{Value, json};
use uuid::Uuid;

fn policy(connection: OAuthConnection, claim: OidcDisplayNameClaim) -> OidcIdentityPolicy {
    OidcIdentityPolicy::new(connection, &["https://issuer.example"], claim).unwrap()
}

#[tokio::test]
async fn signed_mapping_preserves_subject_deadline_email_and_authentication_provenance() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    for (claim, expected) in [
        (OidcDisplayNameClaim::Subject, "subject"),
        (OidcDisplayNameClaim::Name, "Example Person"),
        (OidcDisplayNameClaim::PreferredUsername, "person"),
    ] {
        let (exchange, mut claims) = f.exchange().await;
        claims["name"] = json!("Example Person");
        claims["preferred_username"] = json!("person");
        claims["email"] = json!("provider-attribute@example.test");
        claims["email_verified"] = json!(true);
        let identity = f
            .verifier
            .verify(exchange, f.key.token(&claims))
            .await
            .unwrap();
        let cap = identity.expires_us();
        let issued = identity.issued_at();
        let mapped = policy(f.store.connection.clone(), claim)
            .map(identity)
            .unwrap();
        assert_eq!(mapped.display_name(), Some(expected));
        assert_eq!(mapped.identity().subject(), "subject");
        assert_eq!(mapped.identity().expires_us(), cap);
        assert_eq!(mapped.identity().issued_at(), issued);
        assert_eq!(mapped.identity().authenticated_at(), None);
        assert_eq!(
            mapped.identity().email(),
            Some("provider-attribute@example.test")
        );
        assert!(mapped.identity().email_verified());
        assert!(matches!(mapped.identity().purpose(), OAuthPurpose::SignIn));
        assert_eq!(mapped.policy().jit(), OidcJitPolicy::Deny);
        assert_eq!(format!("{mapped:?}"), "OidcMappedIdentity([REDACTED])");
    }
}

#[test]
fn issuer_allowlist_is_explicit_bounded_and_exact() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let c = &f.store.connection;
    for issuers in [
        vec![],
        vec!["https://issuer.example/"],
        vec!["https://ISSUER.example"],
        vec!["https://other.example"],
        vec!["https://issuer.example", "https://issuer.example"],
        vec!["https://issuer.example", "http://other.example"],
        vec!["https://issuer.example", "https://other.example/#fragment"],
        vec![
            "https://issuer.example",
            "https://other.example?tenant=other",
        ],
        vec!["https://issuer.example", "https://user@other.example"],
        vec!["https://issuer.example", "https://*.other.example"],
    ] {
        assert!(matches!(
            OidcIdentityPolicy::new(c.clone(), &issuers, OidcDisplayNameClaim::Subject),
            Err(Error::InvalidInput)
        ));
    }
    let mut bounded_issuers = vec![c.issuer().to_owned()];
    bounded_issuers.extend((1..8).map(|i| format!("https://tenant-{i}.example")));
    assert!(
        OidcIdentityPolicy::new(
            c.clone(),
            &bounded_issuers
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            OidcDisplayNameClaim::Subject,
        )
        .is_ok()
    );
    bounded_issuers.push("https://tenant-8.example".to_owned());
    assert!(matches!(
        OidcIdentityPolicy::new(
            c.clone(),
            &bounded_issuers
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            OidcDisplayNameClaim::Subject,
        ),
        Err(Error::InvalidInput)
    ));
    let allowed = OidcIdentityPolicy::new(
        c.clone(),
        &[c.issuer(), "https://other.example/tenant"],
        OidcDisplayNameClaim::Subject,
    )
    .unwrap();
    assert_eq!(
        allowed.allowed_issuers(),
        &[c.issuer(), "https://other.example/tenant"]
    );
    assert_eq!(OidcJitPolicy::default(), OidcJitPolicy::Deny);
    assert_eq!(
        allowed.clone().with_jit(OidcJitPolicy::Allow).jit(),
        OidcJitPolicy::Allow
    );
    assert_eq!(allowed.jit(), OidcJitPolicy::Deny);
}

#[tokio::test]
async fn signed_subject_cannot_cross_realm_connection_client_revision_or_provider_configuration() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let c = &f.store.connection;
    for field in [
        "realm",
        "connection",
        "client",
        "revision",
        "issuer",
        "provider_client",
        "redirect",
        "defense",
    ] {
        let other = OAuthConnection::new(
            if field == "realm" {
                Uuid::new_v4()
            } else {
                c.realm()
            },
            if field == "connection" {
                Uuid::new_v4()
            } else {
                c.connection()
            },
            if field == "client" {
                Uuid::new_v4()
            } else {
                c.client()
            },
            if field == "issuer" {
                "https://other.example"
            } else {
                c.issuer()
            },
            if field == "provider_client" {
                "other-client"
            } else {
                c.provider_client()
            },
            if field == "redirect" {
                "https://app.example/other"
            } else {
                c.redirect()
            },
            if field == "defense" {
                OAuthMixupDefense::DedicatedRedirect
            } else {
                c.defense()
            },
        )
        .unwrap();
        // Constructing trusted configuration deliberately assigns a fresh revision.
        // Even the revision-only case must reject a proof from the original one.
        let mapped_policy = OidcIdentityPolicy::new(
            other.clone(),
            &[other.issuer()],
            OidcDisplayNameClaim::Subject,
        )
        .unwrap();
        let (exchange, claims) = f.exchange().await;
        let identity = f
            .verifier
            .verify(exchange, f.key.token(&claims))
            .await
            .unwrap();
        assert!(
            matches!(mapped_policy.map(identity), Err(Error::Unauthorized)),
            "{field}"
        );
    }
}

#[tokio::test]
async fn unusable_selected_profile_claim_stays_absent_without_subject_username_or_email_fallback() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    for claim in [
        OidcDisplayNameClaim::Name,
        OidcDisplayNameClaim::PreferredUsername,
    ] {
        let field = match claim {
            OidcDisplayNameClaim::Name => "name",
            _ => "preferred_username",
        };
        for value in [
            Value::Null,
            json!(true),
            json!(12),
            json!([]),
            json!({}),
            json!(""),
            json!("   "),
            json!("name\ncontrol"),
            json!("x".repeat(257)),
            json!("é".repeat(129)),
        ] {
            let (exchange, mut claims) = f.exchange().await;
            claims["name"] = json!("otherwise usable name");
            claims["preferred_username"] = json!("otherwise-usable-username");
            claims["email"] = json!("otherwise-usable@example.test");
            claims[field] = value;
            let identity = f
                .verifier
                .verify(exchange, f.key.token(&claims))
                .await
                .unwrap();
            assert_eq!(
                policy(f.store.connection.clone(), claim)
                    .map(identity)
                    .unwrap()
                    .display_name(),
                None
            );
        }
        let (exchange, claims) = f.exchange().await;
        let identity = f
            .verifier
            .verify(exchange, f.key.token(&claims))
            .await
            .unwrap();
        assert_eq!(
            policy(f.store.connection.clone(), claim)
                .map(identity)
                .unwrap()
                .display_name(),
            None
        );
    }
}

#[tokio::test]
async fn unselected_profile_data_is_not_identity_authority_and_unicode_is_byte_bounded() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let (exchange, mut claims) = f.exchange().await;
    claims["name"] = json!("é".repeat(128));
    claims["preferred_username"] = json!({"unusable":"unselected"});
    claims["auth_time"] = claims["iat"].clone();
    let identity = f
        .verifier
        .verify(exchange, f.key.token(&claims))
        .await
        .unwrap();
    let authenticated_at = identity.authenticated_at();
    let mapped = policy(f.store.connection.clone(), OidcDisplayNameClaim::Name)
        .map(identity)
        .unwrap();
    assert_eq!(mapped.display_name().unwrap().len(), 256);
    assert_eq!(mapped.identity().authenticated_at(), authenticated_at);
    assert!(authenticated_at.is_some());
    assert_eq!(mapped.identity().preferred_username(), None);
}

#[tokio::test]
async fn duplicate_signed_profile_claims_are_not_normalized_before_mapping() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    for field in ["name", "preferred_username"] {
        let (exchange, claims) = f.exchange().await;
        let raw = serde_json::to_string(&claims).unwrap();
        let raw = format!(
            "{},\"{field}\":\"first\",\"{field}\":\"second\"}}",
            raw.strip_suffix('}').unwrap()
        );
        let token = OidcIdToken::parse(f.key.raw(raw.as_bytes())).unwrap();
        assert!(matches!(
            f.verifier.verify(exchange, token).await,
            Err(Error::Unauthorized)
        ));
    }
}
