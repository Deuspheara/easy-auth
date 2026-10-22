use super::super::{setup::Fixture, signed_idp};
use super::setup::{allow_jit, facts, fixture};
use auth_core::{Error, SamlResponseVerifier, SamlSignIn, VerifiedSamlAssertion};
use saml_rs::{Attribute, AttributeValue, Attributes, RespondSso};
use sqlx::PgPool;

async fn verify(f: &Fixture, subject: &str, presentation: &str) -> VerifiedSamlAssertion {
    let start = f.flow.start().await.unwrap();
    let attributes = Attributes::new(vec![
        Attribute::new(
            "email",
            Some("urn:example:one".into()),
            vec![AttributeValue::new("same@example.test")],
        ),
        Attribute::new(
            "email",
            Some("urn:example:two".into()),
            vec![AttributeValue::new("other@example.test")],
        ),
        Attribute::new("displayName", None, vec![AttributeValue::new(presentation)]),
        Attribute::new(
            "role",
            Some(String::new()),
            vec![AttributeValue::new("admin"), AttributeValue::new("admin")],
        ),
    ]);
    let input = signed_idp::response_with(
        f,
        &start,
        subject,
        RespondSso::post()
            .sign_response()
            .apply_web_browser_sso_generation_rules()
            .attributes(attributes),
    );
    let prepared = f
        .flow
        .prepare_response(
            start.request_id(),
            start.relay_state(),
            start.browser_proof(),
        )
        .await
        .unwrap();
    SamlResponseVerifier::new(f.registration.clone(), f.store.clone())
        .unwrap()
        .verify(prepared, input)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn signed_attribute_projection_is_exact_redacted_and_cannot_override_deny(pool: PgPool) {
    let (f, policy) = fixture(pool).await;
    let proof = verify(&f, "normal", "ordinary-presentation").await;
    let attributes = proof.attributes();
    assert_eq!(attributes.len(), 4);
    assert_eq!(attributes[0].name(), "email");
    assert_eq!(attributes[0].name_format(), Some("urn:example:one"));
    assert_eq!(attributes[1].name_format(), Some("urn:example:two"));
    assert_eq!(attributes[2].name_format(), None);
    assert_eq!(attributes[3].name_format(), Some(""));
    assert_eq!(attributes[3].values(), &["admin", "admin"]);
    assert_eq!(format!("{:?}", attributes[0]), "SamlAttribute([REDACTED])");
    assert_eq!(facts(&f).await, (0, 0, 0, 0, 0));
    assert!(matches!(
        SamlSignIn::new(f.store.clone())
            .finish(policy.map(proof).unwrap())
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(facts(&f).await, (0, 0, 0, 0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn identical_email_attributes_never_merge_subjects_or_cross_registered_realms(pool: PgPool) {
    let (mut f, policy) = fixture(pool.clone()).await;
    let policy = allow_jit(&mut f, &policy).await;
    let service = SamlSignIn::new(f.store.clone());
    let (first, _) = service
        .finish(
            policy
                .map(verify(&f, "first-subject", "Initial label").await)
                .unwrap(),
        )
        .await
        .unwrap();
    let (again, _) = service
        .finish(
            policy
                .map(verify(&f, "first-subject", "Changed label").await)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first, again);
    assert_eq!(first.display_name.as_deref(), Some("first-subject"));
    assert_eq!(first.email, None);
    let (second, _) = service
        .finish(
            policy
                .map(verify(&f, "second-subject", "Initial label").await)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(second.email, None);
    let (_, foreign_policy) = fixture(pool).await;
    assert!(matches!(
        foreign_policy.map(verify(&f, "first-subject", "Initial label").await),
        Err(Error::Unauthorized)
    ));
    assert_eq!(facts(&f).await, (2, 2, 3, 6, 3));
}
