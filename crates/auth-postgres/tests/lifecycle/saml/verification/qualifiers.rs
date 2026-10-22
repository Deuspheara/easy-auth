use super::super::signed_idp::{fixture, response_from};
use auth_core::{Error, SamlResponseVerifier};
use saml_rs::{NameId, NameIdFormat};
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn ordinary_signed_nameid_qualifiers_retain_exact_registered_namespaces(pool: PgPool) {
    let f = fixture(pool).await;
    let verifier = SamlResponseVerifier::new(f.registration.clone(), f.store.clone()).unwrap();
    let idp = f.registration.idp_entity();
    let sp = f.registration.sp_entity();
    // Ordinary typed IdP inputs, signed by the existing producer. No XML edits
    // or signature internals: the production verifier must receive these fields.
    for (name, service, provided, accepted) in [
        (None, None, None, true),
        (Some(idp), Some(sp), None, true),
        (Some(idp), None, None, true),
        (None, Some(sp), None, true),
        (Some("urn:example:other-idp"), Some(sp), None, false),
        (Some(idp), Some("urn:example:other-sp"), None, false),
        (Some(idp), Some(sp), Some("ordinary-alias"), false),
    ] {
        let start = f.flow.start().await.unwrap();
        let input = response_from(
            &f,
            &start,
            NameId::with_qualifiers(
                "normal",
                Some(NameIdFormat::Persistent),
                name.map(str::to_owned),
                service.map(str::to_owned),
                provided.map(str::to_owned),
            ),
            idp,
            Duration::from_secs(180),
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
        let result = verifier.verify(prepared, input).await;
        if accepted {
            assert_eq!(result.unwrap().subject(), "normal");
        } else {
            assert!(matches!(result, Err(Error::Unauthorized)));
        }
    }
}
