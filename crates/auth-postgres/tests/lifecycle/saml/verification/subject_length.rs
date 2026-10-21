use super::super::signed_idp::{fixture, response};
use auth_core::{Error, SamlResponseVerifier};
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn persistent_subject_character_and_utf8_bounds_apply_to_real_signed_messages(pool: PgPool) {
    let f = fixture(pool).await;
    let verifier = SamlResponseVerifier::new(f.registration.clone(), f.store.clone()).unwrap();
    for (subject, accepted) in [
        ("n".repeat(256), true),
        ("n".repeat(257), false),
        ("💡".repeat(256), true),
    ] {
        let start = f.flow.start().await.unwrap();
        let input = response(&f, &start, &subject, Duration::from_secs(180));
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
            assert_eq!(result.unwrap().subject(), subject);
        } else {
            assert!(matches!(result, Err(Error::Unauthorized)));
        }
    }
}
