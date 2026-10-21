use super::{
    delivery_setup as delivery,
    setup::{allow_jit, facts, fixture},
};
use auth_core::{Error, SamlSignIn};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn repeated_signed_delivery_is_rejected_across_client_and_registration_revision(
    pool: PgPool,
) {
    let (mut f, policy) = fixture(pool).await;
    let policy = allow_jit(&mut f, &policy).await;
    let message = delivery::first(&f, &policy).await;
    let service = SamlSignIn::new(f.store.clone());
    service.finish(message.first).await.unwrap();
    let other = delivery::other_client(&f).await;
    let next = f
        .store
        .configure_saml_identity_policy(&other, &super::super::signed_idp::trust())
        .await
        .unwrap();
    assert_ne!(
        other.registration().revision(),
        next.registration().revision()
    );
    let repeated = delivery::repeated(&f, &next, &message.request_id, &message.encoded).await;
    assert!(matches!(
        service.finish(repeated).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(facts(&f).await, (1, 1, 1, 2, 1));
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_database_commits_of_one_signed_delivery_have_exactly_one_winner(pool: PgPool) {
    let (mut f, policy) = fixture(pool).await;
    let policy = allow_jit(&mut f, &policy).await;
    let message = delivery::first(&f, &policy).await;
    let other = delivery::other_client(&f).await;
    // Both concrete signature verifications finish sequentially before this race.
    let repeated = delivery::repeated(&f, &other, &message.request_id, &message.encoded).await;
    let service = SamlSignIn::new(f.store.clone());
    let (a, b) = tokio::join!(service.finish(message.first), service.finish(repeated));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(matches!(a.err().or(b.err()), Some(Error::Unauthorized)));
    assert_eq!(facts(&f).await, (1, 1, 1, 2, 1));
}
