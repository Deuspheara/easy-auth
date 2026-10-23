use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn two_real_realms_with_same_client_id_cannot_select_the_others_consent_or_owner(
    pool: PgPool,
) {
    let a = Fixture::new(pool.clone()).await;
    let b = Fixture::with_client(pool, Some(a.base.client.client())).await;
    assert_eq!(a.base.client.client(), b.base.client.client());
    assert_ne!(a.base.realm, b.base.realm);
    let (ap, preview) = a.prepare().await;
    let (bp, bpreview) = b.prepare().await;
    for (target, proofs, operation) in [
        (&b, &ap, &preview["authorization"]),
        (&a, &bp, &bpreview["authorization"]),
    ] {
        assert_eq!(
            target
                .send("approve", &json!({"authorization":operation}), proofs)
                .await
                .status(),
            401
        );
        assert_eq!(
            target.send("resume", &json!({}), proofs).await.status(),
            401
        );
    }
    assert_eq!(a.facts().await, (1, 1, 0, 0));
    assert_eq!(b.facts().await, (1, 1, 0, 0));
    assert_eq!(
        a.send(
            "approve",
            &json!({"authorization":preview["authorization"]}),
            &ap
        )
        .await
        .status(),
        200
    );
    assert_eq!(
        b.send(
            "cancel",
            &json!({"authorization":bpreview["authorization"]}),
            &bp
        )
        .await
        .status(),
        200
    );
    assert_eq!(a.facts().await, (1, 1, 0, 1));
    assert_eq!(b.facts().await, (0, 0, 0, 0));
}
