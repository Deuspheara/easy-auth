use super::setup::*;
use crate::support::post;
use axum::extract::ConnectInfo;
use sqlx::PgPool;

#[sqlx::test]
async fn apple_private_proofs_precede_exchange_and_actual_source_spends_admission(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    let foreign = f.start().await;
    let raw = f.issue(&a, json!({}), None).await;
    let fields: Vec<_> = a.cookie.split("; ").collect();
    let foreign_fields: Vec<_> = foreign.cookie.split("; ").collect();
    for field in [0, 2, 3] {
        let mut tampered = fields.clone();
        tampered[field] = foreign_fields[field];
        let r = f
            .post("finish", json!({"response":raw}), &tampered.join("; "))
            .await;
        assert_eq!(r.status(), 401);
        no_session(&r);
        assert_eq!(f.facts().await, (0, 0, 0, 0, 2));
    }
    let mut request = post(
        &format!("{ROOT}/finish"),
        &json!({"response":raw}).to_string(),
        Some(&a.cookie),
        Some(ORIGIN),
    );
    // Source addresses key committed abuse admission, not an IP-pinned identity.
    // Keep invalid private proof so this observation cannot consume the control.
    let mut wrong_browser = fields.clone();
    wrong_browser[0] = foreign_fields[0];
    request
        .headers_mut()
        .insert("cookie", wrong_browser.join("; ").parse().unwrap());
    request.extensions_mut().insert(ConnectInfo(
        "192.0.2.9:2345".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let r = f.send(request).await;
    assert_eq!(r.status(), 401);
    no_session(&r);
    let attempts:i32=sqlx::query_scalar("SELECT sum(attempts)::int FROM auth_oauth_admission WHERE realm_id=$1 AND dimension='consume_source' AND key_hash=sha256(sha256(convert_to('192.0.2.9','UTF8')))").bind(f.realm()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(attempts, 1);
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.post("finish", json!({"response":raw}), &a.cookie)
            .await
            .status(),
        204
    );
    assert_eq!(
        f.post("cancel", json!({}), &foreign.cookie).await.status(),
        204
    );
}

#[sqlx::test]
async fn apple_malformed_and_unrecognized_error_fields_leave_proof_untouched(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    for raw in [
        format!(
            "state={}&error=user_cancelled_authorize&error_description=private",
            a.field("state")
        ),
        format!("state={}&id_token=unverified", a.field("state")),
        "%FF".to_owned(),
    ] {
        let r = f.post("finish", json!({"response":raw}), &a.cookie).await;
        assert_eq!(r.status(), 401);
        no_session(&r);
        assert!(r.headers().get_all("set-cookie").iter().next().is_none());
        assert!(!text(r).await.contains("private"));
        assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    }
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    let raw = f.issue(&a, json!({}), None).await;
    assert_eq!(
        f.post("finish", json!({"response":raw}), &a.cookie)
            .await
            .status(),
        204
    );
}
