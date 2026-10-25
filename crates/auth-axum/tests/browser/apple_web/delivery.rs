use super::setup::*;
use sqlx::PgPool;

#[sqlx::test]
async fn apple_delivery_never_reads_proofs_or_consumes_state(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    let raw = f
        .issue(
            &a,
            json!({}),
            Some(r#"{"name":{"firstName":"<script>owned-marker</script>"}}"#),
        )
        .await;
    for cookie in ["", a.cookie.as_str(), "__Host-auth-session=invalid"] {
        let r = f.bridge(&raw, cookie).await;
        assert_eq!(r.status(), 200);
        assert!(r.headers().get_all("set-cookie").iter().next().is_none());
        assert_eq!(r.headers()["cache-control"], "no-store");
        assert_eq!(r.headers()["referrer-policy"], "no-referrer");
        let csp = r.headers()["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("script-src 'self'") && !csp.contains("unsafe-inline"));
        let html = text(r).await;
        assert!(html.contains("<template id=\"apple-delivery\" data-response=\""));
        assert!(html.contains("&amp;code="));
        assert!(!html.contains("<script>owned-marker"));
        assert!(html.contains("Confirm Apple return"));
        assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    }
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.post("finish", json!({"response":raw}), &a.cookie)
            .await
            .status(),
        204
    );
}

#[sqlx::test]
async fn apple_delivery_rejects_ambiguous_unbounded_or_query_transport(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let a = f.start().await;
    let valid = f.issue(&a, json!({}), None).await;
    for raw in [
        "".to_owned(),
        format!("{valid}&state={}", a.field("state")),
        format!("{valid}&unknown=private"),
        "a".repeat(32769),
    ] {
        let r = f.bridge(&raw, &a.cookie).await;
        assert!(matches!(r.status().as_u16(), 401 | 413));
        no_session(&r);
        assert!(!text(r).await.contains("private"));
    }
    for (uri, content_type, expected) in [
        (
            "/apple/callback?code=private",
            "application/x-www-form-urlencoded",
            400,
        ),
        ("/apple/callback", "application/json", 415),
    ] {
        let r = f
            .send(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", content_type)
                    .body(Body::from(valid.clone()))
                    .unwrap(),
            )
            .await;
        assert_eq!(r.status(), expected);
    }
    let mut request = Request::builder()
        .method("POST")
        .uri("/apple/callback")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(valid.clone()))
        .unwrap();
    request.headers_mut().append(
        "content-type",
        "application/x-www-form-urlencoded".parse().unwrap(),
    );
    assert_eq!(f.send(request).await.status(), 415);
    assert_eq!(
        f.send(
            Request::builder()
                .uri("/apple/callback")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .status(),
        405
    );
    assert_eq!(f.facts().await, (0, 0, 0, 0, 1));
    assert_eq!(f.provider.posts.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.post("finish", json!({"response":valid}), &a.cookie)
            .await
            .status(),
        204
    );
}
