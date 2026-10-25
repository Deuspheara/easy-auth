use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn closed_bounded_status_forms_authentication_and_trusted_peer_have_no_ambient_fallback(
    pool: PgPool,
) {
    let f = fixture(pool, Profile::Confidential).await;
    for path in ["/oidc/revoke", "/oidc/introspect"] {
        for suffix in [
            "&owner=other",
            "&realm=other",
            "&client_secret=other",
            "&to%6ben=duplicate",
            "&token=%FF",
            "&other=%GG",
        ] {
            let response = send(&f, path, body(&f, "unknown") + suffix).await;
            assert_eq!(response.status(), 400);
            assert!(read(response).await == json!({"error":"invalid_request"}));
        }
        for (media, encoding, status) in [
            ("application/json", None, 415),
            ("application/x-www-form-urlencoded", Some("gzip"), 415),
        ] {
            let mut request = token_request(path, body(&f, "unknown"), f.basic().as_deref(), true);
            request
                .headers_mut()
                .insert(header::CONTENT_TYPE, media.parse().unwrap());
            if let Some(encoding) = encoding {
                request
                    .headers_mut()
                    .insert(header::CONTENT_ENCODING, encoding.parse().unwrap());
            }
            assert_eq!(
                f.app.clone().oneshot(request).await.unwrap().status(),
                status
            );
        }
        assert_eq!(send(&f, path, "x".repeat(4097)).await.status(), 413);
        assert_eq!(
            send(&f, &format!("{path}?realm=other"), body(&f, "unknown"))
                .await
                .status(),
            400
        );
        assert_eq!(
            f.app
                .clone()
                .oneshot(token_request(
                    path,
                    body(&f, "unknown"),
                    f.basic().as_deref(),
                    false
                ))
                .await
                .unwrap()
                .status(),
            503
        );
        assert_eq!(
            f.app.clone().oneshot(get(path)).await.unwrap().status(),
            405
        );
        let mut request = token_request(path, body(&f, "unknown"), None, true);
        request
            .headers_mut()
            .insert(header::COOKIE, f.current.parse().unwrap());
        assert_eq!(f.app.clone().oneshot(request).await.unwrap().status(), 401);
        let mut duplicate = token_request(path, body(&f, "unknown"), f.basic().as_deref(), true);
        duplicate
            .headers_mut()
            .append(header::AUTHORIZATION, f.basic().unwrap().parse().unwrap());
        assert_eq!(
            f.app.clone().oneshot(duplicate).await.unwrap().status(),
            401
        );
        let mismatch = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("token", "unknown")
            .append_pair("client_id", &Uuid::new_v4().to_string())
            .finish();
        assert_eq!(send(&f, path, mismatch).await.status(), 401);
    }
}
