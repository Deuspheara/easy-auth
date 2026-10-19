use super::*;
use serde_json::json;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn management_origin_cookie_json_body_and_query_boundary_fail_closed(pool: PgPool) {
    let f = Fixture::new(pool, false).await;
    let key = f.keys().await.remove(0);
    let input = json!({"id":key["id"],"version":key["version"],"label":"Valid"}).to_string();
    for origin in [None, Some("null"), Some("https://evil.example")] {
        let response = f
            .app
            .clone()
            .oneshot(post(RENAME, &input, Some(&f.cookie()), origin))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
    let mut duplicate = post(RENAME, &input, Some(&f.cookie()), Some(ORIGIN));
    duplicate
        .headers_mut()
        .append(header::ORIGIN, ORIGIN.parse().unwrap());
    assert_eq!(
        f.app.clone().oneshot(duplicate).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    for cookie in [
        String::new(),
        "__Host-auth-session=invalid".into(),
        format!("{}; {}", f.cookie(), f.cookie()),
    ] {
        assert_eq!(
            f.app
                .clone()
                .oneshot(post(RENAME, &input, Some(&cookie), Some(ORIGIN)))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    for body in [
        json!({"id":key["id"],"version":key["version"],"label":"Valid","user_id":f.owner}),
        json!({"id":"invalid","version":key["version"],"label":"Valid"}),
        json!({"id":key["id"],"label":"Valid"}),
    ] {
        let response = f.mutate(RENAME, &body).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json(response).await, json!({"code":"invalid_body"}));
    }
    let duplicate_fields = format!(
        "{{\"id\":{},\"id\":{},\"version\":{},\"label\":\"Valid\"}}",
        key["id"], key["id"], key["version"]
    );
    assert_eq!(
        f.app
            .clone()
            .oneshot(post(
                RENAME,
                &duplicate_fields,
                Some(&f.cookie()),
                Some(ORIGIN)
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        f.mutate(
            REMOVE,
            &json!({"id":key["id"],"version":key["version"],"label":"Unwanted"})
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    for label in [
        "".to_owned(),
        " ".to_owned(),
        "bad\nlabel".into(),
        "é".repeat(129),
    ] {
        let response = f
            .mutate(
                RENAME,
                &json!({"id":key["id"],"version":key["version"],"label":label}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json(response).await, json!({"code":"invalid_input"}));
    }
    for query in [
        "?user_id=untrusted",
        "?realm_id=untrusted",
        "?after=untrusted",
        "?rp_id=untrusted",
    ] {
        let response = f.get(&format!("{INVENTORY}{query}"), &f.cookie()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json(response).await, json!({"code":"invalid_input"}));
    }
    let mut wrong_type = post(RENAME, &input, Some(&f.cookie()), Some(ORIGIN));
    wrong_type
        .headers_mut()
        .insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
    assert_eq!(
        f.app.clone().oneshot(wrong_type).await.unwrap().status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let oversized = json!({"id":key["id"],"version":key["version"],"label":"x".repeat(9000)});
    assert_eq!(
        f.mutate(RENAME, &oversized).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        f.keys().await[0],
        key,
        "all boundary rejections preserve metadata"
    );
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn management_cannot_select_foreign_owner_or_realm_through_public_ids(pool: PgPool) {
    let f = Fixture::new(pool.clone(), true).await;
    let other = Fixture::new(pool, true).await;
    let key = other.keys().await.remove(0);
    for (path, body) in [
        (
            RENAME,
            json!({"id":key["id"],"version":key["version"],"label":"Denied"}),
        ),
        (REMOVE, json!({"id":key["id"],"version":key["version"]})),
    ] {
        let response = f.mutate(path, &body).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            json(response).await,
            json!({"code":"authentication_required"})
        );
    }
    assert_eq!(other.keys().await[0], key);
}
