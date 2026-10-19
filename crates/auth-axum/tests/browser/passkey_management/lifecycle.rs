use super::*;
use serde_json::json;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn proof_gated_inventory_and_rename_preserve_identity_without_exposing_credentials(
    pool: PgPool,
) {
    for email_free in [false, true] {
        let f = Fixture::new(pool.clone(), email_free).await;
        let before = json(f.get("/v1/session", &f.cookie()).await).await;
        assert_eq!(before["email"].is_null(), email_free);
        let keys = f.keys().await;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].as_object().unwrap().len(), 5);
        assert!(keys[0]["last_used_at_ms"].is_i64());
        for field in [
            "credential",
            "credential_id",
            "realm_id",
            "user_id",
            "rp_id",
            "private_state",
        ] {
            assert!(keys[0].get(field).is_none());
        }
        let input = json!({"id":keys[0]["id"],"version":keys[0]["version"],"label":"Renamed key"});
        let response = f.mutate(RENAME, &input).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        let changed = json(response).await;
        assert_ne!(changed["version"], keys[0]["version"]);
        assert_eq!(changed.as_object().unwrap().len(), 1);
        assert_eq!(f.keys().await[0]["version"], changed["version"]);
        assert_eq!(f.keys().await[0]["label"], "Renamed key");
        assert_eq!(
            f.mutate(RENAME, &input).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(json(f.get("/v1/session", &f.cookie()).await).await, before);
        let notices:i64=sqlx::query_scalar("SELECT count(*) FROM auth_security_notifications WHERE realm_id=$1 AND kind='passkeys_changed'")
            .bind(f.auth.realm()).fetch_one(&pool).await.unwrap();
        assert_eq!(notices, if email_free { 0 } else { 1 });
    }
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn removal_keeps_a_proven_key_revokes_sessions_and_clears_all_action_cookies(pool: PgPool) {
    let f = Fixture::new(pool.clone(), true).await;
    let first = f.keys().await.remove(0);
    let input = json!({"id":first["id"],"version":first["version"]});
    let denied = f.mutate(REMOVE, &input).await;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    assert!(denied.headers().get(header::SET_COOKIE).is_none());
    let (spare, mut token) = f.add_key("Spare").await;
    assert_eq!(
        f.mutate(REMOVE, &input).await.status(),
        StatusCode::UNAUTHORIZED,
        "unproven spare cannot authorize last working key removal"
    );
    let other = f.login(&mut token).await;
    let response = f.mutate(REMOVE, &input).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cookies: Vec<_> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    for name in [
        "session",
        "browser",
        "reset",
        "email-change",
        "delete",
        "passkey",
        "attach",
    ] {
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with(&format!("__Host-auth-{name}="))
                    && cookie.contains("Max-Age=0")
                    && cookie.contains("Secure")
                    && cookie.contains("HttpOnly")),
            "all authentication/action cookies must clear"
        );
    }
    for cookie in [
        f.cookie(),
        format!("__Host-auth-session={}", other.expose()),
    ] {
        assert_eq!(
            f.get("/v1/session", &cookie).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let fresh = f.login(&mut token).await;
    let remaining = json(
        f.get(
            INVENTORY,
            &format!("__Host-auth-session={}", fresh.expose()),
        )
        .await,
    )
    .await;
    assert_eq!(remaining["passkeys"].as_array().unwrap().len(), 1);
    assert_eq!(remaining["passkeys"][0]["id"], spare.to_string());
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn mailbox_password_legacy_and_stale_methods_cannot_manage_keys(pool: PgPool) {
    for method in ["email", "password", "legacy_unknown", "stale"] {
        let f = Fixture::new(pool.clone(), false).await;
        let key = f.keys().await.remove(0);
        assert_eq!(
            f.get(INVENTORY, &f.mailbox_cookie).await.status(),
            StatusCode::UNAUTHORIZED
        );
        if method == "stale" {
            sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1")
                .bind(f.session.verifier().as_slice()).execute(&pool).await.unwrap();
        } else {
            sqlx::query("UPDATE auth_sessions SET authentication_method=$2 WHERE token_hash=$1")
                .bind(f.session.verifier().as_slice())
                .bind(method)
                .execute(&pool)
                .await
                .unwrap();
        }
        assert_eq!(
            f.get(INVENTORY, &f.cookie()).await.status(),
            StatusCode::UNAUTHORIZED
        );
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
    }
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn failed_notice_write_returns_generic_unavailable_without_cookie_or_session_success(
    pool: PgPool,
) {
    let f = Fixture::new(pool.clone(), false).await;
    let (id, _) = f.add_key("Spare").await;
    let before = f.keys().await;
    let key = before
        .iter()
        .find(|key| key["id"] == id.to_string())
        .unwrap();
    let input = json!({"id":key["id"],"version":key["version"]});
    sqlx::query("ALTER TABLE auth_security_notifications ADD CONSTRAINT reject_management_notice CHECK(kind<>'passkeys_changed') NOT VALID")
        .execute(&pool).await.unwrap();
    let failed = f.mutate(REMOVE, &input).await;
    assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(failed.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(
        json(failed).await,
        json!({"code":"temporarily_unavailable"})
    );
    assert_eq!(f.keys().await, before);
    assert_eq!(
        f.get("/v1/session", &f.cookie()).await.status(),
        StatusCode::OK
    );
    sqlx::query("ALTER TABLE auth_security_notifications DROP CONSTRAINT reject_management_notice")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        f.mutate(REMOVE, &input).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.get("/v1/session", &f.cookie()).await.status(),
        StatusCode::UNAUTHORIZED
    );
}
