use super::super::setup::Fixture;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

fn restore(proof: &OAuthBrowserProof) -> OAuthBrowserProof {
    OAuthBrowserProof::parse(
        proof.nonce().expose().to_owned(),
        proof.pkce_verifier().expose().to_owned(),
    )
    .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn active_provider_session_can_request_reauthentication_without_promoting_its_old_or_unknown_time(
    pool: PgPool,
) {
    for old in [false, true] {
        let f = Fixture::new(pool.clone(), OidcJitPolicy::Allow).await;
        let attributes = if old {
            json!({"auth_time":f.now_seconds().await - 600})
        } else {
            json!({})
        };
        let (user, current) = f
            .sign_in
            .finish(f.mapped("owned", attributes).await)
            .await
            .unwrap();
        let before = f
            .store
            .list_sessions(f.realm(), current.verifier(), None)
            .await
            .unwrap();
        assert_eq!(before.sessions.len(), 1);
        assert_eq!(before.sessions[0].authenticated_at_ms.is_some(), old);
        let c = f.policy.configuration();
        let flow = OAuthTransactions::new(c.clone(), f.store.clone());
        let browser = Secret::generate().unwrap();
        let purpose = OAuthPurpose::DeleteProviderAccount {
            user: user.id,
            session: current.verifier(),
        };
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-delete-purpose",
            purpose: purpose.clone(),
        };
        let start = flow.begin(&intent).await.unwrap();
        let row: (String, Uuid, Uuid) = sqlx::query_as("SELECT purpose,user_id,session_id FROM auth_oauth_transactions WHERE realm_id=$1 AND state_hash=$2")
            .bind(f.realm()).bind(start.state.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
        assert_eq!(
            row,
            (
                "delete_provider_account".into(),
                user.id,
                before.sessions[0].id
            )
        );
        let callback = || OAuthCallback {
            redirect: c.redirect(),
            issuer: Some(c.issuer()),
        };
        for wrong in [
            OAuthPurpose::SignIn,
            OAuthPurpose::Link {
                user: user.id,
                session: current.verifier(),
            },
        ] {
            let result = flow
                .consume(
                    &OAuthIntent {
                        browser: &browser,
                        source: "owned-delete-purpose",
                        purpose: wrong,
                    },
                    &start.state,
                    restore(&start.proof),
                    callback(),
                )
                .await;
            assert!(
                matches!(result, Err(Error::Unauthorized)),
                "wrong purpose must reject without consuming original state"
            );
        }
        let wrong_browser = Secret::generate().unwrap();
        assert!(matches!(
            flow.consume(
                &OAuthIntent {
                    browser: &wrong_browser,
                    source: "owned-delete-purpose",
                    purpose
                },
                &start.state,
                restore(&start.proof),
                callback()
            )
            .await,
            Err(Error::Unauthorized)
        ));
        let exchange = flow
            .consume(&intent, &start.state, restore(&start.proof), callback())
            .await
            .unwrap();
        assert!(matches!(
            exchange.purpose(),
            OAuthPurpose::DeleteProviderAccount { .. }
        ));
        f.store.check_oidc_exchange(&exchange).await.unwrap();
        assert!(matches!(
            flow.consume(&intent, &start.state, start.proof, callback())
                .await,
            Err(Error::Unauthorized)
        ));
        let after = f
            .store
            .list_sessions(f.realm(), current.verifier(), None)
            .await
            .unwrap();
        assert_eq!(
            after.sessions[0].authenticated_at_ms,
            before.sessions[0].authenticated_at_ms
        );
        assert_eq!(
            f.store
                .authenticate(f.realm(), current.verifier())
                .await
                .unwrap(),
            user
        );
        let (users, identities, sessions, audit, pending) = f.facts().await;
        assert_eq!(
            (users, identities, sessions, audit, pending),
            if old {
                (2, 2, 2, 2, 0)
            } else {
                (1, 1, 1, 1, 0)
            },
            "purpose consumption creates neither authentication nor deletion authority"
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn provider_deletion_purpose_rejects_another_owner_source_realm_and_incompatible_method(
    pool: PgPool,
) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let (user, current) = f
        .sign_in
        .finish(f.mapped("owned", json!({})).await)
        .await
        .unwrap();
    let (other, other_session) = f
        .sign_in
        .finish(f.mapped("other", json!({})).await)
        .await
        .unwrap();
    let browser = Secret::generate().unwrap();
    let c = f.policy.configuration();
    let other_source = Fixture::scoped(
        f.pool.clone(),
        f.store.clone(),
        f.realm(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        OidcJitPolicy::Allow,
    )
    .await;
    let other_realm = Fixture::scoped(
        f.pool.clone(),
        f.store.clone(),
        Uuid::new_v4(),
        c.connection(),
        c.client(),
        OidcJitPolicy::Allow,
    )
    .await;
    let weak = Secret::generate().unwrap();
    sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method) VALUES($1,$2,$3,$4,'email')")
        .bind(f.realm()).bind(Uuid::new_v4()).bind(user.id).bind(weak.verifier().as_slice()).execute(&f.pool).await.unwrap();
    let before = f.facts().await;
    for (configuration, owner, session) in [
        (c, other.id, current.verifier()),
        (c, user.id, other_session.verifier()),
        (c, user.id, Secret::generate().unwrap().verifier()),
        (c, user.id, weak.verifier()),
        (
            other_source.policy.configuration(),
            user.id,
            current.verifier(),
        ),
        (
            other_realm.policy.configuration(),
            user.id,
            current.verifier(),
        ),
    ] {
        let flow = OAuthTransactions::new(configuration.clone(), f.store.clone());
        let result = flow
            .begin(&OAuthIntent {
                browser: &browser,
                source: "owned-bindings",
                purpose: OAuthPurpose::DeleteProviderAccount {
                    user: owner,
                    session,
                },
            })
            .await;
        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "infrastructure errors never prove source/owner denial"
        );
        assert_eq!(f.facts().await, before);
    }
    let flow = OAuthTransactions::new(c.clone(), f.store.clone());
    let intent = OAuthIntent {
        browser: &browser,
        source: "owned-bindings",
        purpose: OAuthPurpose::DeleteProviderAccount {
            user: user.id,
            session: current.verifier(),
        },
    };
    let start = flow.begin(&intent).await.unwrap();
    flow.cancel(&intent, &start.state, &start.proof)
        .await
        .unwrap();
    assert_eq!(f.facts().await, before);
}

#[sqlx::test(migrations = "./migrations")]
async fn signed_provider_deletion_purpose_cannot_become_a_signin_in_use_case_or_repository(
    pool: PgPool,
) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let (user, current) = f
        .sign_in
        .finish(f.mapped("owned", json!({})).await)
        .await
        .unwrap();
    let before = f.facts().await;
    for direct in [false, true] {
        let proof = f
            .mapped_for(
                "owned",
                json!({"auth_time":f.now_seconds().await}),
                OAuthPurpose::DeleteProviderAccount {
                    user: user.id,
                    session: current.verifier(),
                },
                None,
            )
            .await;
        if direct {
            assert!(matches!(
                f.store
                    .finish_oidc_identity(proof, Secret::generate().unwrap().verifier())
                    .await,
                Err(Error::Unauthorized)
            ));
        } else {
            assert!(matches!(
                f.sign_in.finish(proof).await,
                Err(Error::Unauthorized)
            ));
        }
        assert_eq!(f.facts().await, before);
    }
    f.store
        .authenticate(f.realm(), current.verifier())
        .await
        .unwrap();
}
