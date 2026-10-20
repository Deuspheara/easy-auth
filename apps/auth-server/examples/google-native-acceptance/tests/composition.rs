use super::{fixture::Fixture, provider::Provider};
use crate::{completion, observations, settings::ClaimsProfile};
use auth_core::{OAuthIntent, OAuthPurpose, Secret};
use easy_auth_server::GoogleDesktopSignIn;
use serde_json::json;
use sqlx::PgPool;
use std::sync::atomic::Ordering;

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn manual_setup_selects_explicit_profile_and_cancels_actual_native_operations(pool: PgPool) {
    for (ip, profile) in [
        ("127.0.0.1", ClaimsProfile::Base),
        ("::1", ClaimsProfile::SessionAge),
    ] {
        let fixture =
            Fixture::new(pool.clone(), profile, ip.parse().unwrap(), Provider::new()).await;
        let setup = fixture.setup;
        let realm = setup.policy.configuration().realm();
        let browser = Secret::generate().unwrap();
        let intent = OAuthIntent {
            browser: &browser,
            source: "manual-profile-control",
            purpose: OAuthPurpose::SignIn,
        };
        let start = setup.service.begin(&intent).await.unwrap();
        let url = url::Url::parse(start.authorization_url.expose()).unwrap();
        let claims: Vec<_> = url
            .query_pairs()
            .filter(|(key, _)| key == "claims")
            .map(|(_, value)| value.into_owned())
            .collect();
        match profile {
            ClaimsProfile::Base => assert!(claims.is_empty()),
            ClaimsProfile::SessionAge => assert_eq!(
                claims
                    .iter()
                    .map(|value| serde_json::from_str::<serde_json::Value>(value).unwrap())
                    .collect::<Vec<_>>(),
                vec![json!({"id_token":{"auth_time":{"essential":true}}})]
            ),
        }
        setup
            .service
            .cancel(&intent, &start.transaction.state, &start.transaction.proof)
            .await
            .unwrap();
        let attempt = GoogleDesktopSignIn::begin(
            setup.listener,
            setup.service,
            "manual-native-cancel-control",
        )
        .await
        .unwrap();
        assert_eq!(
            observations::read(&pool, realm).await.unwrap(),
            (0, 0, 0, 0, 1, 0)
        );
        attempt.cancel().await.unwrap();
        assert_eq!(
            observations::read(&pool, realm).await.unwrap(),
            (0, 0, 0, 0, 0, 0)
        );
        assert_eq!(fixture.provider.posts.load(Ordering::SeqCst), 0);
    }
}

#[sqlx::test(migrations = "../../crates/auth-postgres/migrations")]
async fn actual_signed_socket_completion_commits_validates_and_revokes_only_its_local_session(
    pool: PgPool,
) {
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&pool)
            .await
            .unwrap();
    for (ip, profile, attributes, present) in [
        ("127.0.0.1", ClaimsProfile::Base, json!({}), false),
        (
            "::1",
            ClaimsProfile::SessionAge,
            json!({"auth_time":now-3600}),
            true,
        ),
    ] {
        let delivered = Fixture::new(pool.clone(), profile, ip.parse().unwrap(), Provider::new())
            .await
            .delivered(attributes)
            .await;
        assert_eq!(delivered.provider.posts.load(Ordering::SeqCst), 1);
        assert_eq!(delivered.provider.signed.load(Ordering::SeqCst), 1);
        let realm = delivered.policy.configuration().realm();
        assert_eq!(
            observations::read(&pool, realm).await.unwrap(),
            (0, 0, 0, 0, 0, 0)
        );
        let report = completion::commit(
            &pool,
            &delivered.store,
            &delivered.policy,
            delivered.result.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(report["status"], "passed");
        assert_eq!(report["signed_auth_time_present"], present);
        assert_eq!(report["freshness_or_deletion_accepted"], false);
        assert_eq!(
            observations::read(&pool, realm).await.unwrap(),
            (1, 1, 1, 2, 0, 1)
        );
    }
}
