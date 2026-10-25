use super::*;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn native_grant_capture_preserves_registered_nonce_modes_and_signed_failure_boundary(
    pool: PgPool,
) {
    for encoding in [AppleNonceEncoding::Plain, AppleNonceEncoding::Sha256Hex] {
        let f = Fixture::new(
            pool.clone(),
            AppleClientType::Native(encoding),
            OidcJitPolicy::Allow,
        )
        .await;
        let a = f
            .prepare("owned-native-capture", serde_json::json!({}))
            .await;
        assert!(a.start.request.web_url().is_none());
        let (owner, session) = AppleGrantSignIn::new(f.store.clone())
            .finish(captured(&f, &a).await.unwrap())
            .await
            .unwrap();
        let stored = envelopes(&f).await;
        assert_eq!(stored.len(), 1);
        let binding = stored[0].binding();
        assert_eq!(binding.realm(), f.realm());
        assert_eq!(binding.connection(), f.policy.configuration().connection());
        assert_eq!(binding.client(), f.policy.configuration().client());
        assert!(f.vault.rewrap(&stored[0]).await.is_ok());
        let invalid = f
            .prepare(
                "owned-native-capture",
                serde_json::json!({"nonce":"wrong-signed-native-nonce"}),
            )
            .await;
        assert!(matches!(
            captured(&f, &invalid).await,
            Err(Error::Unauthorized)
        ));
        assert_eq!(envelopes(&f).await.len(), 1);
        assert_eq!(
            f.store
                .authenticate(f.realm(), session.verifier())
                .await
                .unwrap(),
            owner
        );
        assert!(matches!(
            AppleGrantAuthorization::linking(
                Arc::new(OAuthTransactions::new(
                    f.policy.configuration().clone(),
                    f.store.clone()
                )),
                f.component.clone()
            ),
            Err(Error::InvalidInput)
        ));
    }
}
