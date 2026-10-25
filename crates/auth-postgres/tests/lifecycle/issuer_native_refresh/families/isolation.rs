use super::*;
use auth_core::{
    IssuerNativeCredentialRequest, IssuerNativeRefreshRepository, IssuerNativeRotationRequest,
    IssuerTokenError,
};

#[sqlx::test]
async fn actual_same_client_id_in_two_realms_cannot_rotate_or_revoke_the_other_family(
    pool: PgPool,
) {
    let a = Fixture::new(pool.clone()).await;
    let b = Fixture::with_client(pool, a.policy.client().client()).await;
    let acode = a.code().await;
    let atoken = a.exchange(&acode).await.unwrap();
    let bcode = b.code().await;
    let btoken = b.exchange(&bcode).await.unwrap();
    assert!(matches!(
        b.refresher()
            .refresh(
                &b.authentication(),
                &atoken.refresh_token().into(),
                "127.0.0.1"
            )
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    b.refresher()
        .revoke(
            &b.authentication(),
            &atoken.access_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    let next_access = Secret::generate().unwrap();
    let next_refresh = Secret::generate().unwrap();
    let b_auth = b.authentication();
    let inconsistent = IssuerNativeRotationRequest {
        credential: IssuerNativeCredentialRequest {
            authority: &a.base.authority,
            client: b.policy.client(),
            authentication: &b_auth,
            token: atoken.refresh_token().verifier(),
        },
        access_id: Uuid::new_v4(),
        access: next_access.verifier(),
        refresh: next_refresh.verifier(),
    };
    assert!(matches!(
        a.base
            .store
            .rotate_issuer_native_refresh(&inconsistent)
            .await,
        Err(IssuerTokenError::InvalidClient)
    ));
    let _a = a
        .refresher()
        .refresh(
            &a.authentication(),
            &atoken.refresh_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    let _b = b
        .refresher()
        .refresh(
            &b.authentication(),
            &btoken.refresh_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert_eq!(a.facts().await, (1, 2, 2, 1, 1));
    assert_eq!(b.facts().await, (1, 2, 2, 1, 1));
}

#[sqlx::test]
async fn genuine_other_client_and_foreign_credential_formats_cannot_select_family_authority(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let code = f.code().await;
    let issued = f.exchange(&code).await.unwrap();
    let peer = f
        .base
        .store
        .configure_issuer_client(
            &IssuerClientRegistration::public_native_refresh_loopback(
                f.base.authority.realm(),
                Uuid::new_v4(),
                &["http://127.0.0.1/cb"],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let peer_auth = IssuerClientAuthentication::public(peer.client()).unwrap();
    assert!(matches!(
        f.refresher()
            .refresh(&peer_auth, &issued.refresh_token().into(), "127.0.0.1")
            .await,
        Err(IssuerTokenError::InvalidGrant)
    ));
    f.refresher()
        .revoke(&peer_auth, &issued.access_token().into(), "127.0.0.1")
        .await
        .unwrap();
    for presented in [
        auth_core::IssuerPresentedToken::parse("opaque foreign credential".into()).unwrap(),
        (&code).into(),
        issued.access_token().into(),
    ] {
        assert!(matches!(
            f.refresher()
                .refresh(&f.authentication(), &presented, "127.0.0.1")
                .await,
            Err(IssuerTokenError::InvalidGrant)
        ));
    }
    let _next = f
        .refresher()
        .refresh(
            &f.authentication(),
            &issued.refresh_token().into(),
            "127.0.0.1",
        )
        .await
        .unwrap();
    assert_eq!(f.facts().await, (1, 2, 2, 1, 1));
}
