mod snapshot;

use crate::support::{issuer_native_consumers::Consumer, issuer_native_families::Fixture};
use auth_core::{Error, IssuerNativeRefresh, IssuerTokenError, Repository};
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use std::sync::Arc;

#[sqlx::test]
async fn old_snapshot_revives_authority_until_recorded_incident_reductions_are_reapplied(
    pool: PgPool,
) {
    let first = Fixture::new(pool.clone()).await;
    let reader = Consumer::new(&first).await;
    reader.enable(&first).await;
    let tokens = first.exchange(&first.code().await).await.unwrap();
    let key_tokens = first.exchange(&first.code().await).await.unwrap();
    let pending_code = first.code().await;
    let other = Fixture::new(pool.clone()).await;
    let other_reader = Consumer::new(&other).await;
    other_reader.enable(&other).await;
    let other_tokens = other.exchange(&other.code().await).await.unwrap();

    snapshot::with_snapshot(pool, move |live, restored| async move {
        for database in [&live, &restored] {
            let store = Arc::new(Postgres::new(database.clone()));
            let inspect = auth_core::IssuerNativeIntrospection::new(
                first.base.authority.clone(),
                store.clone(),
            );
            // These are independently issued real credentials retained outside
            // the snapshot, not recreated hashes or caller-supplied clock facts.
            store
                .authenticate(first.base.authority.realm(), first.base.current.verifier())
                .await
                .unwrap();
            assert!(
                inspect
                    .introspect_access(
                        &reader.authentication(),
                        &tokens.access_token().into(),
                        "127.0.0.1"
                    )
                    .await
                    .unwrap()
                    .is_some()
            );
            assert_eq!(
                store
                    .issuer_public_keys(&first.base.authority)
                    .await
                    .unwrap()
                    .len(),
                1
            );

            let refresh = IssuerNativeRefresh::new(first.base.authority.clone(), store.clone());
            refresh
                .revoke(
                    &first.authentication(),
                    &tokens.refresh_token().into(),
                    "127.0.0.1",
                )
                .await
                .unwrap();
            assert!(
                inspect
                    .introspect_access(
                        &reader.authentication(),
                        &tokens.access_token().into(),
                        "127.0.0.1"
                    )
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(matches!(
                refresh
                    .refresh(
                        &first.authentication(),
                        &tokens.refresh_token().into(),
                        "127.0.0.1"
                    )
                    .await,
                Err(IssuerTokenError::InvalidGrant)
            ));
            assert!(
                inspect
                    .introspect_access(
                        &reader.authentication(),
                        &key_tokens.access_token().into(),
                        "127.0.0.1"
                    )
                    .await
                    .unwrap()
                    .is_some()
            );
            // Family revocation has not revoked the owner's local session/key.
            store
                .authenticate(first.base.authority.realm(), first.base.current.verifier())
                .await
                .unwrap();
            store
                .disable_issuer_key(&first.base.authority, first.base.key.id())
                .await
                .unwrap();
            // With its sole key disabled the existing metadata contract fails
            // unavailable; it never publishes a misleading usable/empty key set.
            assert!(matches!(
                store.issuer_public_keys(&first.base.authority).await,
                Err(Error::Unavailable)
            ));
            assert!(
                inspect
                    .introspect_access(
                        &reader.authentication(),
                        &key_tokens.access_token().into(),
                        "127.0.0.1"
                    )
                    .await
                    .unwrap()
                    .is_none()
            );
            // A cached verification key can still verify the old ID-token
            // signature. Local disable cannot recall offline consumer caches.
            let cached = josekit::jwk::Jwk::from_bytes(
                serde_json::to_vec(first.base.key.public_key().unwrap().document()).unwrap(),
            )
            .unwrap();
            assert!(
                josekit::jws::deserialize_compact(
                    tokens.id_token(),
                    &josekit::jws::RS256.verifier_from_jwk(&cached).unwrap()
                )
                .is_ok()
            );
            let signer = auth_core::IssuerTokenIssuer::new(
                first.base.authority.clone(),
                store.clone(),
                vec![first.base.key.clone()],
            )
            .unwrap();
            let native = auth_core::IssuerNativeTokenIssuer::new(&signer, store.clone());
            assert!(matches!(
                native
                    .exchange(
                        &first.authentication(),
                        &pending_code,
                        "http://127.0.0.1:41002/cb",
                        &first.base.pkce,
                        "127.0.0.1"
                    )
                    .await,
                Err(IssuerTokenError::Unavailable)
            ));
            store
                .revoke_all_sessions(first.base.authority.realm(), first.base.current.verifier())
                .await
                .unwrap();
            assert!(matches!(
                store
                    .authenticate(first.base.authority.realm(), first.base.current.verifier())
                    .await,
                Err(Error::Unauthorized)
            ));
            // Reductions remain possible after session/key disable. They cannot
            // reset earlier family revocation or fabricate owner authentication.
            let revoked: i64 = sqlx::query_scalar(
                "SELECT revoked_at_us FROM auth_issuer_native_families WHERE realm_id=$1 AND revoked_at_us IS NOT NULL",
            )
            .bind(first.base.authority.realm())
            .fetch_one(database)
            .await
            .unwrap();
            refresh
                .revoke(
                    &first.authentication(),
                    &tokens.access_token().into(),
                    "127.0.0.1",
                )
                .await
                .unwrap();
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT revoked_at_us FROM auth_issuer_native_families WHERE realm_id=$1 AND revoked_at_us IS NOT NULL"
                )
                .bind(first.base.authority.realm())
                .fetch_one(database)
                .await
                .unwrap(),
                revoked
            );
            store
                .disable_issuer_key(&first.base.authority, first.base.key.id())
                .await
                .unwrap();
            assert!(matches!(
                store
                    .revoke_all_sessions(
                        first.base.authority.realm(),
                        first.base.current.verifier()
                    )
                    .await,
                Err(Error::Unauthorized)
            ));
            // The independent realm still has its original usable authority.
            store
                .authenticate(other.base.authority.realm(), other.base.current.verifier())
                .await
                .unwrap();
            let foreign = auth_core::IssuerNativeIntrospection::new(
                other.base.authority.clone(),
                store.clone(),
            );
            assert!(
                foreign
                    .introspect_access(
                        &other_reader.authentication(),
                        &other_tokens.access_token().into(),
                        "127.0.0.1"
                    )
                    .await
                    .unwrap()
                    .is_some()
            );
            assert_eq!(
                store
                    .issuer_public_keys(&other.base.authority)
                    .await
                    .unwrap()
                    .len(),
                1
            );
        }
        // Snapshot reductions cannot mutate the live database: both have their
        // own immutable first-revocation timestamps and independent transactions.
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM auth_issuer_native_families WHERE revoked_at_us IS NOT NULL"
            )
            .fetch_one(&live)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM auth_issuer_native_families WHERE revoked_at_us IS NOT NULL"
            )
            .fetch_one(&restored)
            .await
            .unwrap(),
            1
        );
    })
    .await;
}
