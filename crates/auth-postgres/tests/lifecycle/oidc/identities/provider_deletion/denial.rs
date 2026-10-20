use super::completion_setup::{account, fresh, proof, snapshot};
use crate::support::signed_in;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn deletion_rejects_missing_or_old_authentication_time_in_core_and_repository_without_mutation(
    pool: PgPool,
) {
    let (f, user, current) = account(pool).await;
    for direct in [false, true] {
        for old in [false, true] {
            let attributes = if old {
                json!({"auth_time":f.now_seconds().await-600})
            } else {
                json!({})
            };
            let deletion = proof(&f, &user, &current, attributes, None).await;
            let before = snapshot(&f).await;
            let result = if direct {
                f.store.finish_oidc_account_deletion(deletion).await
            } else {
                OidcAccountDeletion::new(f.store.clone())
                    .finish(deletion)
                    .await
            };
            assert!(
                matches!(result, Err(Error::Unauthorized)),
                "only actual authorization rejection proves the negative"
            );
            assert!(
                snapshot(&f).await == before,
                "rejection must leave exact account/session/audit/notice/pending/cooldown state"
            );
        }
    }
    OidcAccountDeletion::new(f.store.clone())
        .finish(fresh(&f, &user, &current).await)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn genuine_deletion_proof_for_another_or_differently_cased_subject_cannot_delete_initiating_owner(
    pool: PgPool,
) {
    let (f, user, current) = account(pool).await;
    for direct in [false, true] {
        for subject in ["another", "Owned"] {
            let deletion = f
                .mapped_for(
                    subject,
                    json!({"auth_time":f.now_seconds().await}),
                    OAuthPurpose::DeleteProviderAccount {
                        user: user.id,
                        session: current.verifier(),
                    },
                    None,
                )
                .await;
            assert_eq!(
                deletion.identity().subject(),
                subject,
                "test fixture must contain actual verified wrong subject"
            );
            let before = snapshot(&f).await;
            let result = if direct {
                f.store.finish_oidc_account_deletion(deletion).await
            } else {
                OidcAccountDeletion::new(f.store.clone())
                    .finish(deletion)
                    .await
            };
            assert!(matches!(result, Err(Error::Unauthorized)));
            assert!(
                snapshot(&f).await == before,
                "wrong subject must neither delete nor provision/merge an owner"
            );
        }
    }
    OidcAccountDeletion::new(f.store.clone())
        .finish(fresh(&f, &user, &current).await)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn signin_and_link_proofs_cannot_be_promoted_into_provider_deletion_by_either_layer(
    pool: PgPool,
) {
    let (f, user, current) = account(pool).await;
    let mailbox = signed_in(&f.store, f.realm(), "link-control@example.test").await;
    let mailbox_owner = f
        .store
        .authenticate(f.realm(), mailbox.verifier())
        .await
        .unwrap();
    for direct in [false, true] {
        for purpose in [
            OAuthPurpose::SignIn,
            OAuthPurpose::Link {
                user: mailbox_owner.id,
                session: mailbox.verifier(),
            },
        ] {
            let mapped = f
                .mapped_for(
                    "owned",
                    json!({"auth_time":f.now_seconds().await}),
                    purpose,
                    None,
                )
                .await;
            let before = snapshot(&f).await;
            let result = if direct {
                f.store.finish_oidc_account_deletion(mapped).await
            } else {
                OidcAccountDeletion::new(f.store.clone())
                    .finish(mapped)
                    .await
            };
            assert!(matches!(result, Err(Error::Unauthorized)));
            assert!(snapshot(&f).await == before);
        }
    }
    OidcAccountDeletion::new(f.store.clone())
        .finish(fresh(&f, &user, &current).await)
        .await
        .unwrap();
    f.store
        .authenticate(f.realm(), mailbox.verifier())
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn final_deletion_rechecks_initiating_revocation_owner_policy_disable_and_revision_after_verification(
    pool: PgPool,
) {
    for mutation in ["revocation", "policy", "disable", "revision"] {
        let (mut f, user, current) = account(pool.clone()).await;
        let deletion = fresh(&f, &user, &current).await;
        let cap = deletion.identity().expires_us();
        match mutation {
            "revocation" => {
                sqlx::query("UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE realm_id=$1 AND token_hash=$2")
                    .bind(f.realm()).bind(current.verifier().as_slice()).execute(&f.pool).await.unwrap();
            }
            "policy" => {
                sqlx::query("UPDATE auth_users SET authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2")
                    .bind(f.realm()).bind(user.id).execute(&f.pool).await.unwrap();
            }
            "disable" => {
                let c = f.policy.configuration();
                f.store
                    .disable_oauth_connection(c.realm(), c.connection(), c.client())
                    .await
                    .unwrap();
            }
            _ => f.reconfigure(OidcJitPolicy::Deny).await,
        }
        let before = snapshot(&f).await;
        let live: bool = sqlx::query_scalar(
            "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint < $1",
        )
        .bind(cap)
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert!(
            live,
            "test infrastructure: original proof must not expire before invalidation denial"
        );
        assert!(matches!(
            f.store.finish_oidc_account_deletion(deletion).await,
            Err(Error::Unauthorized)
        ));
        assert!(snapshot(&f).await == before);
    }
}
