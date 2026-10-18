use super::session_id;
use crate::support::{realm, signed_in};
use auth_core::Repository;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn audit_foreign_keys_reject_cross_user_and_realm_actor_target_and_subject(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let alice = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, alice.verifier()).await.unwrap();
    let a = session_id(&pool, alice.verifier()).await;
    let bob = signed_in(&store, realm, "bob@example.com").await;
    let b = session_id(&pool, bob.verifier()).await;
    let foreign_realm = Uuid::new_v4();
    store.ensure_realm(foreign_realm).await.unwrap();
    let foreign = signed_in(&store, foreign_realm, "alice@example.com").await;
    let foreign_user = store
        .authenticate(foreign_realm, foreign.verifier())
        .await
        .unwrap();
    let f = session_id(&pool, foreign.verifier()).await;
    for (r, u, actor, target) in [
        (realm, user.id, a, b),
        (realm, user.id, b, a),
        (foreign_realm, foreign_user.id, a, f),
        (foreign_realm, foreign_user.id, f, a),
        (realm, foreign_user.id, a, a),
        (realm, Uuid::new_v4(), a, a),
    ] {
        let error=sqlx::query("INSERT INTO auth_audit(realm_id,user_id,kind,actor_session_id,session_id) VALUES ($1,$2,'session_revoked',$3,$4)")
            .bind(r).bind(u).bind(actor).bind(target).execute(&pool).await.unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("23503")
        );
    }
    store.revoke(realm, alice.verifier()).await.unwrap();
    let attribution:(Uuid,Uuid,Uuid)=sqlx::query_as("SELECT user_id,actor_session_id,session_id FROM auth_audit WHERE realm_id=$1 AND kind='session_revoked'")
        .bind(realm).fetch_one(&pool).await.unwrap();
    assert_eq!(attribution, (user.id, a, a));
    assert!(store.authenticate(realm, bob.verifier()).await.is_ok());
    assert!(
        store
            .authenticate(foreign_realm, foreign.verifier())
            .await
            .is_ok()
    );
}
