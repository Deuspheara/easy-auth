use crate::support::{realm, signed_in};
use auth_core::{Error, Repository};
use sqlx::PgPool;
use uuid::Uuid;

/// Storage capability fixture only: this seeds a previously issued session, not
/// a SAML signature/proof. A binary without the backend must reject its authority.
#[sqlx::test(migrations = "./migrations")]
async fn stored_saml_session_has_no_authority_without_its_backend_but_can_log_out(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let bearer = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, bearer.verifier()).await.unwrap();
    let connection = Uuid::new_v4();
    let client = Uuid::new_v4();
    let revision = Uuid::new_v4();
    let identity = Uuid::new_v4();
    sqlx::query("INSERT INTO auth_saml_registrations(realm_id,id,client_id,revision,sp_entity,idp_entity,sso_url,acs_url) VALUES($1,$2,$3,$4,'urn:example:sp','urn:example:idp','https://idp.example/sso','https://app.example/acs')")
        .bind(realm).bind(connection).bind(client).bind(revision).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO auth_saml_identity_policies(realm_id,connection_id,client_id,revision,jit) VALUES($1,$2,$3,$4,'deny')")
        .bind(realm).bind(connection).bind(client).bind(revision).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO auth_saml_identities(realm_id,id,connection_id,client_id,idp_entity,sp_entity,subject,user_id,subject_hash) VALUES($1,$2,$3,$4,'urn:example:idp','urn:example:sp','subject',$5,auth_saml_subject_key($1,$3,$4,'urn:example:idp','urn:example:sp','subject'))")
        .bind(realm).bind(identity).bind(connection).bind(client).bind(user.id).execute(&pool).await.unwrap();
    sqlx::query("UPDATE auth_users SET authentication_policy='provider_required' WHERE realm_id=$1 AND id=$2")
        .bind(realm).bind(user.id).execute(&pool).await.unwrap();
    sqlx::query("UPDATE auth_sessions SET authentication_method='saml',saml_identity_id=$3,saml_revision=$4 WHERE realm_id=$1 AND token_hash=$2")
        .bind(realm).bind(bearer.verifier().as_slice()).bind(identity).bind(revision).execute(&pool).await.unwrap();
    assert!(matches!(
        store.authenticate(realm, bearer.verifier()).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        store.list_sessions(realm, bearer.verifier(), None).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        store.revoke_all_sessions(realm, bearer.verifier()).await,
        Err(Error::Unauthorized)
    ));
    store.revoke(realm, bearer.verifier()).await.unwrap();
    let revoked: bool = sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2",
    )
    .bind(realm)
    .bind(bearer.verifier().as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(revoked);
}
