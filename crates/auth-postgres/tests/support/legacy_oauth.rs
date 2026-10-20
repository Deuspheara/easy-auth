//! Historical stored-state fixtures, not evidence of a new protocol ceremony.
//! Only migration tests use raw original columns; today's adapter runs after upgrade.
use auth_core::{OAuthBrowserProof, OAuthConnection, OAuthMixupDefense, OAuthStart, Secret};
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) async fn connection(pool: &PgPool, realm: Uuid) -> OAuthConnection {
    let id = Uuid::new_v4();
    let client = Uuid::new_v4();
    let connection = OAuthConnection::new(
        realm,
        id,
        client,
        "https://issuer.example",
        "client",
        &format!("https://app.example/callback/{realm}/{id}/{client}"),
        OAuthMixupDefense::RequireIssuer,
    )
    .unwrap();
    sqlx::query("INSERT INTO auth_oauth_connections(realm_id,id,client_id,revision,issuer,provider_client,redirect_uri,defense,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,'issuer',true)")
        .bind(realm).bind(id).bind(client).bind(connection.revision()).bind(connection.issuer())
        .bind(connection.provider_client()).bind(connection.redirect()).execute(pool).await.unwrap();
    connection
}

pub(crate) async fn pending(
    pool: &PgPool,
    connection: &OAuthConnection,
    browser: &Secret,
) -> OAuthStart {
    let state = Secret::generate().unwrap();
    let proof = OAuthBrowserProof::parse(
        Secret::generate().unwrap().expose().to_owned(),
        Secret::generate().unwrap().expose().to_owned(),
    )
    .unwrap();
    let expires_us = sqlx::query_scalar("WITH clock AS (SELECT clock_timestamp() AS now) INSERT INTO auth_oauth_transactions(realm_id,connection_id,client_id,revision,state_hash,browser_hash,nonce_hash,pkce_hash,purpose,created_at,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,'sign_in',now,now+interval '5 minutes' FROM clock RETURNING (extract(epoch FROM expires_at)*1000000)::bigint")
        .bind(connection.realm()).bind(connection.connection()).bind(connection.client()).bind(connection.revision())
        .bind(state.verifier().as_slice()).bind(browser.verifier().as_slice())
        .bind(proof.nonce().verifier().as_slice()).bind(proof.pkce_verifier().verifier().as_slice())
        .fetch_one(pool).await.unwrap();
    OAuthStart {
        state,
        proof,
        expires_us,
    }
}

#[cfg(feature = "oidc-identities")]
pub(crate) async fn policy(pool: &PgPool, connection: &OAuthConnection) {
    sqlx::query("INSERT INTO auth_oidc_identity_policies(realm_id,connection_id,client_id,revision,allowed_issuers,display_claim,jit) VALUES($1,$2,$3,$4,$5,'name','allow')")
        .bind(connection.realm()).bind(connection.connection()).bind(connection.client()).bind(connection.revision())
        .bind(vec![connection.issuer()]).execute(pool).await.unwrap();
}

#[cfg(feature = "oidc-identities")]
pub(crate) async fn provider_session(
    pool: &PgPool,
    connection: &OAuthConnection,
) -> (auth_core::User, Secret) {
    let user = auth_core::User {
        id: Uuid::new_v4(),
        realm_id: connection.realm(),
        email: None,
        display_name: Some("Provider display".into()),
        authentication_policy: auth_core::AuthenticationPolicy::ProviderRequired,
    };
    let identity = Uuid::new_v4();
    let session = Uuid::new_v4();
    let secret = Secret::generate().unwrap();
    sqlx::query("INSERT INTO auth_users(realm_id,id,email,email_verified_at,display_name,authentication_policy) VALUES($1,$2,NULL,NULL,$3,'provider_required')")
        .bind(user.realm_id).bind(user.id).bind(&user.display_name).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO auth_oidc_identities(realm_id,id,connection_id,client_id,issuer,subject,user_id) VALUES($1,$2,$3,$4,$5,'owned',$6)")
        .bind(user.realm_id).bind(identity).bind(connection.connection()).bind(connection.client()).bind(connection.issuer()).bind(user.id).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authenticated_at,authentication_method,oidc_identity_id,oidc_revision) VALUES($1,$2,$3,$4,'-infinity'::timestamptz,'oidc',$5,$6)")
        .bind(user.realm_id).bind(session).bind(user.id).bind(secret.verifier().as_slice()).bind(identity).bind(connection.revision()).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO auth_audit(realm_id,user_id,kind,session_id) VALUES($1,$2,'oidc_authenticated',$3)")
        .bind(user.realm_id).bind(user.id).bind(session).execute(pool).await.unwrap();
    (user, secret)
}
