use auth_core::ProviderKind;
use sqlx::PgPool;
use uuid::Uuid;

/// Trusted inventory records only. This never issues a session or constructs a
/// verified identity; callers authenticate through the normal email/provider flow.
pub(crate) async fn insert(pool: &PgPool, realm: Uuid, owner: Uuid, id: Uuid, kind: ProviderKind) {
    match kind {
        ProviderKind::Oidc => oidc(pool, realm, owner, id).await,
        ProviderKind::Saml => saml(pool, realm, owner, id).await,
    }
}

async fn oidc(pool: &PgPool, realm: Uuid, owner: Uuid, id: Uuid) {
    sqlx::query(
        "INSERT INTO auth_oauth_connections
        (realm_id,id,client_id,revision,issuer,provider_client,redirect_uri,defense,enabled)
        VALUES ($1,$2,$2,$3,'https://oidc.example','owned-client',$4,'issuer',false)",
    )
    .bind(realm)
    .bind(id)
    .bind(Uuid::new_v4())
    .bind(format!("https://app.example/{realm}/{id}"))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO auth_oidc_identities
        (realm_id,id,connection_id,client_id,issuer,subject,user_id)
        VALUES ($1,$2,$2,$2,'https://oidc.example','private-oidc-subject',$3)",
    )
    .bind(realm)
    .bind(id)
    .bind(owner)
    .execute(pool)
    .await
    .unwrap();
}

async fn saml(pool: &PgPool, realm: Uuid, owner: Uuid, id: Uuid) {
    sqlx::query(
        "INSERT INTO auth_saml_registrations
        (realm_id,id,client_id,revision,sp_entity,idp_entity,sso_url,acs_url,enabled)
        VALUES ($1,$2,$2,$3,'https://sp.example','https://saml.example',
          'https://saml.example/sso','https://app.example/saml/acs',false)",
    )
    .bind(realm)
    .bind(id)
    .bind(Uuid::new_v4())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO auth_saml_identities
        (realm_id,id,connection_id,client_id,idp_entity,sp_entity,subject,user_id,subject_hash)
        VALUES ($1,$2,$2,$2,'https://saml.example','https://sp.example',
          'private-saml-subject',$3,auth_saml_subject_key($1,$2,$2,
            'https://saml.example','https://sp.example','private-saml-subject'))",
    )
    .bind(realm)
    .bind(id)
    .bind(owner)
    .execute(pool)
    .await
    .unwrap();
}
