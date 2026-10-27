use super::ProbeResult;
use sqlx::PgPool;
use uuid::Uuid;

// Ciphertext is compared only inside this process. No Debug, raw output or key
// lookup/decryption exists in the feature-disabled probe.
#[derive(PartialEq, sqlx::FromRow)]
pub(super) struct Envelope {
    id: Uuid,
    connection_id: Uuid,
    client_id: Uuid,
    binding_identity_id: Uuid,
    provider_client: String,
    key_id: Uuid,
    ciphertext: String,
}
pub(super) async fn before(pool: &PgPool, realm: Uuid, owner: Uuid) -> ProbeResult<Vec<Envelope>> {
    Ok(sqlx::query_as(r#"
        SELECT g.id,g.connection_id,g.client_id,g.binding_identity_id,g.provider_client,g.key_id,g.ciphertext
        FROM auth_apple_grants g JOIN auth_oidc_identities i ON i.realm_id=g.realm_id AND i.id=g.identity_id
        WHERE g.realm_id=$1 AND i.user_id=$2 AND g.state='active' ORDER BY g.id
        "#).bind(realm).bind(owner).fetch_all(pool).await?)
}
pub(super) async fn after(
    pool: &PgPool,
    realm: Uuid,
    owner: Uuid,
    original: &[Envelope],
) -> ProbeResult<()> {
    let ids: Vec<_> = original.iter().map(|row| row.id).collect();
    let queued: Vec<Envelope> = sqlx::query_as(
        r#"
        SELECT id,connection_id,client_id,binding_identity_id,provider_client,key_id,ciphertext
        FROM auth_apple_grants WHERE realm_id=$1 AND id=ANY($2) AND state='pending'
            AND identity_id IS NULL AND attempts=0 AND queued_at IS NOT NULL
            AND expires_at=queued_at+interval '604800 seconds' ORDER BY id
        "#,
    )
    .bind(realm)
    .bind(ids)
    .fetch_all(pool)
    .await?;
    if queued != original {
        return Err("owned protected grants not preserved".into());
    }
    let remaining: i64 = sqlx::query_scalar(
        r#"
        SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1 AND id=$2)
            +(SELECT count(*) FROM auth_sessions WHERE realm_id=$1 AND user_id=$2)
            +(SELECT count(*) FROM auth_oidc_identities WHERE realm_id=$1 AND user_id=$2)
            +(SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND user_id=$2)
        "#,
    )
    .bind(realm)
    .bind(owner)
    .fetch_one(pool)
    .await?;
    if remaining != 0 {
        return Err("owned account erasure incomplete".into());
    }
    Ok(())
}
