use crate::{identity::user_from_row, locking::lock_email, unavailable};
use auth_core::{AuthenticationPolicy, Error, OidcJitPolicy, OidcMappedIdentity, Result, User};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

const DELETED_SUBJECT_CLEANUP_BATCH: i64 = 32;

pub(super) async fn resolve(
    tx: &mut Transaction<'_, Postgres>,
    mapped: &OidcMappedIdentity,
) -> Result<(User, Uuid)> {
    let proof = mapped.identity();
    let c = proof.configuration();
    // Canonical scoped hash is a serialization key, not authentication authority.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode(auth_oidc_subject_key($1,$2,$3,$4,$5),'hex'),0))")
        .bind(c.realm())
        .bind(c.connection())
        .bind(c.client())
        .bind(c.issuer())
        .bind(proof.subject())
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    let existing: Option<(Uuid,Uuid,Option<String>)> = sqlx::query_as(r#"
        SELECT e.id,e.user_id,u.email FROM auth_oidc_identities e
        JOIN auth_users u ON u.realm_id=e.realm_id AND u.id=e.user_id
        WHERE e.realm_id=$1 AND e.connection_id=$2 AND e.client_id=$3 AND e.issuer=$4 AND e.subject=$5
    "#)
        .bind(c.realm())
        .bind(c.connection())
        .bind(c.client())
        .bind(c.issuer())
        .bind(proof.subject())
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?;
    if let Some((identity, owner, email)) = existing {
        if let Some(email) = &email {
            lock_email(tx, c.realm(), email).await?;
        }
        let row = sqlx::query(
            r#"
            SELECT id,email,display_name,authentication_policy FROM auth_users
            WHERE realm_id=$1 AND id=$2 AND email IS NOT DISTINCT FROM $3::text
            FOR UPDATE
        "#,
        )
        .bind(c.realm())
        .bind(owner)
        .bind(email)
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
        let user = user_from_row(c.realm(), &row)?;
        if user.authentication_policy != AuthenticationPolicy::ProviderRequired {
            return Err(Error::Unauthorized);
        }
        let bound: Option<Uuid> = sqlx::query_scalar(
            r#"
            SELECT id FROM auth_oidc_identities
            WHERE realm_id=$1 AND id=$2 AND user_id=$3 AND connection_id=$4
              AND client_id=$5 AND issuer=$6 AND subject=$7 FOR UPDATE
        "#,
        )
        .bind(c.realm())
        .bind(identity)
        .bind(owner)
        .bind(c.connection())
        .bind(c.client())
        .bind(c.issuer())
        .bind(proof.subject())
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?;
        if bound != Some(identity) {
            return Err(Error::Unauthorized);
        }
        // A vanished owner never falls through to JIT in an old callback.
        return Ok((user, identity));
    }
    if mapped.policy().jit() != OidcJitPolicy::Allow {
        return Err(Error::Unauthorized);
    }
    let display_name = mapped.display_name().ok_or(Error::Unauthorized)?;
    reject_deleted_subject(tx, mapped).await?;
    let id = Uuid::new_v4();
    let row = sqlx::query(r#"
        INSERT INTO auth_users(realm_id,id,email,email_verified_at,display_name,authentication_policy)
        VALUES($1,$2,NULL,NULL,$3,'provider_required')
        RETURNING id,email,display_name,authentication_policy
    "#)
        .bind(c.realm())
        .bind(id)
        .bind(display_name)
        .fetch_one(&mut **tx)
        .await
        .map_err(unavailable)?;
    let identity = Uuid::new_v4();
    sqlx::query("INSERT INTO auth_oidc_identities(realm_id,id,connection_id,client_id,issuer,subject,user_id) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(c.realm())
        .bind(identity)
        .bind(c.connection())
        .bind(c.client())
        .bind(c.issuer())
        .bind(proof.subject())
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    Ok((user_from_row(c.realm(), &row)?, identity))
}

async fn reject_deleted_subject(
    tx: &mut Transaction<'_, Postgres>,
    mapped: &OidcMappedIdentity,
) -> Result<()> {
    let c = mapped.identity().configuration();
    // Only a new-owner path prunes expired hashes, before acquiring any owner lock.
    sqlx::query(
        r#"
        DELETE FROM auth_oidc_deleted_subjects WHERE ctid IN (
          SELECT ctid FROM auth_oidc_deleted_subjects
          WHERE realm_id=$1 AND blocked_until<=clock_timestamp()
          ORDER BY blocked_until LIMIT $2 FOR UPDATE SKIP LOCKED)
    "#,
    )
    .bind(c.realm())
    .bind(DELETED_SUBJECT_CLEANUP_BATCH)
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?;
    let blocked: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(SELECT 1 FROM auth_oidc_deleted_subjects
        WHERE realm_id=$1 AND subject_hash=auth_oidc_subject_key($1,$2,$3,$4,$5)
          AND blocked_until>clock_timestamp())
    "#,
    )
    .bind(c.realm())
    .bind(c.connection())
    .bind(c.client())
    .bind(c.issuer())
    .bind(mapped.identity().subject())
    .fetch_one(&mut **tx)
    .await
    .map_err(unavailable)?;
    if blocked {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
