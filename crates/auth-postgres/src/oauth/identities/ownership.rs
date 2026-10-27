#[cfg(not(feature = "oidc-linking"))]
use crate::identity::lock_provider_user;
use crate::{identity::user_from_row, unavailable};
use auth_core::{Error, OidcJitPolicy, OidcMappedIdentity, Result, User};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn resolve(
    tx: &mut Transaction<'_, Postgres>,
    mapped: &OidcMappedIdentity,
) -> Result<(User, Uuid)> {
    let proof = mapped.identity();
    let c = proof.configuration();
    super::subject::lock(
        tx,
        c.realm(),
        c.connection(),
        c.client(),
        c.issuer(),
        proof.subject(),
    )
    .await?;
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
        #[cfg(not(feature = "oidc-linking"))]
        let user = lock_provider_user(tx, c.realm(), owner, email.as_deref()).await?;
        #[cfg(feature = "oidc-linking")]
        let user =
            crate::identity::lock_user_snapshot(tx, c.realm(), owner, email.as_deref()).await?;
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
        #[cfg(feature = "oidc-linking")]
        {
            let linked:bool=sqlx::query_scalar("SELECT explicitly_linked FROM auth_oidc_identities WHERE realm_id=$1 AND id=$2 AND user_id=$3")
                .bind(c.realm()).bind(identity).bind(owner).fetch_one(&mut **tx).await.map_err(unavailable)?;
            if !user
                .authentication_policy
                .permits_session_method("oidc", linked)
            {
                return Err(Error::Unauthorized);
            }
        }
        // A vanished owner never falls through to JIT in an old callback.
        return Ok((user, identity));
    }
    if mapped.policy().jit() != OidcJitPolicy::Allow {
        return Err(Error::Unauthorized);
    }
    let display_name = mapped.display_name().ok_or(Error::Unauthorized)?;
    super::subject::reject_deleted(tx, mapped).await?;
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
