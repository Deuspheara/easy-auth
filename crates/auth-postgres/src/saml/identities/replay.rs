use crate::unavailable;
use auth_core::{Error, Result, SamlRegistration, SamlReplayKind, VerifiedSamlAssertion};
use sqlx::{PgPool, Postgres, Transaction};

const REPLAY_CLEANUP_BATCH: i64 = 32;

pub(super) async fn prune(pool: &PgPool, reg: &SamlRegistration) -> Result<()> {
    // Separate autocommit statement; no owner/source/replay reservation lock is
    // retained into sign-in. Outer expiry is rechecked after any row wait.
    sqlx::query("DELETE FROM auth_saml_replays WHERE realm_id=$1 AND connection_id=$2 AND retain_until<=clock_timestamp() AND ctid IN (SELECT ctid FROM auth_saml_replays WHERE realm_id=$1 AND connection_id=$2 AND retain_until<=clock_timestamp() ORDER BY identifier_hash LIMIT $3 FOR UPDATE SKIP LOCKED)")
        .bind(reg.realm()).bind(reg.connection()).bind(REPLAY_CLEANUP_BATCH)
        .execute(pool).await.map_err(unavailable)?;
    Ok(())
}

pub(super) async fn reserve(
    tx: &mut Transaction<'_, Postgres>,
    proof: &VerifiedSamlAssertion,
) -> Result<()> {
    let reg = proof.registration();
    let mut keys: Vec<_> = proof.replay_reservations().iter().collect();
    if keys.len() != 2 {
        return Err(Error::Unavailable);
    }
    // All clients of this connection acquire both unique keys in the same order.
    keys.sort_unstable_by(|a, b| a.hash().cmp(b.hash()));
    for key in keys {
        let kind = match key.kind() {
            SamlReplayKind::Response => "response",
            SamlReplayKind::Assertion => "assertion",
        };
        let owned: Option<bool> = sqlx::query_scalar(r#"
            INSERT INTO auth_saml_replays(realm_id,connection_id,identifier_hash,kind,retain_until)
            VALUES($1,$2,$3,$4,TIMESTAMPTZ 'epoch'+($5::bigint/1000000)*interval '1 second'+($5::bigint%1000000)*interval '1 microsecond')
            ON CONFLICT (realm_id,connection_id,identifier_hash) DO UPDATE SET kind=EXCLUDED.kind,retain_until=EXCLUDED.retain_until
            WHERE auth_saml_replays.retain_until<=clock_timestamp() RETURNING true
        "#).bind(reg.realm()).bind(reg.connection()).bind(key.hash().as_slice()).bind(kind).bind(key.retain_until_us())
            .fetch_optional(&mut **tx).await.map_err(unavailable)?;
        if owned != Some(true) {
            return Err(Error::Unauthorized);
        }
    }
    Ok(())
}
