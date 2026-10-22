use super::authorization;
use crate::{Postgres, deadlines::Deadline, saml::identity_policy, unavailable};
use auth_core::{
    Error, MAX_SAML_PENDING_PER_CONNECTION, Result, SAML_REQUEST_LIFETIME_SECONDS,
    SamlRegistration, SamlRequestAdmission, Verifier,
};

pub(super) async fn save(
    store: &Postgres,
    reg: &SamlRegistration,
    current: Verifier,
    admission: SamlRequestAdmission<'_>,
) -> Result<i64> {
    admission.validate()?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    let request_cap: i64 = sqlx::query_scalar(
        "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint+$1*1000000",
    )
    .bind(SAML_REQUEST_LIFETIME_SECONDS)
    .fetch_one(&mut *tx)
    .await
    .map_err(unavailable)?;
    identity_policy::load(&mut tx, reg).await?;
    let owner = authorization::lock(&mut tx, reg, current).await?;
    let deadline = owner.deadline.with_proof(request_cap);
    deadline.check(&mut tx).await?;
    sqlx::query("DELETE FROM auth_saml_requests WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3 AND expires_at<=clock_timestamp()")
        .bind(reg.realm())
        .bind(reg.connection())
        .bind(reg.client())
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_saml_requests WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3")
        .bind(reg.realm())
        .bind(reg.connection())
        .bind(reg.client())
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
    if pending >= MAX_SAML_PENDING_PER_CONNECTION {
        return Err(Error::RateLimited);
    }
    let cap = deadline.expires_us();
    let b = owner.binding;
    let inserted = sqlx::query(r#"
        WITH observed AS MATERIALIZED (SELECT clock_timestamp() AS now)
        INSERT INTO auth_saml_requests(realm_id,connection_id,client_id,revision,request_id,relay_hash,browser_hash,created_at,expires_at,purpose,user_id,session_id,identity_id)
        SELECT $1,$2,$3,$4,$5,$6,$7,observed.now,
          TIMESTAMPTZ 'epoch'+($8::bigint/1000000)*interval '1 second'+($8::bigint%1000000)*interval '1 microsecond',
          'delete_account',$9,$10,$11 FROM observed
        WHERE (extract(epoch FROM observed.now)*1000000)::bigint<$8
    "#)
    .bind(reg.realm())
    .bind(reg.connection())
    .bind(reg.client())
    .bind(reg.revision())
    .bind(admission.request_id)
    .bind(admission.relay.as_slice())
    .bind(admission.browser.as_slice())
    .bind(cap)
    .bind(b.user)
    .bind(b.session)
    .bind(b.identity)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?
    .rows_affected();
    if inserted != 1 {
        return Err(Error::Unauthorized);
    }
    Deadline::proof(cap).check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(cap / 1000)
}
