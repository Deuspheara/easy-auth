use super::clock;
use crate::{
    Postgres, deadlines::Deadline, issuer::configuration, sessions::FreshSessionSnapshot,
    unavailable,
};
use auth_core::{
    Error, ISSUER_AUTHORIZATION_LIFETIME_SECONDS, IssuerAuthorizationRequest,
    MAX_ISSUER_PENDING_PER_OWNER, MAX_ISSUER_PENDING_PER_REALM, Result, Verifier,
};

pub(super) async fn save(
    store: &Postgres,
    request: &IssuerAuthorizationRequest,
    current: Verifier,
    browser: Verifier,
    handle: Verifier,
) -> Result<i64> {
    let realm = request.authority().realm();
    let snapshot = FreshSessionSnapshot::load(&store.pool, realm, current).await?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    let created = clock::now(&mut tx).await?;
    let original = created
        .checked_add(ISSUER_AUTHORIZATION_LIFETIME_SECONDS * 1_000_000)
        .ok_or(Error::Unavailable)?;
    // Realm admission -> current client -> provider source/email/owner/session ->
    // this owner's operation rows. Never prune another owner's rows under this lock.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text || ':issuer_pending',0))",
    )
    .bind(realm)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    configuration::lock(&mut tx, request.client(), true).await?;
    let caller = snapshot.lock(&mut tx).await?;
    let deadline = Deadline::proof(original).with_proof(caller.deadline.expires_us());
    let now = clock::now(&mut tx).await?;
    sqlx::query("DELETE FROM auth_issuer_authorizations WHERE realm_id=$1 AND user_id=$2 AND status='pending' AND expires_at_us<=$3")
        .bind(realm).bind(caller.user).bind(now).execute(&mut *tx).await.map_err(unavailable)?;
    sqlx::query(
        r#"
            UPDATE auth_issuer_authorizations
            SET status='expired',state=NULL,nonce=NULL,pkce_challenge=NULL
            WHERE realm_id=$1
            AND user_id=$2
            AND status='approved'
            AND code_expires_at_us<=$3
        "#,
    )
    .bind(realm)
    .bind(caller.user)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    let (total, own): (i64, i64) = sqlx::query_as(
        r#"
            SELECT count(*),count(*) FILTER(WHERE user_id=$2)
            FROM auth_issuer_authorizations
            WHERE realm_id=$1
            AND status IN ('pending','approved')
            AND coalesce(code_expires_at_us,expires_at_us)>$3
        "#,
    )
    .bind(realm)
    .bind(caller.user)
    .bind(now)
    .fetch_one(&mut *tx)
    .await
    .map_err(unavailable)?;
    if total >= MAX_ISSUER_PENDING_PER_REALM || own >= MAX_ISSUER_PENDING_PER_OWNER {
        return Err(Error::RateLimited);
    }
    sqlx::query(
        r#"
            INSERT INTO auth_issuer_authorizations(realm_id,
                id,
                issuer,
                client_id,
                client_revision,
                sector,
                user_id,
                session_id,
                authentication_method,
                authenticated_at_us,
                session_cap_us,
                handle_hash,
                browser_hash,
                redirect_uri,
                state,
                nonce,
                pkce_challenge,
                created_at_us,
                expires_at_us)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
        "#,
    )
    .bind(realm)
    .bind(request.id())
    .bind(request.authority().issuer())
    .bind(request.client().client())
    .bind(request.client().revision())
    .bind(request.client().sector())
    .bind(caller.user)
    .bind(caller.session)
    .bind(&caller.method)
    .bind(caller.authenticated_at_us)
    .bind(caller.deadline.expires_us())
    .bind(handle.as_slice())
    .bind(browser.as_slice())
    .bind(request.redirect_uri())
    .bind(request.state())
    .bind(request.nonce())
    .bind(request.pkce_challenge().as_slice())
    .bind(created)
    .bind(deadline.expires_us())
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(deadline.expires_us())
}
