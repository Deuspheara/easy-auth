//! Storage expiry fixtures only: serialized bytes are never presented as protocol proofs.
use super::keeping;
use crate::support::{realm, signed_in};
use auth_core::{RetentionCategory as Category, RetentionRepository};
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use uuid::Uuid;

struct Actor {
    realm: Uuid,
    user: Uuid,
    session: Uuid,
}

async fn actor(store: &Postgres, pool: &PgPool, realm: Uuid, email: &str) -> Actor {
    let current = signed_in(store, realm, email).await;
    let (user, session) =
        sqlx::query_as("SELECT user_id,id FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
            .bind(realm)
            .bind(current.verifier().as_slice())
            .fetch_one(pool)
            .await
            .unwrap();
    Actor {
        realm,
        user,
        session,
    }
}

async fn recovery_parent(pool: &PgPool, actor: &Actor) {
    sqlx::query("INSERT INTO auth_passkey_recovery_codes(realm_id,user_id,rp_id,version,code_hash,consumed_at) VALUES($1,$2,'example.test',gen_random_uuid(),sha256(convert_to($2::uuid::text,'UTF8')),statement_timestamp())")
        .bind(actor.realm).bind(actor.user).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO auth_passkey_recovery_claims(realm_id,user_id,rp_id,id,code_version,browser_hash,created_at,expires_at,delay_seconds,notification_required,not_before) SELECT realm_id,user_id,rp_id,gen_random_uuid(),version,decode(repeat('04',32),'hex'),statement_timestamp(),statement_timestamp()+interval '7 days',1,false,statement_timestamp()+interval '1 second' FROM auth_passkey_recovery_codes WHERE realm_id=$1 AND user_id=$2")
        .bind(actor.realm).bind(actor.user).execute(pool).await.unwrap();
}

const ACTOR: &str = "WITH actor AS (SELECT $1::uuid AS realm,$2::uuid AS owner,$3::uuid AS session,statement_timestamp()+make_interval(secs=>$4::integer) AS expiry) ";

// Each named row exercises one owning feature's expiry column and independent
// realm scope. Live rows are deliberately retained beside expired rows.
const CASES: &[(Category, &str, &str)] = &[
    (
        Category::EmailChallenges,
        "auth_email_challenges",
        "INSERT INTO auth_email_challenges(realm_id,token_hash,browser_hash,email,expires_at) SELECT realm,sha256(convert_to(owner::text,'UTF8')),decode(repeat('01',32),'hex'),'owned@example.test',expiry FROM actor",
    ),
    (
        Category::PasswordResets,
        "auth_password_resets",
        "INSERT INTO auth_password_resets(realm_id,token_hash,browser_hash,email,expires_at) SELECT realm,sha256(convert_to(owner::text,'UTF8')),decode(repeat('01',32),'hex'),'owned@example.test',expiry FROM actor",
    ),
    (
        Category::EmailChanges,
        "auth_email_changes",
        "INSERT INTO auth_email_changes(realm_id,id,user_id,session_id,old_email,new_email,old_hash,new_hash,browser_hash,expires_at) SELECT realm,gen_random_uuid(),owner,session,'old@example.test','new@example.test',sha256(convert_to(owner::text,'UTF8')),sha256(convert_to(owner::text||':new','UTF8')),decode(repeat('01',32),'hex'),expiry FROM actor",
    ),
    (
        Category::AccountDeletions,
        "auth_account_deletions",
        "INSERT INTO auth_account_deletions(realm_id,user_id,session_id,email,token_hash,browser_hash,expires_at) SELECT realm,owner,session,'owned@example.test',sha256(convert_to(owner::text,'UTF8')),decode(repeat('01',32),'hex'),expiry FROM actor",
    ),
    (
        Category::EmailAttachments,
        "auth_email_attachments",
        "INSERT INTO auth_email_attachments(realm_id,user_id,session_id,email,token_hash,browser_hash,expires_at) SELECT realm,owner,session,'owned@example.test',sha256(convert_to(owner::text,'UTF8')),decode(repeat('01',32),'hex'),expiry FROM actor",
    ),
    (
        Category::PasskeyEnrollments,
        "auth_passkey_enrollments",
        "INSERT INTO auth_passkey_enrollments(realm_id,id,user_id,session_id,browser_hash,rp_id,label,private_state,expires_at) SELECT realm,gen_random_uuid(),owner,session,decode(repeat('01',32),'hex'),'example.test','owned',decode('01','hex'),expiry FROM actor",
    ),
    (
        Category::PasskeyAuthentications,
        "auth_passkey_authentications",
        "INSERT INTO auth_passkey_authentications(realm_id,id,user_id,purpose,browser_hash,rp_id,private_state,expires_at) SELECT realm,gen_random_uuid(),owner,'account_bound',decode(repeat('01',32),'hex'),'example.test',decode('01','hex'),expiry FROM actor",
    ),
    (
        Category::PasskeySignups,
        "auth_passkey_signups",
        "INSERT INTO auth_passkey_signups(realm_id,id,prospective_user,browser_hash,rp_id,display_name,stage,registration_state,expires_at) SELECT realm,gen_random_uuid(),gen_random_uuid(),decode(repeat('01',32),'hex'),'example.test','Owned user','registration',decode('01','hex'),expiry FROM actor",
    ),
    (
        Category::RecoverySetups,
        "auth_passkey_recovery_setups",
        "INSERT INTO auth_passkey_recovery_setups(realm_id,user_id,rp_id,id,session_id,code_hash,expires_at) SELECT realm,owner,'example.test',gen_random_uuid(),session,sha256(convert_to(owner::text,'UTF8')),expiry FROM actor",
    ),
    (
        Category::RecoveryReplacements,
        "auth_passkey_recovery_replacements",
        "INSERT INTO auth_passkey_recovery_replacements(realm_id,claim_id,id,user_id,registration_state,expires_at) SELECT a.realm,c.id,gen_random_uuid(),a.owner,decode('01','hex'),a.expiry FROM actor a JOIN auth_passkey_recovery_claims c ON c.realm_id=a.realm AND c.user_id=a.owner",
    ),
];

#[sqlx::test(migrations = "./migrations")]
async fn every_local_pending_proof_category_prunes_expired_only_and_preserves_foreign_rows(
    pool: PgPool,
) {
    let (store, a) = realm(pool.clone()).await;
    let b = Uuid::new_v4();
    store.ensure_realm(b).await.unwrap();
    let expired = actor(&store, &pool, a, "owned-expired@example.test").await;
    let live = actor(&store, &pool, a, "owned-live@example.test").await;
    let foreign = actor(&store, &pool, b, "owned-foreign@example.test").await;
    for actor in [&expired, &live, &foreign] {
        recovery_parent(&pool, actor).await;
    }
    for &(category, table, insert) in CASES {
        let query = format!("{ACTOR}{insert}");
        for (actor, seconds) in [(&expired, -60), (&live, 60), (&foreign, -60)] {
            sqlx::query(&query)
                .bind(actor.realm)
                .bind(actor.user)
                .bind(actor.session)
                .bind(seconds)
                .execute(&pool)
                .await
                .unwrap();
        }
        assert_eq!(
            store
                .retain_batch(a, category, keeping())
                .await
                .unwrap()
                .deleted,
            1,
            "one expired local proof is eligible for {category:?}"
        );
        let query = format!("SELECT count(*) FROM {table} WHERE realm_id=$1");
        let selected: i64 = sqlx::query_scalar(&query)
            .bind(a)
            .fetch_one(&pool)
            .await
            .unwrap();
        let other: i64 = sqlx::query_scalar(&query)
            .bind(b)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!((selected, other), (1, 1));
        assert_eq!(
            store
                .retain_batch(a, category, keeping())
                .await
                .unwrap()
                .deleted,
            0
        );
    }
}
