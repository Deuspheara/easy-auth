use super::{Database, FixtureResult, Source};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction};
use std::time::Duration;

const AUDIT_LOCK: i64 = 5604;
pub(super) struct Gate {
    transaction: Transaction<'static, Postgres>,
    audit: bool,
    cap: i64,
}
impl Gate {
    pub async fn hold(
        database: &Database,
        observer: &PgPool,
        source: &Source,
        command: &Value,
    ) -> FixtureResult<Self> {
        let (count,cap):(i64,Option<i64>)=sqlx::query_as("SELECT count(*),min((extract(epoch FROM expires_at)*1000000)::bigint) FROM auth_oauth_transactions WHERE realm_id=$1")
            .bind(source.realm).fetch_one(observer).await?;
        if count != 1 {
            return Err("one real pending callback required".into());
        }
        let cap = cap.ok_or("missing original cap")?;
        let audit = command["command"].as_str() == Some("hold_audit");
        if audit {
            sqlx::raw_sql("CREATE OR REPLACE FUNCTION hold_owned_web_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(5604); RETURN NEW; END $$; DROP TRIGGER IF EXISTS hold_owned_web_audit ON auth_audit; CREATE TRIGGER hold_owned_web_audit BEFORE INSERT ON auth_audit FOR EACH ROW WHEN (NEW.kind='oidc_authenticated') EXECUTE FUNCTION hold_owned_web_audit();")
                .execute(&database.pool).await?;
        }
        let mut transaction = database.pool.begin().await?;
        if audit {
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(AUDIT_LOCK)
                .execute(&mut *transaction)
                .await?;
        } else {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode(auth_oidc_subject_key($1,$2,$3,$4,$5),'hex'),0))")
                .bind(source.realm).bind(source.connection).bind(source.client).bind(&source.issuer)
                .bind(command["subject"].as_str().ok_or("owned subject required")?).execute(&mut *transaction).await?;
        }
        Ok(Self {
            transaction,
            audit,
            cap,
        })
    }
    pub async fn observe(&self, pool: &PgPool) -> FixtureResult<Value> {
        tokio::time::timeout(Duration::from_secs(5),async {
            loop {
                let pattern=if self.audit{"%INSERT INTO auth_audit%"}else{"%SELECT pg_advisory_xact_lock(hashtextextended(encode(auth_oidc_subject_key%"};
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)")
                    .bind(pattern).fetch_one(pool).await?;
                if waiting {break;}
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<(),sqlx::Error>(())
        }).await.map_err(|_|"actual application completion wait not observed")??;
        let live: bool =
            sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint<$1")
                .bind(self.cap)
                .fetch_one(pool)
                .await?;
        Ok(
            json!({"result":"waiting","original_cap_live":live,"gate":if self.audit{"final_audit"}else{"verified_subject_resolution"}}),
        )
    }
    pub async fn release(self) -> FixtureResult<()> {
        self.transaction.commit().await?;
        Ok(())
    }
}
