use crate::{Postgres, unavailable};
use auth_core::Result;
use uuid::Uuid;

impl Postgres {
    pub(crate) async fn complete_security_notice(
        &self,
        realm: Uuid,
        id: Uuid,
        lease: Uuid,
        delivered: bool,
    ) -> Result<()> {
        if delivered {
            super::recovery_receipt::delivered(&self.pool, realm, id, lease).await?;
        } else {
            sqlx::query(r#"
    UPDATE auth_security_notifications
    SET lease_id=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()+make_interval(secs=>30*power(2,least(attempts-1,7)))
    WHERE realm_id=$1
    AND id=$2
    AND lease_id=$3
"#)
                .bind(realm)
                .bind(id)
                .bind(lease)
                .execute(&self.pool)
                .await
                .map_err(unavailable)?;
        }
        Ok(())
    }
}
