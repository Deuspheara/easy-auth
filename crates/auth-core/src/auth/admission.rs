use super::Auth;
use crate::{Result, Secret};
use sha2::{Digest, Sha256};

impl Auth {
    pub(super) async fn admit_sensitive_action(
        &self,
        current: &Secret,
        source: &str,
    ) -> Result<()> {
        let user = self.authenticate(current).await?;
        self.repository
            .admit_password(
                self.realm,
                &user.email,
                Sha256::digest(source.as_bytes()).into(),
            )
            .await
    }
}
