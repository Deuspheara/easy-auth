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
        let source = Sha256::digest(source.as_bytes()).into();
        match user.email.as_deref() {
            Some(email) => {
                self.repository
                    .admit_password(self.realm, email, source)
                    .await
            }
            None => {
                self.repository
                    .admit_user_action(self.realm, user.id, source)
                    .await
            }
        }
    }
}
