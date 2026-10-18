use super::Auth;
use crate::{Result, Secret, User};

impl Auth {
    pub async fn authenticate(&self, session: &Secret) -> Result<User> {
        self.repository
            .authenticate(self.realm, session.verifier())
            .await
    }
    pub async fn logout(&self, session: &Secret) -> Result<()> {
        self.repository.revoke(self.realm, session.verifier()).await
    }
}
