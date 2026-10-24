use super::Auth;
use crate::{LinkedProviderCursor, LinkedProviderPage, Result, Secret};

impl Auth {
    /// Read public linked-provider metadata for the currently authenticated owner.
    pub async fn linked_providers(
        &self,
        current: &Secret,
        after: Option<LinkedProviderCursor>,
    ) -> Result<LinkedProviderPage> {
        self.repository
            .linked_providers(self.realm, current.verifier(), after)
            .await
    }
}
