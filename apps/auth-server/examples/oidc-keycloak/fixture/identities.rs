use super::*;

impl Fixture {
    #[cfg(feature = "oidc-identities")]
    async fn configure_identity(&mut self, jit: OidcJitPolicy) -> auth_core::Result<Value> {
        if self.pending.is_some() {
            return Err(Error::InvalidInput);
        }
        let policy = match &self.identities {
            Some(cases) => cases.policy().clone().with_jit(jit),
            None => OidcIdentityPolicy::new(
                self.connection.clone(),
                &[self.connection.issuer()],
                OidcDisplayNameClaim::Name,
            )?
            .with_jit(jit),
        };
        let policy = self.store.configure_oidc_identity_policy(&policy).await?;
        if self.identities.is_none() {
            self.store
                .enable_oauth_connection(policy.configuration())
                .await?;
        }
        self.connection = policy.configuration().clone();
        self.transactions = OAuthTransactions::new(self.connection.clone(), self.store.clone());
        self.exchange = crate::protocol::exchange(
            &self.connection,
            self.store.clone(),
            self.http.clone(),
            self.credential.to_string(),
        )
        .map_err(|_| Error::Unavailable)?;
        let previous = match &mut self.identities {
            Some(cases) => cases.reconfigured(policy).await?,
            None => {
                self.identities = Some(Identities::new(
                    self.store.clone(),
                    self.pool.clone(),
                    policy,
                ));
                None
            }
        };
        Ok(json!({"result":"identity_configured","previous_provider_session_rejected":previous}))
    }
    pub(super) async fn identity_command(&mut self, command: &Value) -> auth_core::Result<Value> {
        match command["command"].as_str() {
            Some("identity_configure") => {
                self.configure_identity(match command["jit"].as_str() {
                    Some("deny") => OidcJitPolicy::Deny,
                    Some("allow") => OidcJitPolicy::Allow,
                    _ => return Err(Error::InvalidInput),
                })
                .await
            }
            Some("identity_mailbox") => {
                self.identities
                    .as_mut()
                    .ok_or(Error::InvalidInput)?
                    .mailbox(command["email"].as_str().ok_or(Error::InvalidInput)?)
                    .await
            }
            Some("identity_profile") => {
                self.identities
                    .as_mut()
                    .ok_or(Error::InvalidInput)?
                    .profile(command["enabled"].as_bool().ok_or(Error::InvalidInput)?);
                Ok(json!({"result":"profile_configured"}))
            }
            Some("identity_finish_held") => {
                if self.identities.is_none() {
                    return Err(Error::InvalidInput);
                }
                self.finish(
                    command["callback"].as_str().ok_or(Error::InvalidInput)?,
                    true,
                )
                .await
            }
            Some("identity_resolve_held") => {
                self.identities
                    .as_mut()
                    .ok_or(Error::InvalidInput)?
                    .resolve_held()
                    .await
            }
            Some("identity_status") => {
                self.identities
                    .as_ref()
                    .ok_or(Error::InvalidInput)?
                    .status()
                    .await
            }
            _ => Err(Error::InvalidInput),
        }
    }
}
