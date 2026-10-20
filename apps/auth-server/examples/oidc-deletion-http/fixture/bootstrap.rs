use super::*;

impl Fixture {
    pub(super) async fn begin(&mut self) -> auth_core::Result<Value> {
        if self.pending.is_some() {
            return Err(Error::InvalidInput);
        }
        let browser = Secret::generate()?;
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-keycloak",
            purpose: OAuthPurpose::SignIn,
        };
        let start = self.transactions.begin(&intent).await?;
        let url = self.exchange.authorization_url(&start, &[]).await?;
        let value = json!({"result":"started","authorization":url.expose()});
        self.pending = Some(Pending {
            browser,
            start,
            purpose: OAuthPurpose::SignIn,
        });
        Ok(value)
    }
    pub(super) async fn finish(&mut self, callback: &str) -> auth_core::Result<Value> {
        let (context, replay, code) = self
            .pending
            .take()
            .ok_or(Error::InvalidInput)?
            .consume(&self.transactions, self.policy.configuration(), callback)
            .await?;
        self.replay = Some(replay);
        let verified = self
            .exchange
            .exchange(context, OidcAuthorizationCode::parse(code?)?)
            .await?;
        if verified.subject() != self.observation.subject {
            return Err(Error::Unauthorized);
        }
        let evidence = self.verified_evidence(&verified).await?;
        let (user, session) = match OidcSignIn::new(self.store.clone())
            .finish(self.policy.map(verified)?)
            .await
        {
            Ok(issued) => issued,
            Err(error) => {
                let mut value = classified(Err(error));
                value["verified_proof"] = evidence;
                return Ok(value);
            }
        };
        self.observation.bind(user.id, &session);
        let capability = self.server.bootstrap.arm(&session)?;
        self.current = Some(session);
        // Private pipe transports a one-use fixture capability, never the bearer.
        Ok(
            json!({"result":"authenticated","bootstrap_capability":capability.expose(),"local_contact_absent":user.email.is_none(),"verified_proof":evidence}),
        )
    }
    async fn verified_evidence(&self, identity: &VerifiedOidcIdentity) -> auth_core::Result<Value> {
        let now_us: i64 =
            sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
                .fetch_one(&self.pool)
                .await
                .map_err(|_| Error::Unavailable)?;
        let now = now_us / 1_000_000;
        Ok(json!({"verified_before_resolution":true,
            "configuration_matches":identity.configuration()==self.policy.configuration(),
            "subject_matches":identity.subject()==self.observation.subject,
            "sign_in_purpose":matches!(identity.purpose(),OAuthPurpose::SignIn),
            "signed_time_recent":identity.authenticated_at().is_some_and(|time| i128::from(time)<=i128::from(now) && i128::from(now)-i128::from(time)<=i128::from(MAX_OIDC_DELETION_AUTH_AGE_SECONDS)),
            "original_cap_live":identity.expires_us()>now_us}))
    }
}
