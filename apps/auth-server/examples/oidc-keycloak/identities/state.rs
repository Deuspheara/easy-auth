use super::evidence;
use auth_core::*;
use auth_postgres::Postgres;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::sync::Arc;

struct Held {
    proof: OidcMappedIdentity,
    evidence: Value,
}
pub(crate) struct Identities {
    pub(super) store: Arc<Postgres>,
    pub(super) pool: PgPool,
    pub(super) policy: OidcIdentityPolicy,
    mailbox: Option<(User, Secret)>,
    pub(super) provider: Option<(User, Secret)>,
    held: Option<Held>,
    profile: bool,
}
impl Identities {
    pub(crate) fn new(store: Arc<Postgres>, pool: PgPool, policy: OidcIdentityPolicy) -> Self {
        Self {
            store,
            pool,
            policy,
            mailbox: None,
            provider: None,
            held: None,
            profile: true,
        }
    }
    pub(crate) fn policy(&self) -> &OidcIdentityPolicy {
        &self.policy
    }
    pub(crate) fn profile(&mut self, enabled: bool) {
        self.profile = enabled;
    }
    pub(crate) fn scopes(&self) -> &'static [&'static str] {
        if self.profile {
            &["profile", "email"]
        } else {
            &["email"]
        }
    }
    pub(crate) async fn reconfigured(
        &mut self,
        policy: OidcIdentityPolicy,
    ) -> Result<Option<bool>> {
        self.policy = policy;
        match &self.provider {
            Some((_, session)) => Ok(Some(
                evidence::rejects(&self.store, self.policy.configuration(), session).await?,
            )),
            None => Ok(None),
        }
    }
    pub(crate) async fn mailbox(&mut self, email: &str) -> Result<Value> {
        if self.mailbox.is_some() {
            return Err(Error::InvalidInput);
        }
        let realm = self.policy.configuration().realm();
        let proof = Secret::generate()?;
        let browser = Secret::generate()?;
        let session = Secret::generate()?;
        // Actual bound repository proof flow, not a seeded user/session or SMTP claim.
        self.store
            .begin_email(realm, email, proof.verifier(), browser.verifier(), [30; 32])
            .await?;
        let user = self
            .store
            .finish_email(
                realm,
                proof.verifier(),
                browser.verifier(),
                session.verifier(),
            )
            .await?;
        let valid = self.store.authenticate(realm, session.verifier()).await? == user;
        self.mailbox = Some((user, session));
        Ok(json!({"result":"mailbox_prepared","mailbox_session_valid":valid}))
    }
    pub(crate) async fn verified(
        &mut self,
        identity: VerifiedOidcIdentity,
        cap: i64,
        subject: &str,
        hold: bool,
    ) -> Result<Value> {
        if self.held.is_some() {
            return Err(Error::InvalidInput);
        }
        let cap_live: bool = sqlx::query_scalar(
            "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint < $1",
        )
        .bind(identity.expires_us())
        .fetch_one(&self.pool)
        .await
        .map_err(|_| Error::Unavailable)?;
        if !cap_live {
            return Err(Error::Unavailable);
        }
        let mut details = json!({"verified_before_resolution":true,"subject_matches_original":identity.subject()==subject,
            "verified_configuration_matched":identity.configuration()==self.policy.configuration(),
            "original_cap_retained":identity.expires_us()<=cap,
            "provider_email_matches_mailbox":identity.email().is_some() && identity.email()==self.mailbox.as_ref().and_then(|(user,_)|user.email.as_deref()),
            "provider_email_verified":identity.email_verified(),"provider_name_absent":identity.name().is_none()});
        let mapped = self.policy.map(identity)?;
        details["original_cap_live"] = true.into();
        details["selected_display_present"] = mapped.display_name().is_some().into();
        if matches!(
            mapped.identity().purpose(),
            OAuthPurpose::DeleteProviderAccount { .. }
        ) {
            if hold {
                return Err(Error::InvalidInput);
            }
            return self.resolve_deletion(mapped, details).await;
        }
        if hold {
            self.held = Some(Held {
                proof: mapped,
                evidence: details.clone(),
            });
            details["result"] = "held".into();
            return Ok(details);
        }
        self.resolve(mapped, details).await
    }
    pub(crate) async fn resolve_held(&mut self) -> Result<Value> {
        let Held {
            proof,
            mut evidence,
        } = self.held.take().ok_or(Error::InvalidInput)?;
        let live: bool = sqlx::query_scalar(
            "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint < $1",
        )
        .bind(proof.identity().expires_us())
        .fetch_one(&self.pool)
        .await
        .map_err(|_| Error::Unavailable)?;
        // An expired fixture cannot prove the intended disable/revision rejection.
        if !live {
            return Err(Error::Unavailable);
        }
        evidence["original_cap_live"] = true.into();
        self.resolve(proof, evidence).await
    }
    async fn resolve(&mut self, proof: OidcMappedIdentity, mut details: Value) -> Result<Value> {
        let authenticated_at = proof.identity().authenticated_at();
        match OidcSignIn::new(self.store.clone()).finish(proof).await {
            Ok((user, session)) => {
                let (source, time) = evidence::session(
                    &self.store,
                    &self.pool,
                    &self.policy,
                    &user,
                    &session,
                    authenticated_at,
                )
                .await?;
                details["result"] = "authenticated".into();
                details["source_provenance_valid"] = source.into();
                details["authentication_time_preserved"] = time.into();
                details["provider_required"] =
                    (user.authentication_policy == AuthenticationPolicy::ProviderRequired).into();
                details["local_contact_absent"] = user.email.is_none().into();
                details["different_mailbox_owner"] = self
                    .mailbox
                    .as_ref()
                    .is_some_and(|(mailbox, _)| mailbox.id != user.id)
                    .into();
                details["same_provider_owner"] = self
                    .provider
                    .as_ref()
                    .is_none_or(|(previous, _)| previous.id == user.id)
                    .into();
                details["stored_display_preserved"] = self
                    .provider
                    .as_ref()
                    .is_none_or(|(previous, _)| previous.display_name == user.display_name)
                    .into();
                self.provider = Some((user, session));
            }
            Err(error) => {
                details["result"] = crate::fixture::classified(Err(error))["result"].clone();
            }
        }
        details["mailbox_session_valid"] = self.mailbox_valid().await?.into();
        Ok(details)
    }
    pub(super) async fn mailbox_valid(&self) -> Result<bool> {
        match &self.mailbox {
            Some((user, session)) => match self
                .store
                .authenticate(self.policy.configuration().realm(), session.verifier())
                .await
            {
                Ok(actual) => Ok(actual == *user),
                Err(Error::Unauthorized) => Ok(false),
                Err(error) => Err(error),
            },
            None => Ok(false),
        }
    }
    pub(crate) async fn status(&self) -> Result<Value> {
        let rejected = match &self.provider {
            Some((_, session)) => {
                evidence::rejects(&self.store, self.policy.configuration(), session).await?
            }
            None => false,
        };
        Ok(
            json!({"result":"identity_status","mailbox_session_valid":self.mailbox_valid().await?,"provider_session_rejected":rejected}),
        )
    }
    pub(crate) async fn facts(&self) -> Result<Value> {
        evidence::facts(&self.pool).await
    }
}
