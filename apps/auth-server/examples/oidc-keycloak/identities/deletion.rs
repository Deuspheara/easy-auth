use super::{evidence, state::Identities};
use auth_core::*;
use serde_json::{Value, json};

impl Identities {
    pub(crate) fn deletion_purpose(&self) -> Result<OAuthPurpose> {
        let (user, session) = self.provider.as_ref().ok_or(Error::InvalidInput)?;
        Ok(OAuthPurpose::DeleteProviderAccount {
            user: user.id,
            session: session.verifier(),
        })
    }
    async fn provider_valid(&self) -> Result<bool> {
        let (user, session) = self.provider.as_ref().ok_or(Error::InvalidInput)?;
        match self
            .store
            .authenticate(self.policy.configuration().realm(), session.verifier())
            .await
        {
            Ok(actual) => Ok(actual == *user),
            Err(Error::Unauthorized) => Ok(false),
            Err(error) => Err(error),
        }
    }
    pub(super) async fn resolve_deletion(
        &mut self,
        mapped: OidcMappedIdentity,
        mut details: Value,
    ) -> Result<Value> {
        let (user, session) = self.provider.as_ref().ok_or(Error::InvalidInput)?;
        let purpose_bound = matches!(mapped.identity().purpose(), OAuthPurpose::DeleteProviderAccount {user: owner,session: current} if *owner==user.id && *current==session.verifier());
        let authenticated = mapped
            .identity()
            .authenticated_at()
            .map(i64::try_from)
            .transpose()
            .map_err(|_| Error::Unavailable)?;
        let (cap_live,recent): (bool,bool) = sqlx::query_as(r#"
            WITH now AS MATERIALIZED (SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint AS us)
            SELECT us<$1,coalesce(us>=$2::bigint*1000000 AND us<($2::bigint+$3)*1000000,false) FROM now
        "#).bind(mapped.identity().expires_us()).bind(authenticated).bind(i64::try_from(MAX_OIDC_DELETION_AUTH_AGE_SECONDS).map_err(|_|Error::Unavailable)?)
            .fetch_one(&self.pool).await.map_err(|_|Error::Unavailable)?;
        details["original_cap_live"] = cap_live.into();
        details["signed_authentication_time_present"] = authenticated.is_some().into();
        details["signed_authentication_recent"] = recent.into();
        details["deletion_purpose_bound"] = purpose_bound.into();
        details["initiating_session_valid"] = self.provider_valid().await?.into();
        let result = OidcAccountDeletion::new(self.store.clone())
            .finish(mapped)
            .await;
        details["result"] = match result {
            Ok(()) => "deleted".into(),
            Err(error) => crate::fixture::classified(Err(error))["result"].clone(),
        };
        details["mailbox_session_valid"] = self.mailbox_valid().await?.into();
        details["provider_session_rejected"] = (!self.provider_valid().await?).into();
        Ok(details)
    }
    pub(crate) async fn deletion_facts(&self) -> Result<Value> {
        let (deleted,cooldown,erased,mailbox): (i64,i64,i64,i64) = sqlx::query_as(r#"
            SELECT (SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='account_deleted'),
              (SELECT count(*) FROM auth_oidc_deleted_subjects WHERE realm_id=$1 AND blocked_until>clock_timestamp()),
              (SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='oidc_authenticated' AND subject_erased AND user_id IS NULL AND actor_session_id IS NULL AND session_id IS NULL),
              (SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='email_authenticated' AND NOT subject_erased AND user_id IS NOT NULL)
        "#).bind(self.policy.configuration().realm()).fetch_one(&self.pool).await.map_err(|_|Error::Unavailable)?;
        Ok(
            json!({"deleted":deleted,"live_cooldown":cooldown,"erased_provider_audits":erased,"live_mailbox_audits":mailbox}),
        )
    }
    pub(crate) async fn deletion_status(&self) -> Result<Value> {
        let rejected = match &self.provider {
            Some((_, session)) => {
                evidence::rejects(&self.store, self.policy.configuration(), session).await?
            }
            None => false,
        };
        let c = self.policy.configuration();
        let configured = match self.store.check_oidc_connection(c).await {
            Ok(()) => true,
            Err(Error::Unauthorized) => false,
            Err(error) => return Err(error),
        };
        let allow: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth_oidc_identity_policies WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3 AND revision=$4 AND jit='allow')")
            .bind(c.realm()).bind(c.connection()).bind(c.client()).bind(c.revision()).fetch_one(&self.pool).await.map_err(|_|Error::Unavailable)?;
        Ok(
            json!({"result":"deletion_status","facts":self.deletion_facts().await?,"provider_session_rejected":rejected,"mailbox_session_valid":self.mailbox_valid().await?,"configured_source_current":configured,"persisted_jit_allow":allow}),
        )
    }
}
