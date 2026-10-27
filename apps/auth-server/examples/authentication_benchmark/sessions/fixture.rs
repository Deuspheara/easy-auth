//! Synthetic identities use the actual public proof/commit repository boundary.
use super::{Error, Failure, OWNERS, Postgres, Repository, Secret, Uuid};
use std::sync::Arc;

pub(super) struct Fixture {
    repository: Arc<Postgres>,
    realm: Uuid,
    foreign_realm: Uuid,
    sessions: Vec<Secret>,
    owners: Vec<Uuid>,
    unknown: Secret,
}

impl Fixture {
    pub(super) async fn create(repository: Arc<Postgres>) -> Result<Self, Failure> {
        let realm = Uuid::new_v4();
        let foreign_realm = Uuid::new_v4();
        repository.ensure_realm(realm).await?;
        repository.ensure_realm(foreign_realm).await?;
        let mut fixture = Self {
            repository,
            realm,
            foreign_realm,
            sessions: Vec::new(),
            owners: Vec::new(),
            unknown: Secret::generate()?,
        };
        for _ in 0..OWNERS {
            fixture.add_owner().await?;
        }
        Ok(fixture)
    }

    async fn add_owner(&mut self) -> Result<(), Failure> {
        let token = Secret::generate()?;
        let browser = Secret::generate()?;
        let session = Secret::generate()?;
        let email = format!("{}@example.test", Uuid::new_v4());
        self.repository
            .begin_email(
                self.realm,
                &email,
                token.verifier(),
                browser.verifier(),
                Secret::generate()?.verifier(),
            )
            .await?;
        let user = self
            .repository
            .finish_email(
                self.realm,
                token.verifier(),
                browser.verifier(),
                session.verifier(),
            )
            .await?;
        self.owners.push(user.id);
        self.sessions.push(session);
        Ok(())
    }

    pub(super) async fn authenticate(&self, name: &str, worker: usize) -> auth_core::Result<()> {
        let index = if name == "independent_owners" {
            worker
        } else {
            0
        };
        let session = if name == "unknown_session" {
            &self.unknown
        } else {
            &self.sessions[index]
        };
        let realm = if name == "foreign_realm" {
            self.foreign_realm
        } else {
            self.realm
        };
        match self
            .repository
            .authenticate(realm, session.verifier())
            .await
        {
            Ok(user)
                if matches!(name, "shared_session" | "independent_owners")
                    && user.id == self.owners[index]
                    && user.realm_id == self.realm =>
            {
                Ok(())
            }
            Err(Error::Unauthorized) if matches!(name, "unknown_session" | "foreign_realm") => {
                Err(Error::Unauthorized)
            }
            _ => Err(Error::Unavailable),
        }
    }

    pub(super) async fn check_revocation(&self) -> Result<(), Failure> {
        self.repository
            .revoke(self.realm, self.sessions[0].verifier())
            .await?;
        if !matches!(
            self.repository
                .authenticate(self.realm, self.sessions[0].verifier())
                .await,
            Err(Error::Unauthorized)
        ) {
            return Err("revocation control failed".into());
        }
        self.repository
            .authenticate(self.realm, self.sessions[1].verifier())
            .await?;
        Ok(())
    }
}
