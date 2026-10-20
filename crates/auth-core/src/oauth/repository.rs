use super::OAuthConnection;
use crate::{Result, Secret, Verifier};
use async_trait::async_trait;
use uuid::Uuid;

/// A linking intent is not authority to attach an identity. The exact owned
/// session must be fresh at start/consume and rechecked at future identity commit.
#[derive(Clone, Eq, PartialEq)]
pub enum OAuthPurpose {
    SignIn,
    Link {
        user: Uuid,
        session: Verifier,
    },
    /// An active source-bound provider session may request reauthentication.
    /// This purpose never grants sign-in/linking or deletion by itself. Final
    /// deletion requires the exact existing subject and recent signed auth_time.
    DeleteProviderAccount {
        user: Uuid,
        session: Verifier,
    },
}

/// Request-local context selected by a trusted handler, never callback selectors.
pub struct OAuthIntent<'a> {
    pub browser: &'a Secret,
    pub source: &'a str,
    pub purpose: OAuthPurpose,
}

/// Selected by the trusted callback route; `issuer` is the decoded actual `iss`
/// parameter, never an assumed value copied from configuration.
pub struct OAuthCallback<'a> {
    pub redirect: &'a str,
    pub issuer: Option<&'a str>,
}

/// Repository-only verifiers. No raw state, nonce or PKCE verifier is persisted.
pub struct OAuthRequest {
    pub configuration: OAuthConnection,
    pub purpose: OAuthPurpose,
    pub browser: Verifier,
    pub source: Verifier,
    pub state: Verifier,
    pub nonce: Verifier,
    pub pkce: Verifier,
}

#[async_trait]
pub trait OAuthTransactionRepository: Send + Sync {
    /// Admit, validate configured revision and link owner/session, bound pending
    /// capacity and persist. Return the fixed original expiry in Unix microseconds.
    async fn save_oauth(&self, request: &OAuthRequest) -> Result<i64>;
    /// Atomically delete the exact live transaction once; check final expiry after
    /// all blocking writes. Return only its original deadline, never an identity.
    async fn consume_oauth(&self, request: &OAuthRequest) -> Result<i64>;
    /// Denial only. No provider exchange, identity, session or authentication audit.
    async fn cancel_oauth(&self, request: &OAuthRequest) -> Result<()>;
}
