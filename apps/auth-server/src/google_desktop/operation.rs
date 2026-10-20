use super::{
    GoogleDesktopCallback, GoogleDesktopError, GoogleDesktopListener, GoogleDesktopSignInError,
    launch,
};
use auth_core::{
    GoogleAuthorization, GoogleAuthorizationCompletion, GoogleAuthorizationStart,
    OAuthBrowserProof, OAuthIntent, OAuthPurpose, Secret,
};
use std::{
    fmt,
    future::{Future, pending},
    pin::Pin,
    process::Command,
    sync::Arc,
};

/// One owned native sign-in attempt. Private proof remains in memory and is never
/// exported to the OS browser, logs or a public callback-upload API.
pub struct GoogleDesktopSignIn {
    listener: Option<GoogleDesktopListener>,
    service: Arc<GoogleAuthorization>,
    start: GoogleAuthorizationStart,
    browser: Secret,
    source: String,
}
impl GoogleDesktopSignIn {
    /// Bind/persist the listener's exact redirect first, then construct its matching
    /// core service. A different listener/service pair fails before admission.
    pub async fn begin(
        listener: GoogleDesktopListener,
        service: Arc<GoogleAuthorization>,
        source: &str,
    ) -> Result<Self, GoogleDesktopSignInError> {
        if listener.redirect().as_str() != service.configuration().redirect() {
            return Err(GoogleDesktopError::InvalidInput.into());
        }
        let browser = Secret::generate()?;
        let start = service
            .begin(&OAuthIntent {
                browser: &browser,
                source,
                purpose: OAuthPurpose::SignIn,
            })
            .await?;
        Ok(Self {
            listener: Some(listener),
            service,
            start,
            browser,
            source: source.to_owned(),
        })
    }

    /// Deliberate external-system-browser handoff and actual owned socket return.
    /// Launcher exit0 grants nothing; completion still needs mapped local commit.
    /// Every transport/launcher failure retains original proof for explicit cancel.
    pub async fn run(
        &mut self,
        cancel: impl Future<Output = ()>,
    ) -> Result<GoogleAuthorizationCompletion, GoogleDesktopSignInError> {
        let command = launch::command(&self.start.authorization_url)?;
        self.run_with(command, cancel).await
    }

    async fn run_with(
        &mut self,
        command: Command,
        cancel: impl Future<Output = ()>,
    ) -> Result<GoogleAuthorizationCompletion, GoogleDesktopSignInError> {
        let mut cancel = std::pin::pin!(cancel);
        let callback = self.capture(command, cancel.as_mut()).await?;
        self.verify(callback, cancel.as_mut()).await
    }

    async fn capture<F: Future<Output = ()>>(
        &mut self,
        command: Command,
        mut cancel: Pin<&mut F>,
    ) -> Result<GoogleDesktopCallback, GoogleDesktopSignInError> {
        let listener = self
            .listener
            .take()
            .ok_or(GoogleDesktopError::InvalidInput)?;
        // An already requested cancellation must never spawn the opener.
        tokio::select! {biased;
            _=cancel.as_mut()=>return Err(GoogleDesktopError::Cancelled.into()),
            _=std::future::ready(())=>{}
        }
        let mut process = launch::Process::spawn(command, self.start.transaction.expires_us)?;
        // Accept while the opener is still running: the external browser can
        // deliver before its launcher exits. Require both outcomes before verification.
        let result = tokio::select! {biased;
            _=cancel.as_mut()=>Err(GoogleDesktopError::Cancelled.into()),
            result=async {
                let (_,callback)=tokio::try_join!(process.wait(),async {
                    listener.receive(&self.start.transaction.state,self.start.transaction.expires_us,pending()).await
                        .map_err(GoogleDesktopSignInError::from)
                })?;
                Ok(callback)
            }=>result,
        };
        if result.is_err() {
            process.stop().await?;
        }
        result
    }

    async fn verify<F: Future<Output = ()>>(
        &self,
        callback: GoogleDesktopCallback,
        mut cancel: Pin<&mut F>,
    ) -> Result<GoogleAuthorizationCompletion, GoogleDesktopSignInError> {
        // Retain the original protected proof for cancellation if consumption was
        // rejected before commit (e.g. admission/storage failure). PG owns one-use.
        let proof = OAuthBrowserProof::parse(
            self.start.transaction.proof.nonce().expose().to_owned(),
            self.start
                .transaction
                .proof
                .pkce_verifier()
                .expose()
                .to_owned(),
        )?;
        let intent = self.intent();
        tokio::select! {biased;
            _=cancel.as_mut()=>Err(GoogleDesktopError::Cancelled.into()),
            result=callback.finish(&self.service,&intent,&self.start.transaction.state,proof)=>Ok(result?),
        }
    }

    /// Close transport and cancel only this original pending operation. Drop alone
    /// cannot perform asynchronous DB cleanup; remaining rows keep original expiry.
    pub async fn cancel(mut self) -> auth_core::Result<()> {
        drop(self.listener.take());
        self.service
            .cancel(
                &self.intent(),
                &self.start.transaction.state,
                &self.start.transaction.proof,
            )
            .await
    }
    fn intent(&self) -> OAuthIntent<'_> {
        OAuthIntent {
            browser: &self.browser,
            source: &self.source,
            purpose: OAuthPurpose::SignIn,
        }
    }
}
impl fmt::Debug for GoogleDesktopSignIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GoogleDesktopSignIn([REDACTED])")
    }
}

#[cfg(all(test, feature = "oidc-identities", unix))]
#[path = "tests/operation/mod.rs"]
mod tests;
