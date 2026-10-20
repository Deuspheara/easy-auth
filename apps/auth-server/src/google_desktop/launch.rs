use super::{
    GoogleDesktopError, GoogleDesktopLaunchError, GoogleDesktopSignInError, listener::remaining,
};
use auth_core::OidcAuthorizationUrl;
use std::{
    process::{Command as SystemCommand, Stdio},
    time::Duration,
};
use tokio::{
    process::{Child, Command},
    time::Instant,
};

const MAX_LAUNCH_WAIT: Duration = Duration::from_secs(5);
const MAX_REAP_WAIT: Duration = Duration::from_secs(1);

pub(super) fn command(
    url: &OidcAuthorizationUrl,
) -> Result<SystemCommand, GoogleDesktopSignInError> {
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        // Use only command construction. No dependency execution, output/error
        // aggregation, detached launch, browser selection or fallback iteration.
        open::commands(url.expose())
            .into_iter()
            .next()
            .ok_or_else(|| GoogleDesktopLaunchError::Unavailable.into())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = url;
        Err(GoogleDesktopLaunchError::Unavailable.into())
    }
}

pub(super) struct Process {
    child: Child,
    until: Instant,
    expires: bool,
}
impl Process {
    pub fn spawn(
        command: SystemCommand,
        expires_us: i64,
    ) -> Result<Self, GoogleDesktopSignInError> {
        let remaining = remaining(expires_us)?;
        let until = Instant::now() + remaining.min(MAX_LAUNCH_WAIT);
        let mut command = Command::from(command);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let child = command
            .spawn()
            .map_err(|_| GoogleDesktopLaunchError::Unavailable)?;
        Ok(Self {
            child,
            until,
            expires: remaining <= MAX_LAUNCH_WAIT,
        })
    }
    pub async fn wait(&mut self) -> Result<(), GoogleDesktopSignInError> {
        tokio::select! {biased;
            _=tokio::time::sleep_until(self.until)=>Err(if self.expires {
                GoogleDesktopError::Expired.into()
            }else{GoogleDesktopLaunchError::TimedOut.into()}),
            status=self.child.wait()=>match status {
                Ok(status) if status.success()=>Ok(()),
                _=>Err(GoogleDesktopLaunchError::Unavailable.into()),
            }
        }
    }
    pub async fn stop(&mut self) -> Result<(), GoogleDesktopLaunchError> {
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            return Ok(());
        }
        // Kill/reap only our opener child, never the OS browser or a process group.
        // A racing exit may make kill unnecessary; successful wait still proves cleanup.
        let _ = self.child.start_kill();
        if !matches!(
            tokio::time::timeout(MAX_REAP_WAIT, self.child.wait()).await,
            Ok(Ok(_))
        ) {
            return Err(GoogleDesktopLaunchError::CleanupUnavailable);
        }
        Ok(())
    }
}
