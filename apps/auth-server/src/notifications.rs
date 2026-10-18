use auth_core::Auth;
use std::time::Duration;

/// Start the bounded notification worker alongside either server composition.
/// Keep the handle; abort it at shutdown. Unacknowledged claims become retryable after the lease.
pub fn notification_worker(auth: Auth) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match auth.deliver_security_notice().await {
                Ok(true) => (),
                Ok(false) => tokio::time::sleep(Duration::from_secs(1)).await,
                Err(_) => {
                    tracing::warn!("security_notification_delivery_failed");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    })
}
