mod claim;
mod completion;
mod port;
use auth_core::{AppleGrantRevocationJob, OAuthConnection};
fn matches(source: &OAuthConnection, job: &AppleGrantRevocationJob) -> bool {
    let b = job.envelope().binding();
    (b.realm(), b.connection(), b.client())
        == (source.realm(), source.connection(), source.client())
}
