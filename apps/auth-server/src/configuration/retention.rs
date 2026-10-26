use super::{StartupResult, required_setting};
use auth_core::{Error, RetentionHorizon, RetentionPolicy};
use std::time::Duration;
use uuid::Uuid;

pub(crate) fn read() -> StartupResult<(Uuid, RetentionPolicy)> {
    let realm: Uuid = required_setting("AUTH_REALM_ID")?
        .parse()
        .map_err(|_| "AUTH_REALM_ID must be a non-nil UUID")?;
    if realm.is_nil() {
        return Err("AUTH_REALM_ID must be a non-nil UUID".into());
    }
    let audit = selected("AUTH_RETENTION_AUDIT")?;
    let notices = selected("AUTH_RETENTION_NOTICES")?;
    Ok((realm, RetentionPolicy::new(audit, notices)))
}

fn selected(name: &'static str) -> StartupResult<RetentionHorizon> {
    horizon(&required_setting(name)?)
        .map_err(|_| format!("{name} must be keep or a supported positive whole-second age").into())
}

fn horizon(value: &str) -> auth_core::Result<RetentionHorizon> {
    if value == "keep" {
        return Ok(RetentionHorizon::keep());
    }
    if value.is_empty()
        || value.len() > 10
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::InvalidInput);
    }
    let seconds: u64 = value.parse().map_err(|_| Error::InvalidInput)?;
    RetentionHorizon::after(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_keep_or_bounded_canonical_seconds_only() {
        assert_eq!(horizon("keep").unwrap().seconds(), None);
        assert_eq!(horizon("86400").unwrap().seconds(), Some(86400));
        assert_eq!(
            horizon("3153600000").unwrap().seconds(),
            Some(3_153_600_000)
        );
        for value in [
            "",
            "0",
            "01",
            "-1",
            "+1",
            "1.5",
            " 1",
            "1 ",
            "KEEP",
            "１",
            "3153600001",
            "99999999999",
            "private-marker",
        ] {
            assert!(matches!(horizon(value), Err(Error::InvalidInput)));
        }
    }
}
