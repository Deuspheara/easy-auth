use super::StartupResult;

pub(super) fn optional_setting(name: &'static str) -> StartupResult<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{name} must be valid Unicode").into())
        }
    }
}

pub(super) fn setting(name: &'static str, default: &str) -> StartupResult<String> {
    Ok(optional_setting(name)?.unwrap_or_else(|| default.to_owned()))
}

pub(crate) fn required_setting(name: &'static str) -> StartupResult<String> {
    optional_setting(name)?.ok_or_else(|| format!("{name} is required").into())
}
