use crate::{Error, Result};

/// Conservative ASCII mailbox policy, consistently case-insensitive. No plus/dot rewriting.
pub fn normalize_email(value: &str) -> Result<String> {
    if value.len() > 254 || !value.is_ascii() {
        return Err(Error::InvalidInput);
    }
    let (local, domain) = value.split_once('@').ok_or(Error::InvalidInput)?;
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        || !domain.contains('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(Error::InvalidInput);
    }
    Ok(value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mailbox_policy_is_explicit() {
        assert_eq!(
            normalize_email("Alice+tag@EXAMPLE.com").unwrap(),
            "alice+tag@example.com"
        );
        for invalid in [
            "x",
            " x@example.com",
            "a..b@example.com",
            "a@-bad.com",
            "a@b..com",
            "a@b@c.com",
            "a\r\n@b.com",
            "a@b",
            "é@b.com",
        ] {
            assert!(normalize_email(invalid).is_err(), "{invalid:?}");
        }
    }
}
