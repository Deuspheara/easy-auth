use crate::{Error, Result};
use serde::{Deserialize, Deserializer};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientContext {
    #[serde(default)]
    cross_origin: bool,
    #[serde(rename = "topOrigin", default, deserialize_with = "reject_top_origin")]
    _top_origin: (),
}

fn reject_top_origin<'de, D: Deserializer<'de>>(_: D) -> std::result::Result<(), D::Error> {
    Err(serde::de::Error::custom("unapproved top-level context"))
}

/// Application context policy in addition to the high-level verifier. The pinned
/// assertion path does not check crossOrigin/topOrigin. Signature verification still
/// covers the exact complete clientDataJSON; this does not implement cryptography.
pub(super) fn require_same_origin(encoded: &[u8]) -> Result<()> {
    if encoded
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        != Some(b'{')
    {
        return Err(Error::Unauthorized);
    }
    let context: ClientContext =
        serde_json::from_slice(encoded).map_err(|_| Error::Unauthorized)?;
    if context.cross_origin {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_unambiguous_same_origin_context() {
        for value in [r#"{}"#, r#"{"crossOrigin":false}"#] {
            assert!(require_same_origin(value.as_bytes()).is_ok());
        }
        for value in [
            r#"{"crossOrigin":true}"#,
            r#"{"crossOrigin":null}"#,
            r#"{"crossOrigin":false,"crossOrigin":true}"#,
            r#"{"crossOrigin":true,"crossOrigin":false}"#,
            r#"{"topOrigin":null}"#,
            r#"{"topOrigin":"https://parent.example.com"}"#,
            r#"[]"#,
        ] {
            assert!(matches!(
                require_same_origin(value.as_bytes()),
                Err(Error::Unauthorized)
            ));
        }
    }
}
