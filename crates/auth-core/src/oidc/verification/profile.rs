use serde::{Deserialize, Deserializer};

/// An unusable optional presentation attribute is absent, not identity authority.
/// Selecting it for required local mapping fails closed later. Parsing remains
/// under the existing signed ID-token byte bound; no raw JSON is retained.
pub(super) fn attribute<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::String(value)
            if super::super::identities::usable_display_name(&value) =>
        {
            Some(value)
        }
        _ => None,
    })
}
