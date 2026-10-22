use super::attributes::{Attribute, AttributeValue, Attributes};
use crate::{error::SamlError, util::Value};

pub(super) fn project(records: &Value) -> Result<Attributes, SamlError> {
    let Value::Array(records) = records else {
        return Err(invalid());
    };
    records
        .iter()
        .map(attribute)
        .collect::<Result<Vec<_>, _>>()
        .map(Attributes::new)
}

fn attribute(record: &Value) -> Result<Attribute, SamlError> {
    let name = record
        .get_str("Name")
        .filter(|name| !name.is_empty())
        .ok_or_else(invalid)?;
    let format = match record.get("NameFormat") {
        None => None,
        Some(Value::Str(value)) => Some(value.clone()),
        _ => return Err(invalid()),
    };
    let Some(Value::Array(values)) = record.get("values") else {
        return Err(invalid());
    };
    let values = values
        .iter()
        .map(|value| match value {
            Value::Str(value) => Ok(AttributeValue::new(value.clone())),
            _ => Err(invalid()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Attribute::new(name, format, values))
}

fn invalid() -> SamlError {
    SamlError::Invalid("typed attributes require named records with scalar non-nil values".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_records_are_a_complete_empty_projection() {
        assert!(project(&Value::Array(Vec::new()))
            .unwrap()
            .as_slice()
            .is_empty());
    }

    #[test]
    fn unavailable_values_never_become_partial_or_empty_string_records() {
        let record = |value| {
            Value::Object(vec![
                ("Name".into(), Value::Str("department".into())),
                ("values".into(), Value::Array(vec![value])),
            ])
        };
        assert!(project(&Value::Array(vec![
            record(Value::Str("Engineering".into())),
            record(Value::Null)
        ]))
        .is_err());
    }
}
