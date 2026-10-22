//! Ordered attribute records from the same verified Assertion shortcut as the
//! other assertion fields. The legacy name-keyed raw extraction stays intact.
use super::dom::{self, Node, XmlLimits};
use crate::{error::SamlError, util::Value};

pub(crate) fn append(
    extracted: &mut Value,
    assertion: Option<&str>,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    let Some(assertion) = assertion else {
        return Ok(());
    };
    let document = dom::parse_with_limits(assertion, limits)?;
    if document.root.local_name != "Assertion" {
        return Err(SamlError::Invalid(
            "attribute projection requires an Assertion".into(),
        ));
    }
    let rows = document
        .root
        .children
        .iter()
        .filter(|node| node.local_name == "AttributeStatement")
        .flat_map(|node| &node.children)
        .filter(|node| node.local_name == "Attribute")
        .map(record)
        .collect();
    let Value::Object(fields) = extracted else {
        return Err(SamlError::Invalid("expected extracted field object".into()));
    };
    fields.push(("attributeRecords".into(), Value::Array(rows)));
    Ok(())
}

fn record(node: &Node) -> Value {
    let mut fields: Vec<_> = ["Name", "NameFormat"]
        .into_iter()
        .filter_map(|name| {
            node.attr(name)
                .map(|value| (name.into(), Value::Str(value.into())))
        })
        .collect();
    let values = node
        .children
        .iter()
        .filter(|node| node.local_name == "AttributeValue")
        .map(|value| {
            // The typed scalar contract cannot silently flatten XML-valued or nil
            // data into an ordinary string. Preserve its unsupported shape.
            if !value.children.is_empty() || value.attr("nil").is_some() {
                Value::Null
            } else {
                Value::Str(value.text.clone())
            }
        })
        .collect();
    fields.push(("values".into(), Value::Array(values)));
    Value::Object(fields)
}
