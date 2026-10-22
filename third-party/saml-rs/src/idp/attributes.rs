use crate::{error::SamlError, model::Attributes, xml::write::XmlWriter};

pub(super) fn write(
    writer: &mut XmlWriter,
    prefix: &str,
    attributes: &Attributes,
) -> Result<(), SamlError> {
    if attributes.as_slice().is_empty() {
        return Ok(());
    }
    let statement = format!("{prefix}:AttributeStatement");
    let attribute_name = format!("{prefix}:Attribute");
    let value_name = format!("{prefix}:AttributeValue");
    writer.start(&statement, &[]);
    for attribute in attributes.as_slice() {
        if attribute.name().is_empty() {
            return Err(SamlError::Invalid(
                "attribute Name must not be empty".into(),
            ));
        }
        let mut fields = vec![("Name", attribute.name())];
        if let Some(format) = attribute.name_format() {
            fields.push(("NameFormat", format));
        }
        writer.start(&attribute_name, &fields);
        for value in attribute.values() {
            writer.text_element(&value_name, &[], value.as_str());
        }
        writer.end(&attribute_name);
    }
    writer.end(&statement);
    Ok(())
}
