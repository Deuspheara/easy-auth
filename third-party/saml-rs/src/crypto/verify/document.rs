//! Bind extraction to the verifier's parsed source without serializing XML.
use super::selected_assertion;
use crate::{
    config::XmlSignatureProfile,
    error::SamlError,
    xml::dom::{Node, XmlLimits},
};
use bergshamra::xml::{uppsala, Document, NodeId};
use quick_xml::{
    events::{attributes::Attribute, BytesStart, Event},
    name::{QName, ResolveResult},
    NsReader, XmlVersion,
};
use std::borrow::Cow;

pub(super) fn parse(xml: &str, limits: XmlLimits) -> Result<Document<'_>, SamlError> {
    // Enforce the existing no-DTD policy independently in the backend parser.
    // Never raise its established depth ceiling when local limits are larger.
    let depth = limits
        .max_depth
        .min(uppsala::parser::DEFAULT_MAX_DEPTH as usize) as u32;
    uppsala::Parser::new()
        .with_forbid_dtd(true)
        .with_forbid_entities(true)
        .with_max_depth(depth)
        .parse(xml)
        .map_err(|_| mismatch())
}

fn mismatch() -> SamlError {
    SamlError::SignedReferenceMismatch
}

fn same_namespace(resolved: ResolveResult<'_>, expected: Option<&str>) -> bool {
    match resolved {
        ResolveResult::Unbound => expected.unwrap_or_default().is_empty(),
        ResolveResult::Bound(namespace) => {
            // NsReader exposes the raw namespace-binding value. Normalize it
            // as an XML attribute before comparing the backend's resolved URI.
            let binding = Attribute {
                key: QName("xmlns"),
                value: Cow::Borrowed(namespace.as_ref()),
            };
            binding
                .normalized_value(XmlVersion::Implicit1_0)
                .is_ok_and(|value| value.as_ref() == expected.unwrap_or_default())
        }
        ResolveResult::Unknown(_) => false,
    }
}

fn attributes_agree(
    reader: &NsReader<&[u8]>,
    start: &BytesStart<'_>,
    element: &uppsala::Element<'_>,
) -> Result<(), SamlError> {
    let mut expected = element.attributes.iter();
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|_| mismatch())?;
        if attribute.key.as_namespace_binding().is_some() {
            continue;
        }
        let expected = expected.next().ok_or_else(mismatch)?;
        let (namespace, local) = reader.resolver().resolve_attribute(attribute.key);
        if local.into_inner() != expected.name.local_name.as_ref()
            || !same_namespace(namespace, expected.name.namespace_uri.as_deref())
        {
            return Err(mismatch());
        }
    }
    if expected.next().is_some() {
        return Err(mismatch());
    }
    Ok(())
}

fn namespaces_agree(
    xml: &str,
    document: &Document<'_>,
    profile: XmlSignatureProfile,
) -> Result<(), SamlError> {
    let mut reader = NsReader::from_str(xml);
    let mut elements = document
        .descendants(document.root())
        .into_iter()
        .filter_map(|id| document.element(id));
    loop {
        let (namespace, event) = reader.read_resolved_event().map_err(|_| mismatch())?;
        match event {
            Event::Start(start) | Event::Empty(start) => {
                let expected = elements.next().ok_or_else(mismatch)?;
                if start.local_name().into_inner() != expected.name.local_name.as_ref()
                    || !same_namespace(namespace, expected.name.namespace_uri.as_deref())
                {
                    return Err(mismatch());
                }
                attributes_agree(&reader, &start, expected)?;
            }
            Event::Decl(declaration)
                if profile != XmlSignatureProfile::AllowProviderSupportedForCompatibility =>
            {
                if declaration.version().map_err(|_| mismatch())?.as_ref() != "1.0" {
                    return Err(mismatch());
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if elements.next().is_some() {
        return Err(mismatch());
    }
    Ok(())
}

fn direct_text_agrees(local: &Node, document: &Document<'_>, id: NodeId) -> bool {
    let mut remaining = local.text.as_str();
    for child in document.children_iter(id) {
        if let Some(uppsala::NodeKind::Text(text) | uppsala::NodeKind::CData(text)) =
            document.node_kind(child)
        {
            let Some(rest) = remaining.strip_prefix(text.as_ref()) else {
                return false;
            };
            remaining = rest;
        }
    }
    remaining.is_empty()
}

fn check_node(
    local: &Node,
    document: &Document<'_>,
    id: NodeId,
) -> Result<std::ops::Range<usize>, SamlError> {
    let element = document.element(id).ok_or_else(mismatch)?;
    let range = document.node_range(id).ok_or_else(mismatch)?;
    let attributes = element
        .attributes
        .iter()
        .map(|a| (a.name.local_name.as_ref(), a.value.as_ref()));
    if range != (local.start..local.end)
        || element.name.local_name.as_ref() != local.local_name
        || !local
            .attrs
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .eq(attributes)
        || !direct_text_agrees(local, document, id)
    {
        return Err(mismatch());
    }
    Ok(range)
}

/// Every local extraction value and element boundary must agree with the exact
/// backend DOM. Expanded names are independently compared using NsReader.
/// Returned identity names the actually selected source Assertion, not the first
/// Assertion or a string-ID approximation. This is not canonicalization evidence.
pub(super) fn bind_extraction(
    xml: &str,
    local: &Node,
    document: &Document<'_>,
    profile: XmlSignatureProfile,
) -> Result<Option<NodeId>, SamlError> {
    namespaces_agree(xml, document, profile)?;
    let selected = selected_assertion(local).map(|node| node.start..node.end);
    let root = document.document_element().ok_or_else(mismatch)?;
    let mut pending = vec![(local, root)];
    let mut selected_id = None;
    while let Some((local, id)) = pending.pop() {
        let range = check_node(local, document, id)?;
        if selected.as_ref() == Some(&range) {
            selected_id = Some(id);
        }
        let children: Vec<_> = document
            .children_iter(id)
            .filter(|child| document.element(*child).is_some())
            .collect();
        if local.children.len() != children.len() {
            return Err(mismatch());
        }
        pending.extend(local.children.iter().zip(children));
    }
    if selected.is_some() && selected_id.is_none() {
        return Err(mismatch());
    }
    Ok(selected_id)
}
