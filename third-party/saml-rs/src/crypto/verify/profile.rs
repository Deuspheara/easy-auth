//! Algorithm and reference-shape policy on verifier-authenticated signature nodes.
use super::{reference_resolution, verified_target_from_uri};
use crate::config::XmlSignatureProfile;
use crate::constants::{digest_algorithm, signature_algorithm, transform_algorithm};
use crate::error::{ReferenceResolutionReason, SamlError};
use bergshamra::core::ns as bergshamra_ns;
use bergshamra::xml::{Document as BergshamraDocument, NodeId as BergshamraNodeId};

pub(super) fn dsig_children(
    document: &BergshamraDocument<'_>,
    parent: BergshamraNodeId,
    local_name: &str,
) -> Vec<BergshamraNodeId> {
    document
        .children_iter(parent)
        .filter(|child| {
            document
                .element(*child)
                .is_some_and(|element| element.matches_name_ns(bergshamra_ns::DSIG, local_name))
        })
        .collect()
}

fn exactly_one_dsig_child(
    document: &BergshamraDocument<'_>,
    parent: BergshamraNodeId,
    local_name: &str,
) -> Option<BergshamraNodeId> {
    let mut children = dsig_children(document, parent, local_name).into_iter();
    let only = children.next()?;
    children.next().is_none().then_some(only)
}

fn dsig_algorithm<'a>(
    document: &'a BergshamraDocument<'_>,
    node: BergshamraNodeId,
) -> Option<&'a str> {
    document
        .element(node)
        .and_then(|element| element.get_attribute(bergshamra_ns::attr::ALGORITHM))
}

/// Check one verifier-accepted signature against the strict RSA-SHA2 profile.
///
/// Callers apply this only to a signature that authenticated the message being
/// accepted. An invalid, untrusted, or unrelated signature therefore cannot
/// reject the message.
pub(super) fn enforce_strict_profile_on_verified_signature(
    document: &BergshamraDocument<'_>,
    signature_node: BergshamraNodeId,
    profile: XmlSignatureProfile,
) -> Result<(), SamlError> {
    let signed_info =
        exactly_one_dsig_child(document, signature_node, bergshamra_ns::node::SIGNED_INFO)
            .ok_or(SamlError::SignedReferenceMismatch)?;
    let canonicalization = exactly_one_dsig_child(
        document,
        signed_info,
        bergshamra_ns::node::CANONICALIZATION_METHOD,
    )
    .ok_or(SamlError::AlgorithmUnsupported)?;
    if dsig_algorithm(document, canonicalization) != Some(transform_algorithm::EXC_C14N) {
        return Err(SamlError::AlgorithmUnsupported);
    }
    let signature_method =
        exactly_one_dsig_child(document, signed_info, bergshamra_ns::node::SIGNATURE_METHOD)
            .ok_or(SamlError::AlgorithmUnsupported)?;
    if !matches!(
        dsig_algorithm(document, signature_method),
        Some(
            crate::constants::signature_algorithm::RSA_SHA256
                | crate::constants::signature_algorithm::RSA_SHA384
                | crate::constants::signature_algorithm::RSA_SHA512
        )
    ) {
        return Err(SamlError::AlgorithmUnsupported);
    }
    let reference = exactly_one_dsig_child(document, signed_info, bergshamra_ns::node::REFERENCE)
        .ok_or(SamlError::SignedReferenceMismatch)?;
    let Some(uri) = document
        .element(reference)
        .and_then(|element| element.get_attribute(bergshamra_ns::attr::URI))
    else {
        return Err(reference_resolution(
            ReferenceResolutionReason::UnsupportedReferenceUri,
        ));
    };
    if !uri.starts_with('#') || uri.len() == 1 || uri.starts_with("#xpointer(") {
        return Err(reference_resolution(
            ReferenceResolutionReason::UnsupportedReferenceUri,
        ));
    }
    verified_target_from_uri(uri)?;

    let digest_method =
        exactly_one_dsig_child(document, reference, bergshamra_ns::node::DIGEST_METHOD)
            .ok_or(SamlError::AlgorithmUnsupported)?;
    if !matches!(
        dsig_algorithm(document, digest_method),
        Some(
            crate::constants::digest_algorithm::SHA256
                | crate::constants::digest_algorithm::SHA384
                | crate::constants::digest_algorithm::SHA512
        )
    ) {
        return Err(SamlError::AlgorithmUnsupported);
    }
    // Evaluate the exact verified Signature/SignedInfo in the verifier DOM.
    // No unsigned-node scan or parse/serialize bridge supplies policy evidence.
    if profile == XmlSignatureProfile::StrictRsaSha256
        && (dsig_algorithm(document, signature_method) != Some(signature_algorithm::RSA_SHA256)
            || dsig_algorithm(document, digest_method) != Some(digest_algorithm::SHA256))
    {
        return Err(SamlError::AlgorithmUnsupported);
    }
    enforce_reference_transforms(document, reference)
}

/// Restrict execution before digest processing as well as authenticated policy.
pub(super) fn enforce_reference_transforms(
    document: &BergshamraDocument<'_>,
    reference: BergshamraNodeId,
) -> Result<(), SamlError> {
    for transforms in dsig_children(document, reference, bergshamra_ns::node::TRANSFORMS) {
        // Bergshamra executes every direct child whose local name is
        // `Transform`, including elements outside the XML-DSig namespace.
        // Reject any element it would execute, and any other element child,
        // unless it is an allowed XML-DSig transform.
        for child in document.children_iter(transforms) {
            let Some(element) = document.element(child) else {
                continue;
            };
            if !element.matches_name_ns(bergshamra_ns::DSIG, bergshamra_ns::node::TRANSFORM)
                || !matches!(
                    element.get_attribute(bergshamra_ns::attr::ALGORITHM),
                    Some(transform_algorithm::ENVELOPED_SIGNATURE | transform_algorithm::EXC_C14N)
                )
            {
                return Err(SamlError::AlgorithmUnsupported);
            }
        }
    }
    Ok(())
}
