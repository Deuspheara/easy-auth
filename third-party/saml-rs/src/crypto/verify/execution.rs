//! Pre-execution constraints for every signature the backend can visit.
//!
//! This is an execution boundary, not evidence that a signature authenticated
//! SAML content. Acceptance still checks the exact verified signature separately.
use super::{
    profile::{
        dsig_children, enforce_reference_transforms, inclusive_namespace_parameters,
        unqualified_attribute,
    },
    verified_target_from_uri,
};
use crate::{config::XmlSignatureProfile, error::SamlError};
use bergshamra::core::ns;
use bergshamra::xml::Document;

/// Use the same DOM, namespace and descendant traversal as Bergshamra's
/// `verify_all_document_with_source`, before any certificate attempt. Checking
/// only Response/Assertion candidates misses other signatures processed there.
/// No parse/serialize bridge or unsigned-node scan supplies acceptance evidence.
pub(super) fn preflight_backend_references(
    document: &Document<'_>,
    profile: XmlSignatureProfile,
) -> Result<(), SamlError> {
    for signature in document.descendants(document.root()) {
        if !document
            .element(signature)
            .is_some_and(|element| element.matches_name_ns(ns::DSIG, ns::node::SIGNATURE))
        {
            continue;
        }
        for signed_info in dsig_children(document, signature, ns::node::SIGNED_INFO) {
            preflight_signed_info(document, signed_info, profile)?;
        }
    }
    Ok(())
}

fn preflight_signed_info(
    document: &Document<'_>,
    signed_info: bergshamra::xml::NodeId,
    profile: XmlSignatureProfile,
) -> Result<(), SamlError> {
    let strict = profile != XmlSignatureProfile::AllowProviderSupportedForCompatibility;
    // Scan all direct containers, a superset of the backend's first selection.
    if strict {
        for kind in [
            ns::node::CANONICALIZATION_METHOD,
            ns::node::SIGNATURE_METHOD,
        ] {
            for method in dsig_children(document, signed_info, kind) {
                unqualified_attribute(document, method, ns::attr::ALGORITHM)?;
                if kind == ns::node::CANONICALIZATION_METHOD {
                    inclusive_namespace_parameters(document, method)?;
                }
            }
        }
    }
    for reference in dsig_children(document, signed_info, ns::node::REFERENCE) {
        let uri = if strict {
            unqualified_attribute(document, reference, ns::attr::URI)?
        } else {
            document
                .element(reference)
                .and_then(|element| element.get_attribute(ns::attr::URI))
        }
        .unwrap_or_default();
        // Reject paths before the resolver can use its working-directory fallback.
        verified_target_from_uri(uri)?;
        if strict {
            for digest in dsig_children(document, reference, ns::node::DIGEST_METHOD) {
                unqualified_attribute(document, digest, ns::attr::ALGORITHM)?;
            }
            enforce_reference_transforms(document, reference)?;
        }
    }
    Ok(())
}
