//! Pre-execution constraints for every signature the backend can visit.
//!
//! This is an execution boundary, not evidence that a signature authenticated
//! SAML content. Acceptance still checks the exact verified signature separately.
use super::{
    profile::{dsig_children, enforce_reference_transforms},
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
        // Check all direct SignedInfo/Transforms containers, a superset of the
        // backend's first-container selection. Missing structure still fails in
        // the backend; duplicate structure cannot hide an executable reference.
        for signed_info in dsig_children(document, signature, ns::node::SIGNED_INFO) {
            for reference in dsig_children(document, signed_info, ns::node::REFERENCE) {
                let uri = document
                    .element(reference)
                    .and_then(|element| element.get_attribute(ns::attr::URI))
                    .unwrap_or_default();
                // In particular, reject relative paths before the backend's
                // resolver can fall back to reading from its working directory.
                verified_target_from_uri(uri)?;
                // The explicitly selected compatibility API retains its
                // provider-supported transforms. Production uses the exact
                // strict profile and never selects that compatibility mode.
                if profile != XmlSignatureProfile::AllowProviderSupportedForCompatibility {
                    enforce_reference_transforms(document, reference)?;
                }
            }
        }
    }
    Ok(())
}
