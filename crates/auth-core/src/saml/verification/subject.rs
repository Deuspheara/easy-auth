use crate::{Error, Result, SamlRegistration};
use saml_rs::{NameId, NameIdFormat};

const MAX_SUBJECT_BYTES: usize = 1024;
// SAML Core 8.3.7, Approved Errata05 E78: persistent identifiers have a
// 256-character limit. UTF-8 storage bytes alone do not enforce that contract.
const MAX_PERSISTENT_SUBJECT_CHARACTERS: usize = 256;

pub(super) fn persistent(reg: &SamlRegistration, id: &NameId) -> Result<String> {
    if id.format() != Some(&NameIdFormat::Persistent)
        || id.value().is_empty()
        || id.value().len() > MAX_SUBJECT_BYTES
        || id.value().chars().count() > MAX_PERSISTENT_SUBJECT_CHARACTERS
        || id.value().trim() != id.value()
        || id.value().chars().any(char::is_control)
        || id.sp_provided_id().is_some()
        || id.name_qualifier().is_some_and(|q| q != reg.idp_entity())
        || id.sp_name_qualifier().is_some_and(|q| q != reg.sp_entity())
    {
        return Err(Error::Unauthorized);
    }
    Ok(id.value().to_owned())
}
