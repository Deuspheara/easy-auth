use super::subject;
use crate::{Error, SamlRegistration};
use saml_rs::{NameId, NameIdFormat};
use uuid::Uuid;

fn registration() -> SamlRegistration {
    SamlRegistration::unsigned_redirect(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        "urn:example:sp",
        "urn:example:idp",
        "https://idp.example/sso",
        "https://sp.example/acs",
    )
    .unwrap()
}

#[test]
fn persistent_subject_policy_preserves_exact_values_and_trusted_qualifiers() {
    let reg = registration();
    for (idp, sp) in [
        (None, None),
        (
            Some(reg.idp_entity().to_owned()),
            Some(reg.sp_entity().to_owned()),
        ),
    ] {
        let name = NameId::with_qualifiers(
            "Opaque-Subject",
            Some(NameIdFormat::Persistent),
            idp,
            sp,
            None,
        );
        assert_eq!(subject::persistent(&reg, &name).unwrap(), "Opaque-Subject");
    }
    let exact_limit = NameId::new("é".repeat(512), Some(NameIdFormat::Persistent));
    assert_eq!(subject::persistent(&reg, &exact_limit).unwrap().len(), 1024);
}

#[test]
fn subject_policy_rejects_other_formats_namespaces_aliases_and_invalid_values() {
    let reg = registration();
    for format in [
        None,
        Some(NameIdFormat::EmailAddress),
        Some(NameIdFormat::Transient),
        Some(NameIdFormat::Unspecified),
    ] {
        assert!(matches!(
            subject::persistent(&reg, &NameId::new("normal", format)),
            Err(Error::Unauthorized)
        ));
    }
    for value in [
        String::new(),
        " padded ".into(),
        "line\nbreak".into(),
        "é".repeat(513),
    ] {
        assert!(matches!(
            subject::persistent(&reg, &NameId::new(value, Some(NameIdFormat::Persistent))),
            Err(Error::Unauthorized)
        ));
    }
    for (idp, sp, alias) in [
        (Some("urn:example:other-idp".into()), None, None),
        (None, Some("urn:example:other-sp".into()), None),
        (Some(String::new()), None, None),
        (None, Some(String::new()), None),
        (None, None, Some("alias".into())),
    ] {
        let name =
            NameId::with_qualifiers("normal", Some(NameIdFormat::Persistent), idp, sp, alias);
        assert!(matches!(
            subject::persistent(&reg, &name),
            Err(Error::Unauthorized)
        ));
    }
}
