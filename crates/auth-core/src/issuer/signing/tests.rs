use super::*;
use crate::Error;
use josekit::{jwk::KeyPair, jws::RS256};
use uuid::Uuid;

// Ordinary standard-library key output, as already used by the existing OIDC
// fixtures. No signature mutation, hostile material or custom crypto producer.
fn normal_key() -> (Uuid, String) {
    let key = RS256.generate_key_pair(2048).unwrap();
    (
        Uuid::new_v4(),
        String::from_utf8(key.to_pem_private_key()).unwrap(),
    )
}
#[test]
fn protected_key_has_only_a_deliberate_validated_public_projection() {
    let (id, pem) = normal_key();
    let key = IssuerSigningKey::from_pkcs8_pem(id, pem).unwrap();
    assert_eq!(key.id(), id);
    assert_eq!(format!("{key:?}"), "IssuerSigningKey([REDACTED])");
    let public = key.public_key().unwrap();
    assert_eq!(public.id(), id);
    let mut names = public
        .document()
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    names.sort_unstable();
    assert_eq!(names, ["alg", "e", "key_ops", "kid", "kty", "n", "use"]);
    assert_eq!(public.document()["alg"], "RS256");
    let encoded = serde_json::to_vec(public.document()).unwrap();
    assert_eq!(IssuerPublicKey::from_json(&encoded).unwrap(), public);
}
#[test]
fn key_input_is_explicit_private_pkcs8_with_no_implicit_identity_or_format_fallback() {
    let (id, pem) = normal_key();
    assert!(matches!(
        IssuerSigningKey::from_pkcs8_pem(Uuid::nil(), pem.clone()),
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        IssuerSigningKey::from_pkcs8_pem(id, format!("{pem}{pem}")),
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        IssuerSigningKey::from_pkcs8_pem(id, format!("{pem}unexpected")),
        Err(Error::InvalidInput)
    ));
    let pair = josekit::jwk::alg::rsa::RsaKeyPair::from_pem(pem).unwrap();
    let public = String::from_utf8(pair.to_pem_public_key()).unwrap();
    assert!(matches!(
        IssuerSigningKey::from_pkcs8_pem(id, public),
        Err(Error::InvalidInput)
    ));
}
#[test]
fn public_metadata_requires_exact_public_only_algorithm_and_identifier_profile() {
    let (id, pem) = normal_key();
    let key = IssuerSigningKey::from_pkcs8_pem(id, pem).unwrap();
    let public = key.public_key().unwrap();
    for (name, value) in [
        ("alg", serde_json::json!("HS256")),
        ("key_ops", serde_json::json!(["sign"])),
        ("use", serde_json::json!("enc")),
        ("kid", serde_json::json!(format!("urn:uuid:{id}"))),
        ("private", serde_json::json!(true)),
        ("jku", serde_json::json!("https://unselected.example/keys")),
    ] {
        let mut metadata = public.document().clone();
        metadata[name] = value;
        assert!(matches!(
            IssuerPublicKey::from_json(&serde_json::to_vec(&metadata).unwrap()),
            Err(Error::InvalidInput)
        ));
    }
    let serialized = serde_json::to_string(public.document()).unwrap();
    let duplicated = serialized.replacen('{', "{\"alg\":\"RS256\",", 1);
    assert!(matches!(
        IssuerPublicKey::from_json(duplicated.as_bytes()),
        Err(Error::InvalidInput)
    ));
}

#[test]
fn publication_retains_a_full_token_lifetime_and_never_creates_current_authority() {
    let (id, pem) = normal_key();
    let key = IssuerSigningKey::from_pkcs8_pem(id, pem)
        .unwrap()
        .public_key()
        .unwrap();
    let authority = crate::IssuerAuthority::new(Uuid::new_v4(), "https://issuer.example").unwrap();
    for (start, end, retained) in [
        (-1, 100, 300_000_100),
        (100, 100, 300_000_100),
        (0, 100, 300_000_099),
        (0, i64::MAX, i64::MAX),
    ] {
        assert!(matches!(
            IssuerKeyPublication::new(authority.clone(), key.clone(), start, end, retained),
            Err(Error::InvalidInput)
        ));
    }
    let publication =
        IssuerKeyPublication::new(authority.clone(), key, 0, 100, 300_000_100).unwrap();
    assert!(IssuerSigningSnapshot::from_persisted(Uuid::nil(), publication.clone()).is_err());
    let revision = Uuid::new_v4();
    let snapshot = IssuerSigningSnapshot::from_persisted(revision, publication).unwrap();
    assert_eq!(snapshot.authority(), &authority);
    assert_eq!(snapshot.revision(), revision);
    assert_eq!(snapshot.publication().key().id(), id);
}
