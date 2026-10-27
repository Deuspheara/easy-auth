use super::{binding, payload, vault};
use crate::Error;
use crate::oidc::apple::grants::{AppleGrantBinding, AppleGrantEnvelope, protection};
use josekit::{
    Value,
    jwe::{self, Dir},
};
use uuid::Uuid;

#[tokio::test]
async fn real_envelope_roundtrip_and_fresh_nonce_do_not_expose_plaintext() {
    let vault = vault();
    let binding = binding();
    let first = protection::seal(&vault.keys, binding, payload()).unwrap();
    let second = protection::seal(&vault.keys, binding, payload()).unwrap();
    assert!(first.ciphertext() != second.ciphertext());
    assert!(!first.ciphertext().contains("owned-refresh-material"));
    let opened = protection::open(&vault.keys, &first).unwrap();
    assert!(opened.token == "owned-refresh-material");
    assert_eq!(format!("{first:?}"), "AppleGrantEnvelope([REDACTED])");
    assert!(vault.rewrap(&first).await.is_ok());
}

#[tokio::test]
async fn every_realm_source_identity_and_grant_context_is_authenticated() {
    let vault = vault();
    let original = binding();
    let sealed = protection::seal(&vault.keys, original, payload()).unwrap();
    for part in 0..5 {
        let mut values = [
            original.realm(),
            original.connection(),
            original.client(),
            original.identity(),
            original.grant(),
        ];
        values[part] = Uuid::new_v4();
        let b =
            AppleGrantBinding::new(values[0], values[1], values[2], values[3], values[4]).unwrap();
        let swapped =
            AppleGrantEnvelope::restore(b, sealed.key_id(), sealed.ciphertext().to_owned())
                .unwrap();
        assert!(matches!(
            vault.rewrap(&swapped).await,
            Err(Error::Unauthorized)
        ));
    }
    let mut parts: Vec<_> = sealed.ciphertext().split('.').map(str::to_owned).collect();
    let replacement = if parts[3].starts_with('A') { "B" } else { "A" };
    parts[3].replace_range(..1, replacement);
    let tampered = AppleGrantEnvelope::restore(original, sealed.key_id(), parts.join(".")).unwrap();
    assert!(matches!(
        vault.rewrap(&tampered).await,
        Err(Error::Unauthorized)
    ));
}

#[tokio::test]
async fn even_validly_encrypted_compression_extra_headers_and_other_profiles_are_rejected() {
    let vault = vault();
    let sealed = protection::seal(&vault.keys, binding(), payload()).unwrap();
    let key = vault.keys.key(sealed.key_id()).unwrap();
    let decrypter = Dir.decrypter_from_bytes(key.bytes.as_slice()).unwrap();
    let encrypter = Dir.encrypter_from_bytes(key.bytes.as_slice()).unwrap();
    let (bytes, original) = jwe::deserialize_compact(sealed.ciphertext(), &decrypter).unwrap();
    for (name, value) in [
        ("typ", Value::String("JWT".into())),
        ("zip", Value::String("DEF".into())),
        ("extra", Value::Bool(true)),
        ("enc", Value::String("A128CBC-HS256".into())),
        ("kid", Value::String(Uuid::new_v4().to_string())),
    ] {
        let mut header = original.clone();
        header.set_claim(name, Some(value)).unwrap();
        let ciphertext = jwe::serialize_compact(&bytes, &header, &encrypter).unwrap();
        let foreign =
            AppleGrantEnvelope::restore(sealed.binding(), sealed.key_id(), ciphertext).unwrap();
        assert!(matches!(
            vault.rewrap(&foreign).await,
            Err(Error::Unauthorized)
        ));
    }
    let mut invalid: Value = serde_json::from_slice(&bytes).unwrap();
    invalid["version"] = Value::from(2);
    let ciphertext = jwe::serialize_compact(
        &serde_json::to_vec(&invalid).unwrap(),
        &original,
        &encrypter,
    )
    .unwrap();
    let foreign =
        AppleGrantEnvelope::restore(sealed.binding(), sealed.key_id(), ciphertext).unwrap();
    assert!(matches!(
        vault.rewrap(&foreign).await,
        Err(Error::Unauthorized)
    ));
}

#[test]
fn untrusted_storage_shapes_and_payload_lifetimes_have_explicit_bounds() {
    let b = binding();
    for value in [
        String::new(),
        "a.b.c.d.e".into(),
        "a..b.c.d.extra".into(),
        "a..b.c.d=".into(),
        "a..b.c.d\n".into(),
        "A".repeat(65537),
    ] {
        assert!(AppleGrantEnvelope::restore(b, Uuid::new_v4(), value).is_err());
    }
    let mut p = payload();
    p.token = "a".repeat(16385);
    assert!(p.validate().is_err());
    p.token = "valid".into();
    p.access_expires_us = Some(1);
    assert!(p.validate().is_err());
    p.kind = super::super::payload::GrantTokenKind::Access;
    assert!(p.validate().is_ok());
    p.access_expires_us = Some(0);
    assert!(p.validate().is_err());
    p.access_expires_us = None;
    assert!(p.validate().is_err());
    p.access_expires_us = Some(1);
    p.token = "a\nb".into();
    assert!(p.validate().is_err());
}
