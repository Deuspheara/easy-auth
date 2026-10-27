use super::{setup::*, *};
use josekit::{
    jwk::KeyPair,
    jws::{ES384, RS256},
};

#[test]
fn key_input_requires_one_private_pkcs8_p256_with_no_format_or_curve_fallback() {
    let key = key();
    let private = pem(&key);
    let other_curve = ES384.generate_key_pair().unwrap();
    let rsa = RS256.generate_key_pair(2048).unwrap();
    for input in [
        String::new(),
        "private-sentinel-invalid-key".to_owned(),
        format!("{private}{private}"),
        format!("{private}unexpected"),
        format!(" {private}"),
        String::from_utf8(key.to_pem_public_key()).unwrap(),
        String::from_utf8(key.to_traditional_pem_private_key()).unwrap(),
        String::from_utf8(other_curve.to_pem_private_key()).unwrap(),
        String::from_utf8(rsa.to_pem_private_key()).unwrap(),
        "x".repeat(4097),
    ] {
        let result =
            AppleClientSecretSigner::from_pkcs8_pem(TEAM, CLIENT, "KEY0000001", 0, 1000, input);
        assert!(matches!(result, Err(Error::InvalidInput)));
        assert!(!format!("{result:?}").contains("sentinel"));
    }
    assert!(
        AppleClientSecretSigner::from_pkcs8_pem(TEAM, CLIENT, "KEY0000001", 0, 1000, private)
            .is_ok()
    );
}

#[test]
fn configuration_rejects_ambiguous_identifiers_and_unbounded_or_empty_windows() {
    let key = key();
    for (team, client, id, start, end) in [
        ("", CLIENT, "KEY0000001", 0, 1000),
        ("team000001", CLIENT, "KEY0000001", 0, 1000),
        (TEAM, CLIENT, "KEY000000!", 0, 1000),
        (TEAM, CLIENT, " KEY000001", 0, 1000),
        (TEAM, "", "KEY0000001", 0, 1000),
        (TEAM, "com..example", "KEY0000001", 0, 1000),
        (TEAM, "com.example\n", "KEY0000001", 0, 1000),
        (TEAM, "https://example.com", "KEY0000001", 0, 1000),
        (TEAM, CLIENT, "KEY0000001", 1, 1),
        (TEAM, CLIENT, "KEY0000001", 2, 1),
        (TEAM, CLIENT, "KEY0000001", 0, u64::MAX),
    ] {
        assert!(matches!(
            AppleClientSecretSigner::from_pkcs8_pem(team, client, id, start, end, pem(&key)),
            Err(Error::InvalidInput)
        ));
    }
    assert!(
        AppleClientSecretSigner::from_pkcs8_pem(
            TEAM,
            "Com.Example.Native-App",
            "KEY0000001",
            0,
            1000,
            pem(&key)
        )
        .is_ok()
    );
}
