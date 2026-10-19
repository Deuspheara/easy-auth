use super::setup::Fixture;
use crate::{Error, OAuthConnection, OAuthMixupDefense, OidcDocuments};

#[test]
fn explicit_origins_ports_and_literal_address_binding_fail_closed() {
    let f = Fixture::new();
    let connection = &f.registry.connection;
    for origins in [
        vec![],
        vec!["https://issuer.example", "https://issuer.example"],
        vec!["http://issuer.example"],
        vec!["https://issuer.example:443"],
        vec!["https://*.example"],
        vec!["https://issuer.example/path"],
        vec!["https://issuer.example?x=1"],
        vec!["https://issuer.example#fragment"],
        vec!["https://user:secret@issuer.example"],
        vec!["https://other.example"],
    ] {
        assert!(matches!(
            OidcDocuments::new(
                connection.clone(),
                &origins,
                f.registry.clone(),
                f.http.clone()
            ),
            Err(Error::InvalidInput)
        ));
    }
    let excessive = vec!["https://issuer.example"; 9];
    assert!(matches!(
        OidcDocuments::new(
            connection.clone(),
            &excessive,
            f.registry.clone(),
            f.http.clone()
        ),
        Err(Error::InvalidInput)
    ));
    for (issuer, origin) in [
        ("https://127.0.0.1", "https://127.0.0.1"),
        ("https://2130706433", "https://127.0.0.1"),
        ("https://[::ffff:127.0.0.1]", "https://[::ffff:7f00:1]"),
    ] {
        let input = OAuthConnection::new(
            connection.realm(),
            connection.connection(),
            connection.client(),
            issuer,
            connection.provider_client(),
            connection.redirect(),
            OAuthMixupDefense::RequireIssuer,
        )
        .unwrap();
        assert!(matches!(
            OidcDocuments::new(input, &[origin], f.registry.clone(), f.http.clone()),
            Err(Error::InvalidInput)
        ));
    }
    let input = OAuthConnection::new(
        connection.realm(),
        connection.connection(),
        connection.client(),
        "https://issuer.example:8443/tenant/",
        connection.provider_client(),
        connection.redirect(),
        OAuthMixupDefense::RequireIssuer,
    )
    .unwrap();
    let policy =
        super::super::policy::Policy::new(&input, &["https://issuer.example:8443"]).unwrap();
    let target = policy
        .target(
            policy.discovery_url().unwrap(),
            vec!["8.8.8.8:8443".parse().unwrap()],
        )
        .unwrap();
    assert_eq!(target.url().port(), Some(8443));
    assert_eq!(target.addresses()[0].port(), 8443);
    let input = OAuthConnection::new(
        connection.realm(),
        connection.connection(),
        connection.client(),
        "https://1.1.1.1",
        connection.provider_client(),
        connection.redirect(),
        OAuthMixupDefense::RequireIssuer,
    )
    .unwrap();
    let policy = super::super::policy::Policy::new(&input, &["https://1.1.1.1"]).unwrap();
    assert!(matches!(
        policy.target(
            policy.discovery_url().unwrap(),
            vec!["8.8.8.8:443".parse().unwrap()]
        ),
        Err(Error::Unavailable)
    ));
    assert!(
        policy
            .target(
                policy.discovery_url().unwrap(),
                vec!["1.1.1.1:443".parse().unwrap()]
            )
            .is_ok()
    );
    assert_eq!(f.gets(), 0);
}
