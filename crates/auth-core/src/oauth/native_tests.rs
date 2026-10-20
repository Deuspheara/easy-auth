use super::*;
use crate::Error;
use uuid::Uuid;

fn connection(redirect: OAuthRedirect) -> OAuthConnection {
    OAuthConnection::with_redirect(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        "https://issuer.example",
        "registered-desktop-client",
        redirect,
        OAuthMixupDefense::RequireIssuer,
    )
    .unwrap()
}

#[test]
fn explicit_loopback_keeps_web_https_only_and_requires_exact_callback() {
    for address in ["127.0.0.1:49153", "[::1]:49154"] {
        let native =
            OAuthRedirect::desktop_loopback(address.parse().unwrap(), "/oauth/callback").unwrap();
        let expected = format!("http://{address}/oauth/callback");
        assert_eq!(native.as_str(), expected);
        assert!(matches!(
            OAuthRedirect::https(&expected),
            Err(Error::InvalidInput)
        ));
        let c = connection(native);
        assert!(matches!(
            OAuthConnection::new(
                c.realm(),
                c.connection(),
                c.client(),
                c.issuer(),
                c.provider_client(),
                &expected,
                c.defense()
            ),
            Err(Error::InvalidInput)
        ));
        for (redirect, issuer) in [
            (
                expected.replace(address, "127.0.0.1:49155"),
                Some(c.issuer()),
            ),
            (
                expected.replace("/oauth/callback", "/other"),
                Some(c.issuer()),
            ),
            (expected.clone(), Some("https://attacker.example")),
            (expected.clone(), None),
        ] {
            assert!(matches!(
                c.validate_callback(&OAuthCallback {
                    redirect: &redirect,
                    issuer
                }),
                Err(Error::Unauthorized)
            ));
        }
        c.validate_callback(&OAuthCallback {
            redirect: &expected,
            issuer: Some(c.issuer()),
        })
        .unwrap();
    }
}

#[test]
fn native_redirect_has_literal_loopback_nonzero_nondefault_port_and_canonical_path() {
    for address in [
        "0.0.0.0:49153",
        "[::]:49153",
        "192.0.2.1:49153",
        "127.0.0.2:49153",
        "[::ffff:127.0.0.1]:49153",
        "127.0.0.1:0",
        "127.0.0.1:80",
    ] {
        assert!(matches!(
            OAuthRedirect::desktop_loopback(address.parse().unwrap(), "/callback"),
            Err(Error::InvalidInput)
        ));
    }
    let address = "127.0.0.1:49153".parse().unwrap();
    for path in [
        "",
        "/",
        "callback",
        "//other.example/callback",
        "/a/../callback",
        "/%63allback",
        "/callback?code=x",
        "/callback#x",
        "/a b",
        "/a\\b",
        "/callback\n",
    ] {
        assert!(
            matches!(
                OAuthRedirect::desktop_loopback(address, path),
                Err(Error::InvalidInput)
            ),
            "noncanonical native path admitted"
        );
    }
    assert!(matches!(
        OAuthRedirect::desktop_loopback(address, &format!("/{}", "x".repeat(2048))),
        Err(Error::InvalidInput)
    ));
}

#[test]
fn explicit_redirect_preserves_metadata_validation_and_reconfiguration_is_fresh() {
    let c = connection(
        OAuthRedirect::desktop_loopback("127.0.0.1:49153".parse().unwrap(), "/callback").unwrap(),
    );
    let changed = c.reconfigured();
    assert_ne!(changed.revision(), c.revision());
    assert_eq!(
        (changed.realm(), changed.connection(), changed.client()),
        (c.realm(), c.connection(), c.client())
    );
    assert_eq!(
        (
            changed.issuer(),
            changed.provider_client(),
            changed.redirect(),
            changed.defense()
        ),
        (c.issuer(), c.provider_client(), c.redirect(), c.defense())
    );
    for (realm, issuer, client) in [
        (Uuid::nil(), c.issuer(), c.provider_client()),
        (c.realm(), "http://issuer.example", c.provider_client()),
        (c.realm(), c.issuer(), " client"),
    ] {
        let redirect =
            OAuthRedirect::desktop_loopback("127.0.0.1:49153".parse().unwrap(), "/callback")
                .unwrap();
        assert!(matches!(
            OAuthConnection::with_redirect(
                realm,
                c.connection(),
                c.client(),
                issuer,
                client,
                redirect,
                c.defense()
            ),
            Err(Error::InvalidInput)
        ));
    }
    let web = connection(OAuthRedirect::https("https://app.example/callback").unwrap());
    assert_eq!(web.redirect(), "https://app.example/callback");
}

#[test]
fn desktop_registration_is_explicit_issuer_bound_and_keeps_a_stable_anchor() {
    let exact = connection(
        OAuthRedirect::desktop_loopback("127.0.0.1:49153".parse().unwrap(), "/oauth/owned")
            .unwrap(),
    );
    let profile = exact.clone().with_desktop_loopback_returns().unwrap();
    assert_eq!(
        profile.redirect_policy(),
        OAuthRedirectPolicy::DesktopLoopback
    );
    assert_eq!(profile.redirect(), exact.redirect());
    assert_eq!(profile.revision(), exact.revision());
    assert_ne!(profile, exact);
    for actual in [
        "http://127.0.0.1:49154/oauth/owned",
        "http://[::1]:49155/oauth/owned",
    ] {
        assert!(profile.permits_return(actual));
        assert!(!exact.permits_return(actual));
    }
    for actual in [
        "http://127.0.0.2:49154/oauth/owned",
        "http://0.0.0.0:49154/oauth/owned",
        "http://localhost:49154/oauth/owned",
        "https://127.0.0.1:49154/oauth/owned",
        "http://127.0.0.1:0/oauth/owned",
        "http://127.0.0.1:80/oauth/owned",
        "http://127.0.0.1:49154/other",
        "http://127.0.0.1:49154/oauth/owned?x=1",
        "http://127.0.0.1:49154/oauth/owned#x",
        "http://127.0.0.1:49154/oauth/%6fwned",
        "http://user@127.0.0.1:49154/oauth/owned",
        "http://127.1:49154/oauth/owned",
    ] {
        assert!(!profile.permits_return(actual));
    }
    let updated = profile.reconfigured();
    assert_eq!(updated.redirect_policy(), profile.redirect_policy());
    assert_ne!(updated.revision(), profile.revision());
    assert!(
        connection(OAuthRedirect::https("https://app.example/return").unwrap())
            .with_desktop_loopback_returns()
            .is_err()
    );
    let dedicated = OAuthConnection::with_redirect(
        exact.realm(),
        exact.connection(),
        exact.client(),
        exact.issuer(),
        exact.provider_client(),
        OAuthRedirect::desktop_loopback("127.0.0.1:49153".parse().unwrap(), "/oauth/owned")
            .unwrap(),
        OAuthMixupDefense::DedicatedRedirect,
    )
    .unwrap();
    assert!(dedicated.with_desktop_loopback_returns().is_err());
}
