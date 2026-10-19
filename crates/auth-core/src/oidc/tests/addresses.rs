use super::setup::Fixture;
use crate::{Error, MAX_OIDC_DNS_ANSWERS};
use std::net::{IpAddr, SocketAddr};

#[test]
fn reviewed_public_address_policy_blocks_special_and_transition_ranges() {
    for input in [
        "0.0.0.1",
        "10.1.2.3",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.31.255.255",
        "192.0.0.9",
        "192.0.2.1",
        "192.88.99.1",
        "192.168.1.2",
        "198.18.1.2",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:8.8.8.8",
        "::ffff:127.0.0.1",
        "64:ff9b::a00:1",
        "64:ff9b:1::1",
        "100:0:0:1::1",
        "2001::1",
        "2001:db8::1",
        "2002:a00:1::1",
        "3fff::1",
        "5f00::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "4000::1",
    ] {
        assert!(
            !super::super::public_address::allowed(input.parse::<IpAddr>().unwrap()),
            "must reject {input}"
        );
    }
    for input in [
        "1.1.1.1",
        "8.8.8.8",
        "93.184.216.34",
        "2001:4860:4860::8888",
        "2606:4700:4700::1111",
    ] {
        assert!(
            super::super::public_address::allowed(input.parse().unwrap()),
            "positive control {input}"
        );
    }
}

#[tokio::test]
async fn private_mixed_empty_excess_and_wrong_port_answers_never_reach_connector() {
    let sets: Vec<Vec<SocketAddr>> = vec![
        vec![],
        vec!["127.0.0.1:443".parse().unwrap()],
        vec!["8.8.8.8:443".parse().unwrap(), "[::1]:443".parse().unwrap()],
        vec!["8.8.8.8:8443".parse().unwrap()],
        vec!["8.8.8.8:443".parse().unwrap(); MAX_OIDC_DNS_ANSWERS + 1],
    ];
    for answers in sets {
        let f = Fixture::new();
        *f.http.answers.lock().unwrap() = answers;
        assert!(matches!(
            f.documents.discovery().await,
            Err(Error::Unavailable)
        ));
        assert_eq!(
            f.gets(),
            0,
            "a network/infrastructure failure cannot stand in for pre-connect denial"
        );
    }
    let f = Fixture::new();
    f.documents.discovery().await.unwrap();
    assert_eq!(f.gets(), 1);
    let targets = f.http.targets.lock().unwrap();
    assert_eq!(
        targets[0].0,
        "https://issuer.example/tenant/.well-known/openid-configuration"
    );
    assert!(targets[0].1 == ["8.8.8.8:443".parse().unwrap()]);
}
