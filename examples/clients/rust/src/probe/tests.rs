use super::parse_origin;

#[test]
fn origin_policy_rejects_unsafe_transport_credentials_and_proof_locations() {
    for value in [
        "http://example.test/",
        "https://user:nonsecret@example.test/",
        "http://127.0.0.1:58418/path",
        "https://example.test/?proof=nonsecret",
        "https://example.test/#proof",
        "file:///tmp/example",
        "https://example.test:0/",
    ] {
        assert!(parse_origin(value).is_err());
    }
}

#[test]
fn https_and_literal_loopback_http_remain_valid_without_issuing_a_request() {
    for value in [
        "https://example.test/",
        "http://127.0.0.1:58418/",
        "http://[::1]:58418/",
    ] {
        assert_eq!(parse_origin(value).unwrap().path(), "/");
    }
}
