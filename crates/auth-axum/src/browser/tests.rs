use super::{BrowserConfig, read_cookie};
use auth_core::Secret;
use axum::http::{HeaderMap, header};

#[test]
fn configuration_fails_closed() {
    for bad in [
        "http://example.com",
        "https://u:p@example.com",
        "https://example.com/path",
        "https://example.com/?x=1",
        "https://example.com/#x",
        "file:///tmp/x",
    ] {
        assert!(BrowserConfig::new(bad, false).is_err(), "{bad}");
    }
    assert!(BrowserConfig::new("http://example.com", true).is_err());
    assert!(BrowserConfig::new("http://127.0.0.1:8080", true).is_ok());
    let config = BrowserConfig::new("https://example.com", false).unwrap();
    let cookie = config.cookie(
        config.session_name(),
        Some(&Secret::generate().unwrap()),
        60,
    );
    let cookie = cookie.to_str().unwrap();
    for expected in ["__Host-", "Secure", "HttpOnly", "SameSite=Lax", "Path=/"] {
        assert!(cookie.contains(expected));
    }
    assert!(!cookie.contains("Domain="));
}
#[test]
fn duplicate_cookies_cannot_select_a_session() {
    let token = Secret::generate().unwrap();
    let mut headers = HeaderMap::new();
    headers.append(
        header::COOKIE,
        format!(
            "auth-session={}; auth-session={}",
            token.expose(),
            token.expose()
        )
        .parse()
        .unwrap(),
    );
    assert!(read_cookie(&headers, "auth-session").is_err());
}
