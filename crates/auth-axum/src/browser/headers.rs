//! Fixed browser response policy shared by all deliberately selected boundaries.
use axum::{
    http::{HeaderValue, header},
    response::Response,
};

// Only the exact fixed reference stylesheet may supply inline styles.
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; style-src 'sha256-mrh6CimstRLBArnA3GtEFuIhGV93ne7xr/K73HnM/uY='; style-src-attr 'none'";

pub(super) fn apply(response: &mut Response, secure: bool, request_id: &str) {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    if secure {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    headers.insert(
        "x-request-id",
        HeaderValue::from_str(request_id).expect("UUID is header-safe"),
    );
}

#[cfg(test)]
mod reference_style_tests {
    use super::CONTENT_SECURITY_POLICY;
    use base64::Engine;

    #[test]
    fn inline_style_permission_matches_only_the_fixed_reference_stylesheet() {
        let stylesheet = format!(
            "{}{}{}",
            include_str!("../pages/vendor/basecoat.css"),
            include_str!("../pages/tokens.css"),
            include_str!("../pages/reference.css")
        );
        let digest = openssl::hash::hash(
            openssl::hash::MessageDigest::sha256(),
            stylesheet.as_bytes(),
        )
        .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(digest);
        assert!(CONTENT_SECURITY_POLICY.contains(&format!("style-src 'sha256-{encoded}'")));
        assert!(CONTENT_SECURITY_POLICY.contains("style-src-attr 'none'"));
        assert!(CONTENT_SECURITY_POLICY.contains("default-src 'none'"));
        assert!(CONTENT_SECURITY_POLICY.contains("frame-ancestors 'none'"));
        assert!(!CONTENT_SECURITY_POLICY.contains("unsafe-inline"));
        assert!(!CONTENT_SECURITY_POLICY.contains("style-src 'self'"));
    }
}
