use super::super::super::cache_headers;
use reqwest::header::{AGE, CACHE_CONTROL, HeaderMap, HeaderValue, VARY};

#[test]
fn cache_age_is_explicit_bounded_by_http_and_has_no_stale_fallback() {
    let mut headers = HeaderMap::new();
    assert_eq!(cache_headers::seconds(&headers), 0);
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=120, must-revalidate"),
    );
    headers.insert(AGE, HeaderValue::from_static("20"));
    assert_eq!(cache_headers::seconds(&headers), 100);
    headers.insert(AGE, HeaderValue::from_static("200"));
    assert_eq!(cache_headers::seconds(&headers), 0);
    headers.insert(AGE, HeaderValue::from_static("0"));
    for value in [
        "max-age=120, no-store",
        "no-cache, max-age=120",
        "no-cache=\"field\", max-age=120",
        "max-age=120,max-age=120",
        "max-age=invalid",
        "max-age=+120",
        "max-age=\"\"120\"",
        "max-age=120, unsupported=1",
        "max-age=18446744073709551616",
    ] {
        headers.insert(CACHE_CONTROL, HeaderValue::from_str(value).unwrap());
        assert_eq!(
            cache_headers::seconds(&headers),
            0,
            "must not cache {value}"
        );
    }
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=120"));
    headers.insert(VARY, HeaderValue::from_static("*"));
    assert_eq!(cache_headers::seconds(&headers), 0);
    headers.remove(VARY);
    headers.append(AGE, HeaderValue::from_static("10"));
    assert_eq!(cache_headers::seconds(&headers), 0);
}
