use reqwest::header::{AGE, CACHE_CONTROL, HeaderMap, VARY};

/// Cache only explicit max-age, reduced by Age. Unsupported/ambiguous directives
/// disable reuse; core caps remaining age and never uses stale/conditional fallback.
pub(super) fn seconds(headers: &HeaderMap) -> u64 {
    if headers.get_all(AGE).iter().count() > 1 {
        return 0;
    }
    let age = match headers.get(AGE) {
        None => 0,
        Some(value) => match value.to_str().ok().and_then(|value| decimal(value.trim())) {
            Some(age) => age,
            None => return 0,
        },
    };
    if headers.get_all(VARY).iter().any(|value| {
        value
            .to_str()
            .map_or(true, |value| value.split(',').any(|v| v.trim() == "*"))
    }) {
        return 0;
    }
    let mut max_age = None;
    for value in headers.get_all(CACHE_CONTROL) {
        let Ok(value) = value.to_str() else {
            return 0;
        };
        for directive in value.split(',').map(str::trim) {
            if directive.eq_ignore_ascii_case("no-store")
                || directive.eq_ignore_ascii_case("no-cache")
            {
                return 0;
            }
            if let Some((name, value)) = directive.split_once('=') {
                if name.trim().eq_ignore_ascii_case("no-cache") {
                    return 0;
                }
                if name.trim().eq_ignore_ascii_case("max-age") {
                    let raw = value.trim();
                    let value = if raw.starts_with('"') {
                        raw.strip_prefix('"').and_then(|v| v.strip_suffix('"'))
                    } else {
                        Some(raw)
                    };
                    let Some(value) = value.and_then(decimal) else {
                        return 0;
                    };
                    if max_age.is_some() {
                        return 0;
                    }
                    max_age = Some(value);
                } else {
                    return 0;
                }
            } else if ![
                "public",
                "private",
                "immutable",
                "must-revalidate",
                "proxy-revalidate",
                "no-transform",
            ]
            .iter()
            .any(|known| directive.eq_ignore_ascii_case(known))
            {
                return 0;
            }
        }
    }
    max_age.unwrap_or(0).saturating_sub(age)
}

fn decimal(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}
