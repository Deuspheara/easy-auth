use super::setup::{ClientFixture, callback, parameters};
use crate::*;

#[tokio::test]
async fn callback_binding_rejections_happen_before_code_post() {
    for failure in [
        "state",
        "issuer",
        "duplicate",
        "escaped_duplicate",
        "path",
        "fixed_query",
        "fragment",
        "credentials",
        "bad_percent",
        "bad_utf8",
    ] {
        let f = ClientFixture::new();
        let pending = f.client.authorize().await.unwrap();
        let mut callback = callback(&pending);
        match failure {
            "state" | "issuer" => {
                let key = if failure == "state" { "state" } else { "iss" };
                let mut fields: Vec<_> = callback
                    .query_pairs()
                    .into_owned()
                    .filter(|(name, _)| name != key)
                    .collect();
                let value = if key == "state" {
                    Secret::generate().unwrap().expose().to_owned()
                } else {
                    "https://other.example".into()
                };
                fields.push((key.into(), value));
                callback.set_query(None);
                callback.query_pairs_mut().extend_pairs(fields);
            }
            "duplicate" => {
                callback
                    .query_pairs_mut()
                    .append_pair("code", "another-code");
            }
            "escaped_duplicate" => {
                callback.set_query(Some(&format!(
                    "{}&%73tate=other",
                    callback.query().unwrap()
                )));
            }
            "path" => callback.set_path("/another"),
            "fixed_query" => {
                callback.set_query(Some(
                    &callback
                        .query()
                        .unwrap()
                        .replace("tenant=one", "tenant=two"),
                ));
            }
            "fragment" => callback.set_fragment(Some("data")),
            "credentials" => callback.set_username("someone").unwrap(),
            "bad_percent" => {
                callback.set_query(Some(&format!("{}&extra=%ZZ", callback.query().unwrap())));
            }
            "bad_utf8" => {
                callback.set_query(Some(&format!("{}&extra=%FF", callback.query().unwrap())));
            }
            _ => unreachable!(),
        }
        assert!(
            matches!(
                f.client.complete(pending, callback.as_str()).await,
                Err(OidcClientError::Callback)
            ),
            "{failure}"
        );
        assert_eq!(f.post.posts(), 0);
    }
}

#[tokio::test]
async fn valid_bound_denial_does_not_post_a_code() {
    let f = ClientFixture::new();
    let pending = f.client.authorize().await.unwrap();
    let mut callback = url::Url::parse("https://rp.example/callback?tenant=one").unwrap();
    callback
        .query_pairs_mut()
        .append_pair("state", &parameters(&pending)["state"])
        .append_pair("iss", "https://issuer.example")
        .append_pair("error", "access_denied");
    assert!(matches!(
        f.client.complete(pending, callback.as_str()).await,
        Err(OidcClientError::Denied)
    ));
    assert_eq!(f.post.posts(), 0);
}

#[tokio::test]
async fn another_service_cannot_consume_retained_operation() {
    let f = ClientFixture::new();
    let pending = f.client.authorize().await.unwrap();
    let callback = callback(&pending);
    let other = ClientFixture::service(&f.provider, f.post.clone(), f.id);
    assert!(matches!(
        other.complete(pending, callback.as_str()).await,
        Err(OidcClientError::Callback)
    ));
    assert_eq!(f.post.posts(), 0);
}

#[tokio::test(start_paused = true)]
async fn monotonic_pending_expiry_rejects_before_post() {
    let f = ClientFixture::new();
    let pending = f.client.authorize().await.unwrap();
    let callback = callback(&pending);
    tokio::time::advance(std::time::Duration::from_secs(301)).await;
    assert!(matches!(
        f.client.complete(pending, callback.as_str()).await,
        Err(OidcClientError::Expired)
    ));
    assert_eq!(f.post.posts(), 0);
}
