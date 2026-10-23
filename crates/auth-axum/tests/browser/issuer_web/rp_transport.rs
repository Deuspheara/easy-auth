//! Test-only in-process wire adapter. No live DNS/TLS or independent RP claim.
use super::*;
use async_trait::async_trait;
use axum::Router;
use axum::response::Response;
use http_body_util::BodyExt;
use std::net::SocketAddr;

pub(super) struct OwnedTransport(pub Router);
#[async_trait]
impl OidcHttp for OwnedTransport {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        assert_eq!(host, "app.example");
        assert_eq!(port, 443);
        // Satisfy the existing public-address admission without opening a socket.
        Ok(vec![SocketAddr::from(([8, 8, 8, 8], port))])
    }
    async fn get(&self, target: &OidcTarget) -> Result<OidcHttpResponse> {
        assert_eq!(target.url().origin().ascii_serialization(), ORIGIN);
        let response = self
            .0
            .clone()
            .oneshot(get(target.url().path()))
            .await
            .unwrap();
        let status = response.status().as_u16();
        let content_type = text_header(&response, header::CONTENT_TYPE);
        let content_encoding = text_header(&response, header::CONTENT_ENCODING);
        assert_eq!(
            text_header(&response, header::CACHE_CONTROL).as_deref(),
            Some("no-store")
        );
        Ok(OidcHttpResponse {
            status,
            content_type,
            content_encoding,
            body: response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
            cache_seconds: 0,
        })
    }
}
#[async_trait]
impl OidcTokenHttp for OwnedTransport {
    async fn post(
        &self,
        target: &OidcTarget,
        input: &OidcTokenRequest,
    ) -> Result<OidcTokenResponse> {
        assert_eq!(target.url().as_str(), "https://app.example/oidc/token");
        let response = self
            .0
            .clone()
            .oneshot(token_request(
                target.url().path(),
                input.form().to_owned(),
                input.authorization(),
                true,
            ))
            .await
            .unwrap();
        let status = response.status().as_u16();
        let content_type = text_header(&response, header::CONTENT_TYPE);
        let encoding = text_header(&response, header::CONTENT_ENCODING);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        OidcTokenResponse::new(
            status,
            content_type,
            encoding,
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
    }
}
fn text_header(response: &Response, name: header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .map(|value| value.to_str().unwrap().to_owned())
}
