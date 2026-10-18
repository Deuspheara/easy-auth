mod boundary;
mod inventory;
mod revocation;

use axum::{
    Router,
    body::Body,
    http::{Request, header},
    response::Response,
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

async fn get(app: &Router, path: &str, cookie: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}
async fn json(response: Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
