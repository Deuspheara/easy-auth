use crate::router::AppState;
use axum::{Router, http::header, routing::get};

pub(crate) fn routes(passwords: bool, api: &utoipa::openapi::OpenApi) -> Router<AppState> {
    let index = super::capabilities::index(passwords, api);
    authentication_pages(index)
        .merge(account_pages())
        .merge(client_modules())
}

fn client_modules() -> Router<AppState> {
    let mut routes = Router::new();
    for (path, source) in [
        (
            "/ui/browser-operations.js",
            include_str!("browser-operations.js"),
        ),
        ("/ui/view.js", include_str!("view.js")),
        ("/ui/signin.js", include_str!("signin.js")),
        ("/ui/account.js", include_str!("account.js")),
        ("/ui/passkeys.js", include_str!("passkeys.js")),
    ] {
        routes = routes.route(
            path,
            get(move || async move {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    source,
                )
            }),
        );
    }
    routes
}

fn authentication_pages(index: String) -> Router<AppState> {
    Router::new()
        .route(
            "/",
            get(move || {
                let index = index.clone();
                async move { super::document(&index) }
            }),
        )
        .route(
            "/client.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("client.js"),
                )
            }),
        )
        .route(
            "/reset",
            get(|| async { crate::pages::document(include_str!("reset.html")) }),
        )
        .route(
            "/reset.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("reset.js"),
                )
            }),
        )
}

fn account_pages() -> Router<AppState> {
    Router::new()
        .route(
            "/email-change",
            get(|| async { crate::pages::document(include_str!("email-change.html")) }),
        )
        .route(
            "/account-delete",
            get(|| async { crate::pages::document(include_str!("account-delete.html")) }),
        )
        .route(
            "/account-action.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("account-action.js"),
                )
            }),
        )
}
