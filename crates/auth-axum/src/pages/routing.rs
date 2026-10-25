use crate::router::AppState;
use axum::{Router, http::header, routing::get};

pub(crate) fn routes(passwords: bool, api: &utoipa::openapi::OpenApi) -> Router<AppState> {
    let index = super::capabilities::index(passwords, api);
    authentication_pages(index)
        .merge(account_pages())
        .merge(client_modules())
        .merge(presentation_assets())
}

fn presentation_assets() -> Router<AppState> {
    Router::new()
        .route(
            "/ui/licenses.txt",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                    concat!(
                        include_str!("vendor/basecoat-css.LICENSE"),
                        "\n",
                        include_str!("vendor/motion.LICENSE"),
                        "\n",
                        include_str!("vendor/framer-motion.LICENSE"),
                        "\n",
                        include_str!("vendor/motion-dom.LICENSE"),
                        "\n",
                        include_str!("vendor/motion-utils.LICENSE"),
                        "\n",
                        include_str!("vendor/tslib.LICENSE"),
                        "\n",
                        include_str!("vendor/esbuild.LICENSE"),
                        "\n",
                        include_str!("brand.LICENSE")
                    ),
                )
            }),
        )
        .route(
            "/ui/fonts/InterVariable.woff2",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "font/woff2")],
                    include_bytes!("fonts/InterVariable.woff2").as_slice(),
                )
            }),
        )
        .route(
            "/ui/fonts/OFL.txt",
            get(|| async { include_str!("fonts/OFL.txt") }),
        )
}

fn client_modules() -> Router<AppState> {
    let mut routes = Router::new();
    for (path, source) in [
        (
            "/ui/browser-operations.js",
            include_str!("browser-operations.js"),
        ),
        ("/ui/feedback.js", include_str!("feedback.js")),
        ("/ui/settings-search.js", include_str!("settings-search.js")),
        ("/ui/account-search.js", include_str!("account-search.js")),
        ("/ui/recovery-view.js", include_str!("recovery/view.js")),
        (
            "/ui/recovery-setup-view.js",
            include_str!("recovery/setup-view.js"),
        ),
        (
            "/ui/recovery-claim-view.js",
            include_str!("recovery/claim-view.js"),
        ),
        (
            "/ui/basecoat-popover.js",
            include_str!("vendor/basecoat-popover.js"),
        ),
        ("/ui/theme.js", include_str!("theme.js")),
        ("/ui/motion.js", include_str!("vendor/motion.js")),
        (
            "/ui/presentation-motion.js",
            include_str!("presentation-motion.js"),
        ),
        ("/ui/view.js", include_str!("view.js")),
        ("/ui/auth-screens.js", include_str!("auth-screens.js")),
        ("/ui/signin.js", include_str!("signin.js")),
        ("/ui/account.js", include_str!("account.js")),
        ("/ui/account-view.js", include_str!("account-view.js")),
        ("/ui/passkeys.js", include_str!("passkeys.js")),
        ("/ui/passkey-row.js", include_str!("passkey-row.js")),
        ("/ui/passkey-reauth.js", include_str!("passkey-reauth.js")),
        ("/ui/inventory-rows.js", include_str!("inventory-rows.js")),
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
