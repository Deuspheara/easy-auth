use axum::response::Html;

/// Only fixed templates (or already escaped transport documents) enter here.
/// The exact inline stylesheet is allowlisted by the browser boundary's CSP hash.
pub(crate) fn document(template: &str) -> Html<String> {
    Html(template.replace(
        "<!-- reference-style -->",
        &format!(
            "<style>{}{}{}</style><script type=\"module\" src=\"/ui/theme.js\"></script>",
            include_str!("vendor/basecoat.css"),
            include_str!("tokens.css"),
            include_str!("reference.css")
        ),
    ))
}
