fn main() {
    println!(
        "{}",
        easy_auth_axum::oidc_web_openapi().to_pretty_json().unwrap()
    );
}
